//! The client against nbdwire's server, and against qemu-nbd, a server it
//! shares no code with. CI installs qemu-nbd (qemu-utils); a missing one fails
//! the test rather than skipping it.

mod common;

use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use nbdwire::proto::Opt;
use nbdwire::tokio_rustls::rustls::pki_types::ServerName;
use nbdwire::{Access, Client, ClientError, Extent, ExtentKind, FileBackend, Server};
use tempfile::TempDir;
use tokio::io::{DuplexStream, duplex};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

const MIB: usize = 1 << 20;
const SIZE: usize = 16 * MIB;

/// A 16 MiB file with data in its first MiB and its ninth, and holes
/// elsewhere. Returns its contents.
fn sparse_image(path: &Path) -> Vec<u8> {
    let mut contents = vec![0; SIZE];
    for (i, byte) in contents[..MIB].iter_mut().enumerate() {
        *byte = (i % 251) as u8 + 1;
    }
    for (i, byte) in contents[8 * MIB..9 * MIB].iter_mut().enumerate() {
        *byte = (i % 241) as u8 + 1;
    }
    let file = std::fs::File::create(path).unwrap();
    file.set_len(SIZE as u64).unwrap();
    file.write_all_at(&contents[..MIB], 0).unwrap();
    file.write_all_at(&contents[8 * MIB..9 * MIB], 8 * MIB as u64)
        .unwrap();
    contents
}

/// A server exporting `image` as "disk", read-only.
fn disk_server(server: Server, image: &Path) -> Arc<Server> {
    server.export(
        "disk",
        Arc::new(FileBackend::open(image, Access::ReadOnly).unwrap()),
    );
    Arc::new(server)
}

/// One end of a connection whose other end `server` serves.
fn connection(server: Arc<Server>) -> DuplexStream {
    let (client, server_end) = duplex(1 << 20);
    tokio::spawn(async move { server.serve(server_end).await });
    client
}

/// Copies the export to a new file in `dir`, checks it holds `contents`
/// with holes where the export has them, and returns how much data the copy
/// read.
async fn check_copy<S>(client: &mut Client<S>, dir: &Path, contents: &[u8]) -> u64
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let copy = dir.join("copy.img");
    let copied = client
        .copy_to(std::fs::File::create(&copy).unwrap())
        .await
        .unwrap();
    assert!(
        std::fs::read(&copy).unwrap() == contents,
        "the copy differs"
    );
    // Its 2 MiB of data, not the 16 a full copy takes up.
    assert!(std::fs::metadata(&copy).unwrap().blocks() * 512 < 4 * MIB as u64);
    copied
}

#[tokio::test]
async fn a_copy_has_the_exports_data_and_its_holes() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    let contents = sparse_image(&image);
    let server = disk_server(Server::new(), &image);

    let mut client = Client::connect(connection(server), "disk").await.unwrap();
    assert_eq!(client.size(), SIZE as u64);
    assert!(client.read_only());
    assert_eq!(
        client.block_status(0, 2 * MIB as u32).await.unwrap(),
        [
            Extent {
                length: MIB as u32,
                kind: ExtentKind::Data
            },
            Extent {
                length: MIB as u32,
                kind: ExtentKind::Hole
            },
        ]
    );
    let mut buf = vec![0; 4096];
    client.read(MIB as u64 - 2048, &mut buf).await.unwrap();
    assert!(buf == contents[MIB - 2048..MIB + 2048]);

    assert_eq!(
        check_copy(&mut client, dir.path(), &contents).await,
        2 * MIB as u64
    );
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn an_export_that_isnt_there_is_refused_for_the_servers_reason() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    sparse_image(&image);
    let server = disk_server(Server::new(), &image);

    match Client::connect(connection(server.clone()), "other").await {
        Err(ClientError::Refused {
            option: Opt::Go,
            message,
        }) => {
            assert!(message.contains("other"), "{message}")
        }
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("connected to an export that isn't there"),
    }
    // Gone once unexported, for clients that ask from then on.
    server.unexport("disk");
    assert!(Client::connect(connection(server), "disk").await.is_err());
}

#[tokio::test]
async fn the_client_starts_tls_where_the_server_requires_it() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    let contents = sparse_image(&image);
    let tls = common::tls(dir.path());
    let server = disk_server(Server::with_tls(tls.acceptor), &image);

    let localhost = ServerName::try_from("localhost").unwrap();
    let mut client = Client::connect_tls(
        connection(server.clone()),
        "disk",
        &tls.connector,
        localhost,
    )
    .await
    .unwrap();
    check_copy(&mut client, dir.path(), &contents).await;

    match Client::connect(connection(server), "disk").await {
        Err(ClientError::Refused {
            option: Opt::StructuredReply,
            message,
        }) => {
            assert!(message.contains("TLS"), "{message}")
        }
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("connected without TLS"),
    }
}

/// qemu-nbd serving `image` as "disk" on a Unix socket in `dir`, with
/// `args` before the image; and the socket. Killed when dropped.
async fn qemu_nbd(dir: &Path, image: &Path, args: &[&str]) -> (Child, PathBuf) {
    let socket = dir.join("qemu-nbd.sock");
    let child = Command::new("qemu-nbd")
        .args([
            "--read-only",
            "--persistent",
            "--format=raw",
            "--export-name=disk",
        ])
        .arg(format!("--socket={}", socket.display()))
        .args(args)
        .arg(image)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("running qemu-nbd");
    for _ in 0..100 {
        if socket.exists() {
            return (child, socket);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("qemu-nbd never opened its socket");
}

#[tokio::test]
async fn the_client_copies_from_qemu_nbd() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    let contents = sparse_image(&image);
    let (_qemu_nbd, socket) = qemu_nbd(dir.path(), &image, &[]).await;

    let stream = UnixStream::connect(&socket).await.unwrap();
    let mut client = Client::connect(stream, "disk").await.unwrap();
    assert_eq!(client.size(), SIZE as u64);
    assert_eq!(
        check_copy(&mut client, dir.path(), &contents).await,
        2 * MIB as u64
    );
    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn the_client_starts_tls_with_qemu_nbd() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    let contents = sparse_image(&image);
    let certs = dir.path().join("certs");
    std::fs::create_dir(&certs).unwrap();
    let tls = common::tls(&certs);
    let creds = format!(
        "tls-creds-x509,id=tls0,endpoint=server,verify-peer=on,dir={}",
        certs.display()
    );
    let (_qemu_nbd, socket) = qemu_nbd(
        dir.path(),
        &image,
        &["--object", &creds, "--tls-creds=tls0"],
    )
    .await;

    let stream = UnixStream::connect(&socket).await.unwrap();
    let localhost = ServerName::try_from("localhost").unwrap();
    let mut client = Client::connect_tls(stream, "disk", &tls.connector, localhost)
        .await
        .unwrap();
    check_copy(&mut client, dir.path(), &contents).await;
}
