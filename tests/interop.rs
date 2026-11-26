//! The server against clients it shares no code with: libnbd's nbdinfo and
//! nbdcopy, and QEMU's qemu-img and qemu-io. CI installs them (libnbd-bin,
//! qemu-utils); a missing tool fails the test rather than skipping it.

mod common;

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nbdwire::{Access, FileBackend, Server};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
const SIZE: usize = 8 * MIB;

/// Serves `server` on a Unix socket in `dir` for the rest of the test.
fn serve(server: Server, dir: &Path) -> PathBuf {
    let socket = dir.join("nbd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = Arc::new(server);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let server = server.clone();
            tokio::spawn(async move { server.serve(stream).await });
        }
    });
    socket
}

fn uri(socket: &Path) -> String {
    format!("nbd+unix:///disk?socket={}", socket.display())
}

fn export(path: &Path, access: Access) -> Server {
    let backend = FileBackend::open(path, access).unwrap();
    Server::new().export("disk", Arc::new(backend))
}

/// Runs a client and returns what it printed, failing the test if it fails.
async fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .unwrap_or_else(|e| panic!("running {program}: {e}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

async fn run_json(program: &str, args: &[&str]) -> Value {
    let output = run(program, args).await;
    serde_json::from_str(&output).unwrap_or_else(|e| panic!("{e}: {output}"))
}

/// An 8 MiB file with data in its first MiB and its fifth, and holes
/// elsewhere. Returns its contents.
fn sparse_image(path: &Path) -> Vec<u8> {
    let mut contents = vec![0; SIZE];
    for (i, byte) in contents[..MIB].iter_mut().enumerate() {
        *byte = (i % 251) as u8 + 1;
    }
    for (i, byte) in contents[4 * MIB..5 * MIB].iter_mut().enumerate() {
        *byte = (i % 241) as u8 + 1;
    }
    let file = std::fs::File::create(path).unwrap();
    file.set_len(SIZE as u64).unwrap();
    file.write_all_at(&contents[..MIB], 0).unwrap();
    file.write_all_at(&contents[4 * MIB..5 * MIB], 4 * MIB as u64)
        .unwrap();
    contents
}

fn empty_image(path: &Path) {
    std::fs::File::create(path)
        .unwrap()
        .set_len(SIZE as u64)
        .unwrap();
}

#[tokio::test]
async fn nbdinfo_sees_the_export_and_its_holes() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    sparse_image(&image);
    let socket = serve(export(&image, Access::ReadOnly), dir.path());

    let info = run_json("nbdinfo", &["--json", &uri(&socket)]).await;
    let disk = &info["exports"][0];
    assert_eq!(disk["export-size"], SIZE, "{info:#}");
    assert_eq!(disk["is_read_only"], true, "{info:#}");
    assert_eq!(disk["can_multi_conn"], true, "{info:#}");
    assert_eq!(disk["can_flush"], true, "{info:#}");
    assert_eq!(disk["block_size_maximum"], 32 * MIB, "{info:#}");
    assert_eq!(disk["contexts"], json!(["base:allocation"]), "{info:#}");

    let map = run_json("nbdinfo", &["--map", "--json", &uri(&socket)]).await;
    let extents: Vec<_> = map
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["offset"].clone(), e["length"].clone(), e["type"].clone()))
        .collect();
    let mib = |n: usize| json!(n * MIB);
    assert_eq!(
        extents,
        [
            (mib(0), mib(1), json!(0)),
            (mib(1), mib(3), json!(3)),
            (mib(4), mib(1), json!(0)),
            (mib(5), mib(3), json!(3)),
        ],
        "{map:#}"
    );
}

#[tokio::test]
async fn nbdcopy_and_qemu_img_read_what_the_file_holds() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    let contents = sparse_image(&image);
    let socket = serve(export(&image, Access::ReadOnly), dir.path());

    let copy = dir.path().join("copy.img");
    empty_image(&copy);
    run("nbdcopy", &[&uri(&socket), copy.to_str().unwrap()]).await;
    assert!(
        std::fs::read(&copy).unwrap() == contents,
        "the copy differs"
    );

    let image = image.to_str().unwrap();
    run(
        "qemu-img",
        &["compare", "-f", "raw", "-F", "raw", image, &uri(&socket)],
    )
    .await;
}

#[tokio::test]
async fn nbdcopy_and_qemu_io_write_through_the_export() {
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("source.img");
    let mut expected = sparse_image(&source);
    let image = dir.path().join("disk.img");
    empty_image(&image);
    let socket = serve(export(&image, Access::ReadWrite), dir.path());

    run("nbdcopy", &[source.to_str().unwrap(), &uri(&socket)]).await;
    assert!(
        std::fs::read(&image).unwrap() == expected,
        "the copy differs"
    );

    // A write with FUA, zeroes written in place and as a hole, a trim and a
    // flush.
    run(
        "qemu-io",
        &[
            "-f",
            "raw",
            &uri(&socket),
            "-c",
            "write -P 0xab -f 2M 64k",
            "-c",
            "write -z 64k 64k",
            "-c",
            "write -z -u 4M 1M",
            "-c",
            "discard 7M 1M",
            "-c",
            "flush",
        ],
    )
    .await;
    expected[2 * MIB..2 * MIB + 64 * KIB].fill(0xab);
    expected[64 * KIB..128 * KIB].fill(0);
    expected[4 * MIB..5 * MIB].fill(0);
    // Trimmed bytes may read back as anything.
    let written = std::fs::read(&image).unwrap();
    assert!(
        written[..7 * MIB] == expected[..7 * MIB],
        "the writes differ"
    );
}

#[tokio::test]
async fn tls_is_required() {
    let dir = TempDir::new().unwrap();
    let image = dir.path().join("disk.img");
    sparse_image(&image);
    let certs = dir.path().join("certs");
    std::fs::create_dir(&certs).unwrap();
    let backend = FileBackend::open(&image, Access::ReadOnly).unwrap();
    let server = Server::with_tls(common::tls(&certs)).export("disk", Arc::new(backend));
    let socket = serve(server, dir.path());

    let tls_uri = format!(
        "nbds+unix:///disk?socket={}&tls-certificates={}",
        socket.display(),
        certs.display()
    );
    let info = run_json("nbdinfo", &["--json", &tls_uri]).await;
    assert_eq!(info["TLS"], true, "{info:#}");
    assert_eq!(info["exports"][0]["export-size"], SIZE, "{info:#}");

    let plain = Command::new("nbdinfo")
        .arg(uri(&socket))
        .output()
        .await
        .unwrap();
    assert!(!plain.status.success(), "a client without TLS got in");
}
