//! The server's answers to what clients in good standing don't send, checked
//! byte by byte against the specification
//! (<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>).
//! The numbers are written out here rather than taken from `nbdwire::proto`,
//! so that a misreading of the specification there doesn't pass here too.

mod common;

use std::sync::Arc;

use nbdwire::{Access, FileBackend, Server};
use tempfile::{NamedTempFile, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

const OPT_ABORT: u32 = 2;
const OPT_GO: u32 = 7;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = (1 << 31) | 1;
const REP_ERR_TLS_REQD: u32 = (1 << 31) | 5;
const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const EPERM: u32 = 1;
const EINVAL: u32 = 22;

struct Client(DuplexStream);

impl Client {
    /// Connect to `server` and answer its greeting.
    async fn connect(server: Server) -> Self {
        let (client, server_end) = duplex(1 << 20);
        tokio::spawn(async move { server.serve(server_end).await });
        let mut client = Client(client);
        let mut greeting = [0; 18];
        client.0.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting[..16], b"NBDMAGICIHAVEOPT");
        // Fixed newstyle, no zeroes.
        client.0.write_u32(0b11).await.unwrap();
        client
    }

    async fn option(&mut self, code: u32, data: &[u8]) {
        self.0.write_all(b"IHAVEOPT").await.unwrap();
        self.0.write_u32(code).await.unwrap();
        self.0.write_u32(data.len() as u32).await.unwrap();
        self.0.write_all(data).await.unwrap();
    }

    /// One reply to an option: the option it answers, its type and payload.
    async fn option_reply(&mut self) -> (u32, u32, Vec<u8>) {
        assert_eq!(self.0.read_u64().await.unwrap(), 0x0003_e889_0455_65a9);
        let option = self.0.read_u32().await.unwrap();
        let kind = self.0.read_u32().await.unwrap();
        let mut payload = vec![0; self.0.read_u32().await.unwrap() as usize];
        self.0.read_exact(&mut payload).await.unwrap();
        (option, kind, payload)
    }

    async fn go(&mut self, export: &str) {
        let mut data = (export.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(export.as_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        self.option(OPT_GO, &data).await;
        let (_, kind, _) = self.option_reply().await;
        assert_eq!(kind, REP_INFO);
        let (_, kind, _) = self.option_reply().await;
        assert_eq!(kind, REP_ACK);
    }

    async fn request(&mut self, kind: u16, cookie: u64, offset: u64, length: u32) {
        self.0.write_u32(0x2560_9513).await.unwrap();
        self.0.write_u16(0).await.unwrap();
        self.0.write_u16(kind).await.unwrap();
        self.0.write_u64(cookie).await.unwrap();
        self.0.write_u64(offset).await.unwrap();
        self.0.write_u32(length).await.unwrap();
    }

    /// A simple reply's error and cookie.
    async fn simple_reply(&mut self) -> (u32, u64) {
        assert_eq!(self.0.read_u32().await.unwrap(), 0x6744_6698);
        let error = self.0.read_u32().await.unwrap();
        (error, self.0.read_u64().await.unwrap())
    }
}

/// A read-only export of 1 MiB of zeroes.
fn read_only_disk() -> (NamedTempFile, Server) {
    let image = NamedTempFile::new().unwrap();
    image.as_file().set_len(1 << 20).unwrap();
    let backend = FileBackend::open(image.path(), Access::ReadOnly).unwrap();
    (image, Server::new().export("disk", Arc::new(backend)))
}

#[tokio::test]
async fn unknown_options_are_refused_and_negotiation_goes_on() {
    let (_image, server) = read_only_disk();
    let mut client = Client::connect(server).await;
    client.option(999, b"whatever").await;
    let (option, kind, _) = client.option_reply().await;
    assert_eq!((option, kind), (999, REP_ERR_UNSUP));
    client.go("disk").await;
}

#[tokio::test]
async fn options_before_starttls_need_tls() {
    let certs = TempDir::new().unwrap();
    let mut client = Client::connect(Server::with_tls(common::tls(certs.path()))).await;
    client.option(OPT_GO, &[0, 0, 0, 0, 0, 0]).await;
    let (option, kind, _) = client.option_reply().await;
    assert_eq!((option, kind), (OPT_GO, REP_ERR_TLS_REQD));
    client.option(OPT_ABORT, &[]).await;
    let (option, kind, _) = client.option_reply().await;
    assert_eq!((option, kind), (OPT_ABORT, REP_ACK));
}

#[tokio::test]
async fn invalid_requests_fail_and_the_connection_goes_on() {
    let (_image, server) = read_only_disk();
    let mut client = Client::connect(server).await;
    client.go("disk").await;

    // Past the end.
    client.request(CMD_READ, 1, (1 << 20) - 512, 1024).await;
    assert_eq!(client.simple_reply().await, (EINVAL, 1));
    // A write to a read-only export, whose data the server must still read.
    client.request(CMD_WRITE, 2, 0, 512).await;
    client.0.write_all(&[0xff; 512]).await.unwrap();
    assert_eq!(client.simple_reply().await, (EPERM, 2));
    // A command that doesn't exist.
    client.request(42, 3, 0, 0).await;
    assert_eq!(client.simple_reply().await, (EINVAL, 3));

    client.request(CMD_FLUSH, 4, 0, 0).await;
    assert_eq!(client.simple_reply().await, (0, 4));
    client.request(CMD_DISC, 5, 0, 0).await;
    assert_eq!(client.0.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn a_request_without_its_magic_ends_the_connection() {
    let (_image, server) = read_only_disk();
    let mut client = Client::connect(server).await;
    client.go("disk").await;
    client.0.write_all(&[0; 28]).await.unwrap();
    assert_eq!(client.0.read(&mut [0; 1]).await.unwrap(), 0);
}
