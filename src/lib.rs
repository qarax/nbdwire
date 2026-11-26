//! An async server for the NBD (Network Block Device) protocol.
//!
//! A [`Server`] serves exports, each a [`Backend`], on any stream: a Unix
//! socket for clients on the same host, or TCP with TLS required of every
//! client ([`Server::with_tls`]). [`FileBackend`] exports a regular file. A
//! [`Client`] reads an export, from this server or any other, and copies one
//! to a file with its holes left as holes ([`Client::copy_to`]).
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use nbdwire::{Access, FileBackend, Server};
//!
//! # async fn run() -> std::io::Result<()> {
//! let disk = FileBackend::open("disk.img", Access::ReadOnly)?;
//! let server = Arc::new(Server::new());
//! server.export("disk", Arc::new(disk));
//! let listener = tokio::net::UnixListener::bind("/run/disk.sock")?;
//! loop {
//!     let (stream, _) = listener.accept().await?;
//!     let server = server.clone();
//!     tokio::spawn(async move { server.serve(stream).await });
//! }
//! # }
//! ```

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

mod backend;
mod client;
pub mod proto;
mod server;

pub use backend::{Access, Backend, Extent, ExtentKind, FileBackend};
pub use client::{Client, ClientError, MAX_READ};
pub use server::{Error, Server};
/// The TLS crate [`Server::with_tls`] takes an acceptor from.
pub use tokio_rustls;
