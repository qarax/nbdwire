//! A client for NBD servers. It negotiates structured replies and block
//! status, reads an export, and copies one to a file with its holes left as
//! holes.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::backend::{Extent, ExtentKind};
use crate::proto::{
    self, BASE_ALLOCATION, CHUNK_HEADER_LEN, Cmd, Info, OPTION_REPLY_HEADER_LEN, Opt, ParseError,
    REPLY_FLAG_DONE, STRUCTURED_REPLY_MAGIC, allocation, client_flags, handshake_flags, rep,
    reply_type, transmission_flags,
};

/// The most one [`Client::read`] asks for: what a server that states no block
/// sizes must take.
pub const MAX_READ: u32 = 32 * 1024 * 1024;
/// The most an option reply may carry. No server answers an option this
/// client sends with anything near it.
const MAX_OPTION_REPLY: u32 = 64 * 1024;
/// The most a chunk other than data may carry: a block status of a span with
/// very many extents comes near it.
const MAX_CHUNK: u32 = 16 * 1024 * 1024;
/// How much of an export a copy asks the block status of at a time.
const STATUS_SPAN: u64 = 1 << 30;
/// How much a copy reads at a time.
const COPY_CHUNK: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The server broke the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The server refused an option, for the reason it gave.
    #[error("the server refused {option:?}: {message}")]
    Refused { option: Opt, message: String },
    /// A request failed on the server, for the reason it gave.
    #[error("the request failed on the server (error {errno}): {message}")]
    Failed { errno: u32, message: String },
    /// The server doesn't report block status (`base:allocation`).
    #[error("the server doesn't report block status")]
    NoBlockStatus,
}

impl From<ParseError> for ClientError {
    fn from(e: ParseError) -> Self {
        ClientError::Protocol(e.to_string())
    }
}

fn protocol(message: impl Into<String>) -> ClientError {
    ClientError::Protocol(message.into())
}

/// A connection to an export, sending one request at a time.
pub struct Client<S> {
    stream: S,
    size: u64,
    flags: u16,
    /// The ID the server gave `base:allocation`, if it has it.
    base_allocation: Option<u32>,
    cookie: u64,
}

impl<S> Client<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Connect to `export` over `stream`, which the client upgrades to TLS
    /// with `connector` before anything else. `server` is the name the
    /// server's certificate must hold.
    pub async fn connect_tls(
        mut stream: S,
        export: &str,
        connector: &TlsConnector,
        server: ServerName<'static>,
    ) -> Result<Self, ClientError> {
        greet(&mut stream).await?;
        send_option(&mut stream, Opt::StartTls, &[]).await?;
        expect_ack(&mut stream, Opt::StartTls).await?;
        let stream = connector.connect(server, stream).await?;
        Client::open(stream, export).await
    }
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Connect to `export` over `stream`, in the clear.
    pub async fn connect(mut stream: S, export: &str) -> Result<Self, ClientError> {
        greet(&mut stream).await?;
        Self::open(stream, export).await
    }

    /// Negotiate structured replies and block status, and pick `export`.
    async fn open(mut stream: S, export: &str) -> Result<Self, ClientError> {
        send_option(&mut stream, Opt::StructuredReply, &[]).await?;
        expect_ack(&mut stream, Opt::StructuredReply).await?;

        let request = proto::meta_context_request(export, &[BASE_ALLOCATION]);
        send_option(&mut stream, Opt::SetMetaContext, &request).await?;
        let mut base_allocation = None;
        loop {
            let (reply_type, payload) = option_reply(&mut stream, Opt::SetMetaContext).await?;
            match reply_type {
                rep::ACK => break,
                rep::META_CONTEXT => {
                    let (id, name) = proto::parse_meta_context(&payload)?;
                    if name == BASE_ALLOCATION {
                        base_allocation = Some(id);
                    }
                }
                // A server without metadata contexts: copies read all of the
                // export.
                t if proto::is_option_error(t) => break,
                t => return Err(protocol(format!("reply {t} to NBD_OPT_SET_META_CONTEXT"))),
            }
        }

        send_option(&mut stream, Opt::Go, &proto::info_request(export, &[])).await?;
        let mut export_info = None;
        loop {
            let (reply_type, payload) = option_reply(&mut stream, Opt::Go).await?;
            match reply_type {
                rep::ACK => break,
                rep::INFO => {
                    if let Info::Export { size, flags } = proto::parse_info(&payload)? {
                        export_info = Some((size, flags));
                    }
                }
                t if proto::is_option_error(t) => return Err(refused(Opt::Go, &payload)),
                t => return Err(protocol(format!("reply {t} to NBD_OPT_GO"))),
            }
        }
        let (size, flags) = export_info
            .ok_or_else(|| protocol("NBD_OPT_GO succeeded without the export's size"))?;
        Ok(Self {
            stream,
            size,
            flags,
            base_allocation,
            cookie: 0,
        })
    }

    /// The export's size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read_only(&self) -> bool {
        self.flags & transmission_flags::READ_ONLY != 0
    }

    /// Fill `buf`, at most [`MAX_READ`] bytes, with the export's at `offset`.
    pub async fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ClientError> {
        let length = u32::try_from(buf.len())
            .ok()
            .filter(|length| *length <= MAX_READ)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "a read of more than MAX_READ")
            })?;
        let end = offset
            .checked_add(u64::from(length))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a read past 2^64"))?;
        // What the server reports as holes reads as zeroes.
        buf.fill(0);
        let cookie = self.request(Cmd::Read, offset, length).await?;
        let mut failure = None;
        loop {
            let chunk = self.chunk_header(cookie).await?;
            match chunk.kind {
                reply_type::OFFSET_DATA => {
                    let at = self.stream.read_u64().await?;
                    let len = chunk
                        .length
                        .checked_sub(8)
                        .ok_or_else(|| protocol("a data chunk without its offset"))?;
                    let start = within(offset, end, at, len)?;
                    self.stream
                        .read_exact(&mut buf[start..start + len as usize])
                        .await?;
                }
                reply_type::OFFSET_HOLE => {
                    let payload = self.payload(chunk.length).await?;
                    let (at, len) = proto::parse_offset_hole(&payload)?;
                    within(offset, end, at, len)?;
                }
                reply_type::NONE if chunk.length == 0 => {}
                kind if proto::is_error_chunk(kind) => {
                    let payload = self.payload(chunk.length).await?;
                    failure.get_or_insert(failed(&payload)?);
                }
                kind => return Err(protocol(format!("chunk type {kind} in a read's reply"))),
            }
            if chunk.flags & REPLY_FLAG_DONE != 0 {
                break;
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// How `length` bytes at `offset` are allocated, as extents in order from
    /// `offset`. They may stop short of `offset + length`.
    pub async fn block_status(
        &mut self,
        offset: u64,
        length: u32,
    ) -> Result<Vec<Extent>, ClientError> {
        let context = self.base_allocation.ok_or(ClientError::NoBlockStatus)?;
        let cookie = self.request(Cmd::BlockStatus, offset, length).await?;
        let mut descriptors = Vec::new();
        let mut failure = None;
        loop {
            let chunk = self.chunk_header(cookie).await?;
            let payload = self.payload(chunk.length).await?;
            match chunk.kind {
                reply_type::BLOCK_STATUS => {
                    let (id, extents) = proto::parse_block_status(&payload)?;
                    if id == context {
                        descriptors = extents;
                    }
                }
                reply_type::NONE if payload.is_empty() => {}
                kind if proto::is_error_chunk(kind) => {
                    failure.get_or_insert(failed(&payload)?);
                }
                kind => {
                    return Err(protocol(format!(
                        "chunk type {kind} in a block status reply"
                    )));
                }
            }
            if chunk.flags & REPLY_FLAG_DONE != 0 {
                break;
            }
        }
        if let Some(failure) = failure {
            return Err(failure);
        }
        // The last extent may go past the request; none may be empty.
        let mut extents = Vec::new();
        let mut left = length;
        for descriptor in descriptors {
            if descriptor.length == 0 {
                return Err(protocol("an empty extent"));
            }
            let length = descriptor.length.min(left);
            let kind = if descriptor.flags & allocation::HOLE != 0 {
                ExtentKind::Hole
            } else {
                ExtentKind::Data
            };
            extents.push(Extent { length, kind });
            left -= length;
            if left == 0 {
                break;
            }
        }
        if extents.is_empty() {
            return Err(protocol("a block status without extents"));
        }
        Ok(extents)
    }

    /// Copy the export over `file`: its data, and its holes as holes where the
    /// server reports block status. Returns how many bytes of data it read.
    pub async fn copy_to(&mut self, file: File) -> Result<u64, ClientError> {
        let file = Arc::new(file);
        let size = self.size;
        blocking({
            let file = file.clone();
            // Emptied first, so that what the export has as holes is.
            move || file.set_len(0).and_then(|()| file.set_len(size))
        })
        .await?;
        let mut copied = 0;
        let mut offset = 0;
        while offset < size {
            let span = (size - offset).min(STATUS_SPAN) as u32;
            let extents = match self.base_allocation {
                Some(_) => self.block_status(offset, span).await?,
                None => vec![Extent {
                    length: span,
                    kind: ExtentKind::Data,
                }],
            };
            for extent in extents {
                let end = offset + u64::from(extent.length);
                if extent.kind == ExtentKind::Data {
                    let mut at = offset;
                    while at < end {
                        let mut buf = vec![0; (end - at).min(COPY_CHUNK) as usize];
                        self.read(at, &mut buf).await?;
                        let len = buf.len() as u64;
                        let file = file.clone();
                        blocking(move || file.write_all_at(&buf, at)).await?;
                        at += len;
                        copied += len;
                    }
                }
                offset = end;
            }
        }
        Ok(copied)
    }

    /// Tell the server the client is done, and close the connection.
    pub async fn disconnect(mut self) -> Result<(), ClientError> {
        self.request(Cmd::Disc, 0, 0).await?;
        // Over TLS this sends close_notify. The server may have closed already.
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    async fn request(&mut self, cmd: Cmd, offset: u64, length: u32) -> Result<u64, ClientError> {
        self.cookie += 1;
        let request = proto::request(0, cmd, self.cookie, offset, length);
        send(&mut self.stream, &request).await?;
        Ok(self.cookie)
    }

    /// The header of the next reply chunk, which must answer request `cookie`.
    async fn chunk_header(&mut self, cookie: u64) -> Result<proto::ChunkHeader, ClientError> {
        let magic = self.stream.read_u32().await?;
        if magic != STRUCTURED_REPLY_MAGIC {
            return Err(protocol(format!(
                "magic {magic:#x} where a structured reply chunk was due"
            )));
        }
        let mut header = [0; CHUNK_HEADER_LEN - 4];
        self.stream.read_exact(&mut header).await?;
        let header = proto::parse_chunk_header(&header)?;
        if header.cookie != cookie {
            return Err(protocol(format!(
                "a reply to request {} where {cookie}'s was due",
                header.cookie
            )));
        }
        Ok(header)
    }

    async fn payload(&mut self, length: u32) -> Result<Vec<u8>, ClientError> {
        if length > MAX_CHUNK {
            return Err(protocol(format!("a reply chunk of {length} bytes")));
        }
        let mut payload = vec![0; length as usize];
        self.stream.read_exact(&mut payload).await?;
        Ok(payload)
    }
}

/// Where `len` bytes the server sent for `at` go in the buffer of a read of
/// `start..end`: the server may only send what the read asked for.
fn within(start: u64, end: u64, at: u64, len: u32) -> Result<usize, ClientError> {
    let fits = at >= start
        && at
            .checked_add(u64::from(len))
            .is_some_and(|stop| stop <= end);
    if !fits {
        return Err(protocol(format!(
            "{len} bytes at {at}, outside the read of {start}..{end}"
        )));
    }
    Ok((at - start) as usize)
}

fn failed(payload: &[u8]) -> Result<ClientError, ClientError> {
    let (errno, message) = proto::parse_error_chunk(payload)?;
    Ok(ClientError::Failed { errno, message })
}

fn refused(option: Opt, payload: &[u8]) -> ClientError {
    ClientError::Refused {
        option,
        message: String::from_utf8_lossy(payload).into_owned(),
    }
}

/// Read the server's greeting and answer it.
async fn greet<S>(stream: &mut S) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0; 18];
    stream.read_exact(&mut greeting).await?;
    let flags = proto::parse_greeting(&greeting)?;
    if flags & handshake_flags::FIXED_NEWSTYLE == 0 {
        return Err(protocol("the server doesn't speak fixed newstyle"));
    }
    let mut ours = client_flags::FIXED_NEWSTYLE;
    if flags & handshake_flags::NO_ZEROES != 0 {
        ours |= client_flags::NO_ZEROES;
    }
    send(stream, &ours.to_be_bytes()).await?;
    Ok(())
}

async fn send_option<S>(stream: &mut S, option: Opt, data: &[u8]) -> Result<(), ClientError>
where
    S: AsyncWrite + Unpin,
{
    send(stream, &proto::option_request(option, data)).await?;
    Ok(())
}

/// The next reply to `option`: its type and payload.
async fn option_reply<S>(stream: &mut S, option: Opt) -> Result<(u32, Vec<u8>), ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; OPTION_REPLY_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let header = proto::parse_option_reply_header(&header)?;
    if header.option != option.code() {
        return Err(protocol(format!(
            "a reply to option {} where {option:?}'s was due",
            header.option
        )));
    }
    if header.length > MAX_OPTION_REPLY {
        return Err(protocol(format!(
            "an option reply of {} bytes",
            header.length
        )));
    }
    let mut payload = vec![0; header.length as usize];
    stream.read_exact(&mut payload).await?;
    Ok((header.reply_type, payload))
}

async fn expect_ack<S>(stream: &mut S, option: Opt) -> Result<(), ClientError>
where
    S: AsyncRead + Unpin,
{
    match option_reply(stream, option).await? {
        (rep::ACK, _) => Ok(()),
        (t, payload) if proto::is_option_error(t) => Err(refused(option, &payload)),
        (t, _) => Err(protocol(format!("reply {t} to {option:?}"))),
    }
}

async fn send<S>(stream: &mut S, bytes: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(bytes).await?;
    // A TLS stream holds what it's given until flushed.
    stream.flush().await
}

/// Run `op`, blocking file I/O, off the async runtime.
async fn blocking<T: Send + 'static>(
    op: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    match tokio::task::spawn_blocking(op).await {
        Ok(result) => result,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}
