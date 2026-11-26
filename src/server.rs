use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use crate::backend::{Backend, ExtentKind};
use crate::proto::{
    self, BASE_ALLOCATION, Cmd, Descriptor, Errno, Opt, OptError, Request, allocation,
    client_flags, command_flags, handshake_flags, info, rep, transmission_flags,
};

/// The most data an option may carry. No option a client sends in good faith
/// comes near it; one that does ends the connection.
const MAX_OPTION_LEN: u32 = 64 * 1024;
/// The largest read or write: what clients assume of a server that states no
/// block sizes, and what this one states to clients that ask.
const MAX_PAYLOAD: u32 = 32 * 1024 * 1024;
/// Any alignment works; 4 KiB is best.
const MIN_BLOCK_SIZE: u32 = 1;
const PREFERRED_BLOCK_SIZE: u32 = 4096;
/// The ID of `base:allocation`, the only metadata context.
const BASE_ALLOCATION_ID: u32 = 0;

/// Why a connection ended, other than the client closing it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The client broke the protocol in a way that leaves no reply to send.
    #[error("protocol error: {0}")]
    Protocol(String),
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

/// An NBD server: named exports, each served to one client per
/// [`serve`](Self::serve) call.
#[derive(Default)]
pub struct Server {
    exports: BTreeMap<String, Arc<dyn Backend>>,
    tls: Option<TlsAcceptor>,
}

impl Server {
    /// A server that speaks plain NBD, for clients that can't be anyone else,
    /// such as those on a Unix socket that only they may open.
    pub fn new() -> Self {
        Self::default()
    }

    /// A server that requires TLS: a client must upgrade the connection with
    /// `NBD_OPT_STARTTLS` before anything else. The acceptor's configuration
    /// decides whether clients need certificates.
    pub fn with_tls(acceptor: TlsAcceptor) -> Self {
        Self {
            exports: BTreeMap::new(),
            tls: Some(acceptor),
        }
    }

    /// Serve `backend` as `name`.
    pub fn export(mut self, name: impl Into<String>, backend: Arc<dyn Backend>) -> Self {
        self.exports.insert(name.into(), backend);
        self
    }

    /// Serve one client on `stream` until it disconnects.
    pub async fn serve<S>(&self, mut stream: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let no_zeroes = handshake(&mut stream).await?;
        let Some(acceptor) = &self.tls else {
            return self.run(stream, Transport::Plain, no_zeroes).await;
        };
        match await_starttls(&mut stream).await? {
            BeforeTls::Abort => Ok(()),
            BeforeTls::StartTls => {
                let stream = acceptor.accept(stream).await?;
                self.run(stream, Transport::Tls, no_zeroes).await
            }
        }
    }

    async fn run<S>(
        &self,
        mut stream: S,
        transport: Transport,
        no_zeroes: bool,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match self.negotiate(&mut stream, transport, no_zeroes).await? {
            Some(session) => session.transmit(stream).await,
            None => Ok(()),
        }
    }

    /// Answer options until the client picks an export (returned) or gives up.
    async fn negotiate<S>(
        &self,
        stream: &mut S,
        transport: Transport,
        no_zeroes: bool,
    ) -> Result<Option<Session>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut structured = false;
        // The export `base:allocation` was selected for, if it was.
        let mut selected: Option<String> = None;
        loop {
            let (code, data) = read_option(stream).await?;
            let ack = proto::option_reply(code, rep::ACK, &[]);

            macro_rules! refuse {
                ($error:expr, $message:expr) => {{
                    debug!(option = code, message = %$message, "refusing option");
                    send(stream, &proto::option_error(code, $error, &$message)).await?;
                    continue;
                }};
            }

            let Some(opt) = Opt::from_code(code) else {
                refuse!(OptError::Unsup, "unknown option");
            };
            match opt {
                Opt::ExportName => {
                    // This option has no error reply: hanging up is the only
                    // way to refuse it.
                    let name = proto::parse_export_name(&data)
                        .map_err(|e| protocol(format!("NBD_OPT_EXPORT_NAME: {e}")))?;
                    let backend = self
                        .exports
                        .get(&name)
                        .ok_or_else(|| protocol(format!("no export named {name:?}")))?;
                    let session = Session::new(
                        backend.clone(),
                        structured,
                        selected.as_deref() == Some(&name),
                    );
                    let reply = proto::export_name_reply(session.size, session.flags(), no_zeroes);
                    send(stream, &reply).await?;
                    return Ok(Some(session));
                }
                Opt::Abort => {
                    // The client may hang up without waiting for the answer.
                    let _ = send(stream, &ack).await;
                    return Ok(None);
                }
                Opt::List => {
                    if !data.is_empty() {
                        refuse!(OptError::Invalid, "NBD_OPT_LIST takes no data");
                    }
                    let mut out = Vec::new();
                    for name in self.exports.keys() {
                        out.extend(proto::option_reply(
                            code,
                            rep::SERVER,
                            &proto::server_entry(name),
                        ));
                    }
                    out.extend(ack);
                    send(stream, &out).await?;
                }
                Opt::StartTls => match transport {
                    Transport::Plain => refuse!(OptError::Policy, "TLS is not configured"),
                    Transport::Tls => refuse!(OptError::Invalid, "TLS is already on"),
                },
                Opt::Info | Opt::Go => {
                    let request = match proto::parse_info_request(&data) {
                        Ok(request) => request,
                        Err(e) => refuse!(OptError::Invalid, e.to_string()),
                    };
                    let Some(backend) = self.exports.get(&request.export) else {
                        refuse!(
                            OptError::Unknown,
                            format!("no export named {:?}", request.export)
                        );
                    };
                    let session = Session::new(
                        backend.clone(),
                        structured,
                        selected.as_deref() == Some(&request.export),
                    );
                    let mut out = proto::option_reply(
                        code,
                        rep::INFO,
                        &proto::info_export(session.size, session.flags()),
                    );
                    if request.requests.contains(&info::BLOCK_SIZE) {
                        out.extend(proto::option_reply(
                            code,
                            rep::INFO,
                            &proto::info_block_size(
                                MIN_BLOCK_SIZE,
                                PREFERRED_BLOCK_SIZE,
                                MAX_PAYLOAD,
                            ),
                        ));
                    }
                    out.extend(ack);
                    send(stream, &out).await?;
                    if opt == Opt::Go {
                        return Ok(Some(session));
                    }
                }
                Opt::StructuredReply => {
                    if !data.is_empty() {
                        refuse!(OptError::Invalid, "NBD_OPT_STRUCTURED_REPLY takes no data");
                    }
                    if structured {
                        refuse!(OptError::Invalid, "structured replies are already on");
                    }
                    structured = true;
                    send(stream, &ack).await?;
                }
                Opt::ListMetaContext | Opt::SetMetaContext => {
                    if !structured {
                        refuse!(
                            OptError::Invalid,
                            "metadata contexts need structured replies"
                        );
                    }
                    let request = match proto::parse_meta_context_request(&data) {
                        Ok(request) => request,
                        Err(e) => refuse!(OptError::Invalid, e.to_string()),
                    };
                    if !self.exports.contains_key(&request.export) {
                        refuse!(
                            OptError::Unknown,
                            format!("no export named {:?}", request.export)
                        );
                    }
                    let queries = &request.queries;
                    let matched = if opt == Opt::ListMetaContext {
                        // No queries, or a namespace alone, lists every context.
                        queries.is_empty()
                            || queries.iter().any(|q| q == "base:" || q == BASE_ALLOCATION)
                    } else {
                        queries.iter().any(|q| q == BASE_ALLOCATION)
                    };
                    if opt == Opt::SetMetaContext {
                        selected = matched.then_some(request.export);
                    }
                    let mut out = Vec::new();
                    if matched {
                        out.extend(proto::option_reply(
                            code,
                            rep::META_CONTEXT,
                            &proto::meta_context_entry(BASE_ALLOCATION_ID, BASE_ALLOCATION),
                        ));
                    }
                    out.extend(ack);
                    send(stream, &out).await?;
                }
            }
        }
    }
}

/// Whether option negotiation runs over TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// TLS isn't configured.
    Plain,
    Tls,
}

enum BeforeTls {
    StartTls,
    Abort,
}

/// Send the greeting and read the client's flags. Returns whether the client
/// asked to skip the zeroes at the end of the `NBD_OPT_EXPORT_NAME` reply.
async fn handshake<S>(stream: &mut S) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let greeting = proto::greeting(handshake_flags::FIXED_NEWSTYLE | handshake_flags::NO_ZEROES);
    send(stream, &greeting).await?;
    let flags = stream.read_u32().await?;
    let known = client_flags::FIXED_NEWSTYLE | client_flags::NO_ZEROES;
    if flags & !known != 0 {
        return Err(protocol(format!("unknown client flags {flags:#x}")));
    }
    // Newstyle without "fixed" has no way to refuse an option: no client in
    // use still speaks it.
    if flags & client_flags::FIXED_NEWSTYLE == 0 {
        return Err(protocol("the client doesn't speak fixed newstyle"));
    }
    Ok(flags & client_flags::NO_ZEROES != 0)
}

/// Before TLS, a client may only start it or give up.
async fn await_starttls<S>(stream: &mut S) -> Result<BeforeTls, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let (code, data) = read_option(stream).await?;
        let ack = proto::option_reply(code, rep::ACK, &[]);
        match Opt::from_code(code) {
            Some(Opt::StartTls) if data.is_empty() => {
                send(stream, &ack).await?;
                return Ok(BeforeTls::StartTls);
            }
            Some(Opt::StartTls) => {
                let reply =
                    proto::option_error(code, OptError::Invalid, "NBD_OPT_STARTTLS takes no data");
                send(stream, &reply).await?;
            }
            Some(Opt::Abort) => {
                // The client may hang up without waiting for the answer.
                let _ = send(stream, &ack).await;
                return Ok(BeforeTls::Abort);
            }
            Some(Opt::ExportName) => {
                return Err(protocol("NBD_OPT_EXPORT_NAME before TLS"));
            }
            _ => {
                let reply = proto::option_error(code, OptError::TlsReqd, "TLS is required");
                send(stream, &reply).await?;
            }
        }
    }
}

async fn read_option<S>(stream: &mut S) -> Result<(u32, Vec<u8>), Error>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; proto::OPTION_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let header =
        proto::parse_option_header(&header).map_err(|e| protocol(format!("option header: {e}")))?;
    if header.length > MAX_OPTION_LEN {
        return Err(protocol(format!(
            "option {} carries {} bytes",
            header.code, header.length
        )));
    }
    let mut data = vec![0; header.length as usize];
    stream.read_exact(&mut data).await?;
    Ok((header.code, data))
}

async fn send<S>(stream: &mut S, bytes: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(bytes).await?;
    // A TLS stream holds what it's given until flushed.
    stream.flush().await
}

/// A client's connection to an export, in the transmission phase.
struct Session {
    backend: Arc<dyn Backend>,
    size: u64,
    read_only: bool,
    structured: bool,
    base_allocation: bool,
}

/// What a valid request asks for.
enum Next {
    Op(Op),
    Disconnect,
}

/// A command this export carries out.
enum Op {
    Read,
    Write(Vec<u8>),
    Flush,
    Trim,
    Zero { may_trim: bool },
    BlockStatus { one: bool },
}

/// Why a request is refused, before it reaches the backend.
struct Refusal {
    errno: Errno,
    message: &'static str,
}

fn refuse(errno: Errno, message: &'static str) -> Refusal {
    Refusal { errno, message }
}

impl Session {
    fn new(backend: Arc<dyn Backend>, structured: bool, base_allocation: bool) -> Self {
        Self {
            size: backend.size(),
            read_only: backend.read_only(),
            backend,
            structured,
            base_allocation,
        }
    }

    /// The transmission flags: what the export is and which commands it takes.
    fn flags(&self) -> u16 {
        use transmission_flags::*;
        let mut flags = HAS_FLAGS | SEND_FLUSH | CAN_MULTI_CONN;
        flags |= if self.read_only {
            READ_ONLY
        } else {
            SEND_FUA | SEND_TRIM | SEND_WRITE_ZEROES
        };
        if self.structured {
            flags |= SEND_DF;
        }
        flags
    }

    /// Serve requests one at a time until the client disconnects.
    async fn transmit<S>(self, stream: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = BufReader::new(stream);
        loop {
            let mut header = [0; proto::REQUEST_HEADER_LEN];
            match stream.read_exact(&mut header).await {
                Ok(_) => {}
                // A client that hangs up without NBD_CMD_DISC is gone all the same.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let request =
                proto::parse_request(&header).map_err(|e| protocol(format!("request: {e}")))?;
            let cmd = Cmd::from_code(request.kind);
            // A write's data follows its header whether or not it's valid:
            // read it now, so that the next request starts where it should.
            let payload = if cmd == Some(Cmd::Write) {
                if request.length > MAX_PAYLOAD {
                    let reply = proto::simple_reply(request.cookie, Some(Errno::Inval));
                    send(&mut stream, &reply).await?;
                    return Err(protocol(format!("a write of {} bytes", request.length)));
                }
                let mut payload = vec![0; request.length as usize];
                stream.read_exact(&mut payload).await?;
                payload
            } else {
                Vec::new()
            };
            let reply = match self.check(cmd, &request, payload) {
                Ok(Next::Disconnect) => break,
                Ok(Next::Op(op)) => self.execute(op, &request).await,
                Err(refusal) => {
                    debug!(
                        ?cmd,
                        ?request,
                        message = refusal.message,
                        "refusing request"
                    );
                    self.error_reply(cmd, request.cookie, refusal.errno, refusal.message)
                }
            };
            send(&mut stream, &reply).await?;
        }
        // Over TLS this sends close_notify. The client may be gone already.
        let _ = stream.shutdown().await;
        Ok(())
    }

    /// Check `request` against the protocol's rules and this export.
    fn check(
        &self,
        cmd: Option<Cmd>,
        request: &Request,
        payload: Vec<u8>,
    ) -> Result<Next, Refusal> {
        let cmd = cmd.ok_or_else(|| refuse(Errno::Inval, "unknown command"))?;
        if cmd == Cmd::Disc {
            return Ok(Next::Disconnect);
        }
        // FUA is accepted on any command, and means nothing on those that
        // don't write.
        let allowed = command_flags::FUA
            | match cmd {
                Cmd::Read if self.structured => command_flags::DF,
                Cmd::WriteZeroes => command_flags::NO_HOLE,
                Cmd::BlockStatus => command_flags::REQ_ONE,
                _ => 0,
            };
        if request.flags & !allowed != 0 {
            return Err(refuse(Errno::Inval, "unsupported command flags"));
        }
        let writes = matches!(cmd, Cmd::Write | Cmd::Trim | Cmd::WriteZeroes);
        if writes && self.read_only {
            return Err(refuse(Errno::Perm, "the export is read-only"));
        }
        let ranged = writes || matches!(cmd, Cmd::Read | Cmd::BlockStatus);
        let end = request.offset.checked_add(u64::from(request.length));
        if ranged && end.is_none_or(|end| end > self.size) {
            let errno = if matches!(cmd, Cmd::Write | Cmd::WriteZeroes) {
                Errno::NoSpc
            } else {
                Errno::Inval
            };
            return Err(refuse(errno, "the request goes past the end of the export"));
        }
        let op = match cmd {
            Cmd::Read if request.length > MAX_PAYLOAD => {
                return Err(refuse(Errno::Inval, "the read is too large"));
            }
            Cmd::Read => Op::Read,
            Cmd::Write => Op::Write(payload),
            Cmd::Flush => Op::Flush,
            Cmd::Trim => Op::Trim,
            Cmd::WriteZeroes => Op::Zero {
                may_trim: request.flags & command_flags::NO_HOLE == 0,
            },
            Cmd::BlockStatus if !self.base_allocation => {
                return Err(refuse(Errno::Inval, "no metadata context is selected"));
            }
            Cmd::BlockStatus if request.length == 0 => {
                return Err(refuse(Errno::Inval, "block status of no bytes"));
            }
            Cmd::BlockStatus => Op::BlockStatus {
                one: request.flags & command_flags::REQ_ONE != 0,
            },
            Cmd::Disc => return Ok(Next::Disconnect),
            // Not advertised, so no client should send them.
            Cmd::Cache | Cmd::Resize => {
                return Err(refuse(Errno::Inval, "unsupported command"));
            }
        };
        Ok(Next::Op(op))
    }

    async fn execute(&self, op: Op, request: &Request) -> Vec<u8> {
        let Request {
            flags,
            cookie,
            offset,
            length,
            ..
        } = *request;
        let fua = flags & command_flags::FUA != 0;
        match op {
            Op::Read => self.read(cookie, offset, length).await,
            Op::BlockStatus { one } => self.block_status(cookie, offset, length, one).await,
            Op::Write(payload) => {
                self.update(cookie, fua, move |b| b.write_at(&payload, offset))
                    .await
            }
            Op::Flush => self.update(cookie, false, |b| b.flush()).await,
            Op::Trim => {
                self.update(cookie, fua, move |b| b.trim(offset, length))
                    .await
            }
            Op::Zero { may_trim } => {
                self.update(cookie, fua, move |b| b.zero(offset, length, may_trim))
                    .await
            }
        }
    }

    async fn read(&self, cookie: u64, offset: u64, length: u32) -> Vec<u8> {
        let header = if !self.structured {
            proto::simple_reply(cookie, None).to_vec()
        } else if length == 0 {
            return proto::none_chunk(cookie).to_vec();
        } else {
            proto::offset_data_prefix(cookie, offset, length).to_vec()
        };
        let start = header.len();
        let mut buf = header;
        buf.resize(start + length as usize, 0);
        let (buf, result) = self
            .blocking(move |b| {
                let result = b.read_at(&mut buf[start..], offset);
                (buf, result)
            })
            .await;
        match result {
            Ok(()) => buf,
            Err(e) => self.backend_error(Some(Cmd::Read), cookie, &e),
        }
    }

    async fn block_status(&self, cookie: u64, offset: u64, length: u32, one: bool) -> Vec<u8> {
        let extents = match self.blocking(move |b| b.extents(offset, length)).await {
            Ok(extents) => extents,
            Err(e) => return self.backend_error(Some(Cmd::BlockStatus), cookie, &e),
        };
        // Keep to the request whatever the backend returned: no empty
        // extents, none past its end.
        let mut descriptors = Vec::new();
        let mut left = length;
        for extent in extents {
            let length = extent.length.min(left);
            if length == 0 {
                continue;
            }
            let flags = match extent.kind {
                ExtentKind::Data => 0,
                ExtentKind::Hole => allocation::HOLE | allocation::ZERO,
            };
            descriptors.push(Descriptor { length, flags });
            left -= length;
            if left == 0 || one {
                break;
            }
        }
        if descriptors.is_empty() {
            let message = "the backend reported no extents";
            return self.error_reply(Some(Cmd::BlockStatus), cookie, Errno::Io, message);
        }
        proto::block_status_chunk(cookie, BASE_ALLOCATION_ID, &descriptors)
    }

    /// Carry out a command that replies without data, flushing after it for
    /// FUA.
    async fn update(
        &self,
        cookie: u64,
        fua: bool,
        f: impl FnOnce(&dyn Backend) -> io::Result<()> + Send + 'static,
    ) -> Vec<u8> {
        let result = self
            .blocking(move |b| {
                f(b)?;
                if fua {
                    b.flush()?;
                }
                Ok(())
            })
            .await;
        match result {
            Ok(()) => proto::simple_reply(cookie, None).to_vec(),
            Err(e) => self.backend_error(None, cookie, &e),
        }
    }

    /// Run `f` on the backend on a blocking thread.
    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn Backend) -> T + Send + 'static,
    ) -> T {
        let backend = self.backend.clone();
        match tokio::task::spawn_blocking(move || f(backend.as_ref())).await {
            Ok(value) => value,
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }

    fn backend_error(&self, cmd: Option<Cmd>, cookie: u64, error: &io::Error) -> Vec<u8> {
        debug!(?cmd, %error, "backend failed");
        self.error_reply(cmd, cookie, errno(error), &error.to_string())
    }

    /// A failed reply. Reads and block status take structured replies when
    /// those are on, which can say why; anything else takes a simple reply.
    fn error_reply(&self, cmd: Option<Cmd>, cookie: u64, errno: Errno, message: &str) -> Vec<u8> {
        if self.structured && matches!(cmd, Some(Cmd::Read | Cmd::BlockStatus)) {
            proto::error_chunk(cookie, errno, message)
        } else {
            proto::simple_reply(cookie, Some(errno)).to_vec()
        }
    }
}

/// The NBD error for a backend's I/O error.
fn errno(error: &io::Error) -> Errno {
    use io::ErrorKind::*;
    match error.kind() {
        PermissionDenied | ReadOnlyFilesystem => Errno::Perm,
        StorageFull | QuotaExceeded | FileTooLarge => Errno::NoSpc,
        InvalidInput => Errno::Inval,
        OutOfMemory => Errno::NoMem,
        Unsupported => Errno::NotSup,
        _ => Errno::Io,
    }
}
