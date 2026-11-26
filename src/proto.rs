//! The NBD wire format, as the protocol specification defines it
//! (<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>):
//! its constants, and the parsing and encoding of what a server reads and
//! writes. Nothing in this module does I/O, so it can be tested and fuzzed on
//! plain bytes.
//!
//! Every integer on the wire is big-endian.

/// The first eight bytes a server sends: `NBDMAGIC`.
pub const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943;
/// `IHAVEOPT`: follows [`NBD_MAGIC`] from a newstyle server, and starts every
/// option a client sends.
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
/// Starts every reply to an option.
pub const OPTION_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
/// Starts every request in the transmission phase.
pub const REQUEST_MAGIC: u32 = 0x2560_9513;
/// Starts a simple reply.
pub const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
/// Starts each chunk of a structured reply.
pub const STRUCTURED_REPLY_MAGIC: u32 = 0x668e_33ef;

/// The longest string a peer may send: an export name, or a metadata context
/// name or query.
pub const MAX_STRING: usize = 4096;

/// Handshake flags, which the server sends after [`IHAVEOPT`].
pub mod handshake_flags {
    pub const FIXED_NEWSTYLE: u16 = 1 << 0;
    pub const NO_ZEROES: u16 = 1 << 1;
}

/// Client flags, the client's answer to the handshake flags.
pub mod client_flags {
    pub const FIXED_NEWSTYLE: u32 = 1 << 0;
    pub const NO_ZEROES: u32 = 1 << 1;
}

/// An option a client sends during negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opt {
    ExportName,
    Abort,
    List,
    StartTls,
    Info,
    Go,
    StructuredReply,
    ListMetaContext,
    SetMetaContext,
}

impl Opt {
    /// The option `code` stands for, or `None` for one this crate doesn't
    /// know, which a server refuses with [`OptError::Unsup`].
    pub fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::ExportName,
            2 => Self::Abort,
            3 => Self::List,
            5 => Self::StartTls,
            6 => Self::Info,
            7 => Self::Go,
            8 => Self::StructuredReply,
            9 => Self::ListMetaContext,
            10 => Self::SetMetaContext,
            _ => return None,
        })
    }
}

/// Types of replies to options that succeeded.
pub mod rep {
    pub const ACK: u32 = 1;
    pub const SERVER: u32 = 2;
    pub const INFO: u32 = 3;
    pub const META_CONTEXT: u32 = 4;
}

/// Types of replies to options that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptError {
    /// The option is unknown or not implemented.
    Unsup,
    /// The server refuses the option by policy.
    Policy,
    /// The option's data is malformed, or the option isn't valid now.
    Invalid,
    /// The client must negotiate TLS first.
    TlsReqd,
    /// There is no export by that name.
    Unknown,
}

impl OptError {
    /// The reply type on the wire.
    pub fn code(self) -> u32 {
        const ERROR: u32 = 1 << 31;
        ERROR
            | match self {
                Self::Unsup => 1,
                Self::Policy => 2,
                Self::Invalid => 3,
                Self::TlsReqd => 5,
                Self::Unknown => 6,
            }
    }
}

/// Information types in `NBD_OPT_INFO` and `NBD_OPT_GO`.
pub mod info {
    pub const EXPORT: u16 = 0;
    pub const NAME: u16 = 1;
    pub const DESCRIPTION: u16 = 2;
    pub const BLOCK_SIZE: u16 = 3;
}

/// Transmission flags: what an export is and which commands it takes.
pub mod transmission_flags {
    pub const HAS_FLAGS: u16 = 1 << 0;
    pub const READ_ONLY: u16 = 1 << 1;
    pub const SEND_FLUSH: u16 = 1 << 2;
    pub const SEND_FUA: u16 = 1 << 3;
    pub const ROTATIONAL: u16 = 1 << 4;
    pub const SEND_TRIM: u16 = 1 << 5;
    pub const SEND_WRITE_ZEROES: u16 = 1 << 6;
    pub const SEND_DF: u16 = 1 << 7;
    pub const CAN_MULTI_CONN: u16 = 1 << 8;
    pub const SEND_RESIZE: u16 = 1 << 9;
    pub const SEND_CACHE: u16 = 1 << 10;
    pub const SEND_FAST_ZERO: u16 = 1 << 11;
}

/// A command in the transmission phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Read,
    Write,
    Disc,
    Flush,
    Trim,
    Cache,
    WriteZeroes,
    BlockStatus,
    Resize,
}

impl Cmd {
    /// The command `code` stands for, or `None` for one this crate doesn't know.
    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Disc,
            3 => Self::Flush,
            4 => Self::Trim,
            5 => Self::Cache,
            6 => Self::WriteZeroes,
            7 => Self::BlockStatus,
            8 => Self::Resize,
            _ => return None,
        })
    }
}

/// Command flags.
pub mod command_flags {
    pub const FUA: u16 = 1 << 0;
    pub const NO_HOLE: u16 = 1 << 1;
    pub const DF: u16 = 1 << 2;
    pub const REQ_ONE: u16 = 1 << 3;
    pub const FAST_ZERO: u16 = 1 << 4;
    pub const PAYLOAD_LEN: u16 = 1 << 5;
}

/// Marks the last chunk of a structured reply.
pub const REPLY_FLAG_DONE: u16 = 1 << 0;

/// Types of structured reply chunks.
pub mod reply_type {
    pub const NONE: u16 = 0;
    pub const OFFSET_DATA: u16 = 1;
    pub const OFFSET_HOLE: u16 = 2;
    pub const BLOCK_STATUS: u16 = 5;
    pub const ERROR: u16 = (1 << 15) | 1;
    pub const ERROR_OFFSET: u16 = (1 << 15) | 2;
}

/// Errors a command can fail with: the Linux errno values of the same names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Errno {
    Perm = 1,
    Io = 5,
    NoMem = 12,
    Inval = 22,
    NoSpc = 28,
    Overflow = 75,
    NotSup = 95,
    Shutdown = 108,
}

/// The metadata context that tells allocated data from holes.
pub const BASE_ALLOCATION: &str = "base:allocation";

/// Flags of a `base:allocation` extent.
pub mod allocation {
    /// Not allocated.
    pub const HOLE: u32 = 1 << 0;
    /// Reads as zeroes.
    pub const ZERO: u32 = 1 << 1;
}

/// Why bytes from a client don't parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("wrong magic number")]
    Magic,
    #[error("message ends early")]
    Truncated,
    #[error("bytes left over after the message")]
    Trailing,
    #[error("string longer than {MAX_STRING} bytes")]
    TooLong,
    #[error("string is not UTF-8")]
    NotUtf8,
}

/// Reads big-endian fields off the front of a buffer.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(ParseError::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        self.array().map(u64::from_be_bytes)
    }

    /// A UTF-8 string of `len` bytes.
    fn string(&mut self, len: u32) -> Result<String, ParseError> {
        let len = usize::try_from(len).map_err(|_| ParseError::TooLong)?;
        if len > MAX_STRING {
            return Err(ParseError::TooLong);
        }
        if self.0.len() < len {
            return Err(ParseError::Truncated);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        std::str::from_utf8(head)
            .map(str::to_owned)
            .map_err(|_| ParseError::NotUtf8)
    }

    /// The rest of the buffer as a UTF-8 string.
    fn rest_string(&mut self) -> Result<String, ParseError> {
        let len = u32::try_from(self.0.len()).map_err(|_| ParseError::TooLong)?;
        self.string(len)
    }

    fn finish(self) -> Result<(), ParseError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ParseError::Trailing)
        }
    }
}

/// What a server sends first: the magic numbers and its handshake flags.
pub fn greeting(flags: u16) -> [u8; 18] {
    let mut out = [0; 18];
    out[..8].copy_from_slice(&NBD_MAGIC.to_be_bytes());
    out[8..16].copy_from_slice(&IHAVEOPT.to_be_bytes());
    out[16..].copy_from_slice(&flags.to_be_bytes());
    out
}

/// The length of the header of an option a client sends.
pub const OPTION_HEADER_LEN: usize = 16;

/// The header of an option: its code and the length of the data after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionHeader {
    pub code: u32,
    pub length: u32,
}

pub fn parse_option_header(buf: &[u8; OPTION_HEADER_LEN]) -> Result<OptionHeader, ParseError> {
    let mut reader = Reader(buf);
    if reader.u64()? != IHAVEOPT {
        return Err(ParseError::Magic);
    }
    Ok(OptionHeader {
        code: reader.u32()?,
        length: reader.u32()?,
    })
}

/// The data of `NBD_OPT_EXPORT_NAME`: the name, without a length.
pub fn parse_export_name(data: &[u8]) -> Result<String, ParseError> {
    Reader(data).rest_string()
}

/// The data of `NBD_OPT_INFO` and `NBD_OPT_GO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoRequest {
    pub export: String,
    /// The information types (see [`info`]) the client asks for.
    pub requests: Vec<u16>,
}

pub fn parse_info_request(data: &[u8]) -> Result<InfoRequest, ParseError> {
    let mut reader = Reader(data);
    let len = reader.u32()?;
    let export = reader.string(len)?;
    let count = reader.u16()?;
    let requests = (0..count).map(|_| reader.u16()).collect::<Result<_, _>>()?;
    reader.finish()?;
    Ok(InfoRequest { export, requests })
}

/// The data of `NBD_OPT_LIST_META_CONTEXT` and `NBD_OPT_SET_META_CONTEXT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaContextRequest {
    pub export: String,
    pub queries: Vec<String>,
}

pub fn parse_meta_context_request(data: &[u8]) -> Result<MetaContextRequest, ParseError> {
    let mut reader = Reader(data);
    let len = reader.u32()?;
    let export = reader.string(len)?;
    let count = reader.u32()?;
    // Not `Vec::with_capacity(count)`: a client can claim four billion queries
    // and send none.
    let mut queries = Vec::new();
    for _ in 0..count {
        let len = reader.u32()?;
        queries.push(reader.string(len)?);
    }
    reader.finish()?;
    Ok(MetaContextRequest { export, queries })
}

/// A reply to option `option`.
pub fn option_reply(option: u32, reply_type: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("option replies are small");
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&OPTION_REPLY_MAGIC.to_be_bytes());
    out.extend_from_slice(&option.to_be_bytes());
    out.extend_from_slice(&reply_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A refusal of option `option`, with a message for people.
pub fn option_error(option: u32, error: OptError, message: &str) -> Vec<u8> {
    option_reply(option, error.code(), message.as_bytes())
}

/// The payload of `NBD_REP_INFO` with `NBD_INFO_EXPORT`.
pub fn info_export(size: u64, flags: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&info::EXPORT.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

/// The payload of `NBD_REP_INFO` with `NBD_INFO_BLOCK_SIZE`.
pub fn info_block_size(minimum: u32, preferred: u32, maximum: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    out.extend_from_slice(&info::BLOCK_SIZE.to_be_bytes());
    out.extend_from_slice(&minimum.to_be_bytes());
    out.extend_from_slice(&preferred.to_be_bytes());
    out.extend_from_slice(&maximum.to_be_bytes());
    out
}

/// The payload of `NBD_REP_SERVER`: an export's name.
pub fn server_entry(name: &str) -> Vec<u8> {
    length_prefixed(name)
}

/// The payload of `NBD_REP_META_CONTEXT`.
pub fn meta_context_entry(id: u32, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out
}

fn length_prefixed(s: &str) -> Vec<u8> {
    let len = u32::try_from(s.len()).expect("names are short");
    let mut out = Vec::with_capacity(4 + s.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

/// The answer to `NBD_OPT_EXPORT_NAME`, after which transmission starts. A
/// client that didn't ask for `NO_ZEROES` expects 124 zeroes at the end.
pub fn export_name_reply(size: u64, flags: u16, no_zeroes: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(134);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    if !no_zeroes {
        out.resize(out.len() + 124, 0);
    }
    out
}

/// The length of a request's header, which a write's data follows.
pub const REQUEST_HEADER_LEN: usize = 28;

/// A request's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Command flags (see [`command_flags`]).
    pub flags: u16,
    /// The command's code (see [`Cmd::from_code`]).
    pub kind: u16,
    /// Chosen by the client and returned in the reply.
    pub cookie: u64,
    pub offset: u64,
    pub length: u32,
}

pub fn parse_request(buf: &[u8; REQUEST_HEADER_LEN]) -> Result<Request, ParseError> {
    let mut reader = Reader(buf);
    if reader.u32()? != REQUEST_MAGIC {
        return Err(ParseError::Magic);
    }
    Ok(Request {
        flags: reader.u16()?,
        kind: reader.u16()?,
        cookie: reader.u64()?,
        offset: reader.u64()?,
        length: reader.u32()?,
    })
}

/// The length of a simple reply, which a read's data follows.
pub const SIMPLE_REPLY_LEN: usize = 16;

pub fn simple_reply(cookie: u64, error: Option<Errno>) -> [u8; SIMPLE_REPLY_LEN] {
    let mut out = [0; SIMPLE_REPLY_LEN];
    out[..4].copy_from_slice(&SIMPLE_REPLY_MAGIC.to_be_bytes());
    out[4..8].copy_from_slice(&error.map_or(0, |e| e as u32).to_be_bytes());
    out[8..].copy_from_slice(&cookie.to_be_bytes());
    out
}

/// The length of a structured reply chunk's header.
pub const CHUNK_HEADER_LEN: usize = 20;

pub fn chunk_header(flags: u16, kind: u16, cookie: u64, length: u32) -> [u8; CHUNK_HEADER_LEN] {
    let mut out = [0; CHUNK_HEADER_LEN];
    out[..4].copy_from_slice(&STRUCTURED_REPLY_MAGIC.to_be_bytes());
    out[4..6].copy_from_slice(&flags.to_be_bytes());
    out[6..8].copy_from_slice(&kind.to_be_bytes());
    out[8..16].copy_from_slice(&cookie.to_be_bytes());
    out[16..].copy_from_slice(&length.to_be_bytes());
    out
}

/// The length of what [`offset_data_prefix`] returns.
pub const OFFSET_DATA_PREFIX_LEN: usize = CHUNK_HEADER_LEN + 8;

/// The start of an `NBD_REPLY_TYPE_OFFSET_DATA` chunk that completes its
/// reply: the header and the offset, which `len` bytes of data follow.
pub fn offset_data_prefix(cookie: u64, offset: u64, len: u32) -> [u8; OFFSET_DATA_PREFIX_LEN] {
    let mut out = [0; OFFSET_DATA_PREFIX_LEN];
    out[..CHUNK_HEADER_LEN].copy_from_slice(&chunk_header(
        REPLY_FLAG_DONE,
        reply_type::OFFSET_DATA,
        cookie,
        len.checked_add(8).expect("reads are at most MAX_PAYLOAD"),
    ));
    out[CHUNK_HEADER_LEN..].copy_from_slice(&offset.to_be_bytes());
    out
}

/// A structured reply that completes without data.
pub fn none_chunk(cookie: u64) -> [u8; CHUNK_HEADER_LEN] {
    chunk_header(REPLY_FLAG_DONE, reply_type::NONE, cookie, 0)
}

/// A structured reply that fails with `error`, with a message for people.
pub fn error_chunk(cookie: u64, error: Errno, message: &str) -> Vec<u8> {
    let message = &message.as_bytes()[..message.len().min(MAX_STRING)];
    let message_len = u16::try_from(message.len()).expect("MAX_STRING fits in u16");
    let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + 6 + message.len());
    out.extend_from_slice(&chunk_header(
        REPLY_FLAG_DONE,
        reply_type::ERROR,
        cookie,
        6 + u32::from(message_len),
    ));
    out.extend_from_slice(&(error as u32).to_be_bytes());
    out.extend_from_slice(&message_len.to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// One extent in an `NBD_REPLY_TYPE_BLOCK_STATUS` chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    pub length: u32,
    /// The context's flags for the extent, such as [`allocation::HOLE`].
    pub flags: u32,
}

/// A structured reply that completes with one context's extents.
pub fn block_status_chunk(cookie: u64, context_id: u32, descriptors: &[Descriptor]) -> Vec<u8> {
    let length = 4 + 8 * descriptors.len();
    let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + length);
    out.extend_from_slice(&chunk_header(
        REPLY_FLAG_DONE,
        reply_type::BLOCK_STATUS,
        cookie,
        u32::try_from(length).expect("one descriptor per extent of a u32-long request"),
    ));
    out.extend_from_slice(&context_id.to_be_bytes());
    for descriptor in descriptors {
        out.extend_from_slice(&descriptor.length.to_be_bytes());
        out.extend_from_slice(&descriptor.flags.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn option_header(magic: u64, code: u32, length: u32) -> [u8; OPTION_HEADER_LEN] {
        let mut buf = [0; OPTION_HEADER_LEN];
        buf[..8].copy_from_slice(&magic.to_be_bytes());
        buf[8..12].copy_from_slice(&code.to_be_bytes());
        buf[12..].copy_from_slice(&length.to_be_bytes());
        buf
    }

    #[test]
    fn option_header_needs_ihaveopt() {
        assert_eq!(
            parse_option_header(&option_header(IHAVEOPT, 7, 12)),
            Ok(OptionHeader {
                code: 7,
                length: 12
            })
        );
        assert_eq!(
            parse_option_header(&option_header(NBD_MAGIC, 7, 12)),
            Err(ParseError::Magic)
        );
    }

    fn info_data(name: &[u8], requests: &[u16]) -> Vec<u8> {
        let mut data = (name.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(name);
        data.extend_from_slice(&(requests.len() as u16).to_be_bytes());
        for request in requests {
            data.extend_from_slice(&request.to_be_bytes());
        }
        data
    }

    #[test]
    fn info_request_must_be_exact() {
        let data = info_data(b"disk", &[info::BLOCK_SIZE]);
        assert_eq!(
            parse_info_request(&data),
            Ok(InfoRequest {
                export: "disk".into(),
                requests: vec![info::BLOCK_SIZE],
            })
        );
        assert_eq!(
            parse_info_request(&data[..data.len() - 1]),
            Err(ParseError::Truncated)
        );
        let mut trailing = data.clone();
        trailing.push(0);
        assert_eq!(parse_info_request(&trailing), Err(ParseError::Trailing));
        // A name longer than the data that follows it.
        let mut short = data.clone();
        short[..4].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(parse_info_request(&short), Err(ParseError::Truncated));
    }

    #[test]
    fn names_must_be_short_utf8() {
        let long = vec![b'a'; MAX_STRING + 1];
        assert_eq!(
            parse_info_request(&info_data(&long, &[])),
            Err(ParseError::TooLong)
        );
        assert_eq!(
            parse_info_request(&info_data(b"\xff", &[])),
            Err(ParseError::NotUtf8)
        );
        assert_eq!(parse_export_name(&long), Err(ParseError::TooLong));
    }

    #[test]
    fn meta_context_count_is_not_trusted() {
        let mut data = 4u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"disk");
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            parse_meta_context_request(&data),
            Err(ParseError::Truncated)
        );

        let query = BASE_ALLOCATION.as_bytes();
        data[8..12].copy_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&(query.len() as u32).to_be_bytes());
        data.extend_from_slice(query);
        assert_eq!(
            parse_meta_context_request(&data),
            Ok(MetaContextRequest {
                export: "disk".into(),
                queries: vec![BASE_ALLOCATION.into()],
            })
        );
    }

    #[test]
    fn request_needs_its_magic() {
        let mut buf = [0; REQUEST_HEADER_LEN];
        buf[..4].copy_from_slice(&REQUEST_MAGIC.to_be_bytes());
        buf[4..6].copy_from_slice(&command_flags::FUA.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        buf[8..16].copy_from_slice(&42u64.to_be_bytes());
        buf[16..24].copy_from_slice(&4096u64.to_be_bytes());
        buf[24..].copy_from_slice(&512u32.to_be_bytes());
        assert_eq!(
            parse_request(&buf),
            Ok(Request {
                flags: command_flags::FUA,
                kind: 1,
                cookie: 42,
                offset: 4096,
                length: 512,
            })
        );
        buf[0] ^= 1;
        assert_eq!(parse_request(&buf), Err(ParseError::Magic));
    }
}
