use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

use rustix::fs::{FallocateFlags, SeekFrom, fallocate, seek};
use rustix::io::Errno;

/// Storage that a [`Server`](crate::Server) exports.
///
/// The server checks every request against [`size`](Self::size) and
/// [`read_only`](Self::read_only) before calling the others, and calls them
/// on blocking threads, from as many connections as clients open: it tells
/// clients they may spread requests over several connections
/// (`NBD_FLAG_CAN_MULTI_CONN`). So [`flush`](Self::flush) must make durable
/// every write that completed before it, whichever connection made it.
pub trait Backend: Send + Sync + 'static {
    /// The export's size in bytes. It doesn't change while it's exported.
    fn size(&self) -> u64;

    fn read_only(&self) -> bool;

    /// Fill `buf` with the bytes at `offset`.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;

    /// Write `buf` at `offset`.
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;

    /// Make every completed write durable.
    fn flush(&self) -> io::Result<()>;

    /// The client no longer needs `len` bytes at `offset`: until written
    /// again, they may read back as anything. Doing nothing is correct.
    fn trim(&self, offset: u64, len: u32) -> io::Result<()>;

    /// Make `len` bytes at `offset` read back as zeroes. With `may_trim`, the
    /// range may be deallocated rather than written.
    fn zero(&self, offset: u64, len: u32, may_trim: bool) -> io::Result<()>;

    /// How `len` bytes at `offset` are allocated, as extents in order from
    /// `offset`. They may stop short of `offset + len`, but must cover at
    /// least its first byte.
    fn extents(&self, offset: u64, len: u32) -> io::Result<Vec<Extent>>;
}

/// A run of bytes that are allocated the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub length: u32,
    pub kind: ExtentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    /// Allocated: may hold anything.
    Data,
    /// Not allocated: reads as zeroes.
    Hole,
}

/// Whether an export takes writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

/// Exports a regular file, holes and all: block status reports the file's
/// holes (`SEEK_HOLE`), and trims and zeroes punch new ones where the
/// filesystem can.
pub struct FileBackend {
    file: File,
    size: u64,
    access: Access,
}

impl FileBackend {
    pub fn open(path: impl AsRef<Path>, access: Access) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(access == Access::ReadWrite)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(Self {
            file,
            size: metadata.len(),
            access,
        })
    }

    fn fallocate(&self, mode: FallocateFlags, offset: u64, len: u32) -> Result<(), Errno> {
        fallocate(
            &self.file,
            mode | FallocateFlags::KEEP_SIZE,
            offset,
            u64::from(len),
        )
    }

    fn write_zeroes(&self, offset: u64, len: u32) -> io::Result<()> {
        const CHUNK: u32 = 1 << 20;
        let zeroes = vec![0; CHUNK.min(len) as usize];
        let end = offset + u64::from(len);
        let mut pos = offset;
        while pos < end {
            let n = (end - pos).min(zeroes.len() as u64) as usize;
            self.file.write_all_at(&zeroes[..n], pos)?;
            pos += n as u64;
        }
        Ok(())
    }
}

impl Backend for FileBackend {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_only(&self) -> bool {
        self.access == Access::ReadOnly
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        self.file.write_all_at(buf, offset)
    }

    fn flush(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn trim(&self, offset: u64, len: u32) -> io::Result<()> {
        match self.fallocate(FallocateFlags::PUNCH_HOLE, offset, len) {
            // Where the filesystem can't punch holes, the data stays.
            Err(e) if e == Errno::OPNOTSUPP => Ok(()),
            result => result.map_err(Into::into),
        }
    }

    fn zero(&self, offset: u64, len: u32, may_trim: bool) -> io::Result<()> {
        if may_trim {
            match self.fallocate(FallocateFlags::PUNCH_HOLE, offset, len) {
                Err(e) if e == Errno::OPNOTSUPP => {}
                result => return result.map_err(Into::into),
            }
        }
        match self.fallocate(FallocateFlags::ZERO_RANGE, offset, len) {
            // Not every filesystem zeroes ranges in place: tmpfs only punches
            // holes, for one.
            Err(e) if e == Errno::OPNOTSUPP => self.write_zeroes(offset, len),
            result => result.map_err(Into::into),
        }
    }

    fn extents(&self, offset: u64, len: u32) -> io::Result<Vec<Extent>> {
        let end = offset + u64::from(len);
        let mut extents = Vec::new();
        let mut pos = offset;
        while pos < end {
            let data = match seek(&self.file, SeekFrom::Data(pos)) {
                Ok(data) => data.min(end),
                // No data from `pos` to the end of the file.
                Err(e) if e == Errno::NXIO => end,
                Err(e) => return Err(e.into()),
            };
            if data > pos {
                extents.push(Extent {
                    length: (data - pos) as u32,
                    kind: ExtentKind::Hole,
                });
                pos = data;
            }
            if pos < end {
                let hole = seek(&self.file, SeekFrom::Hole(pos))?.min(end);
                // A write between the two seeks can leave no data at `pos`
                // after all; the next round sees the hole.
                if hole > pos {
                    extents.push(Extent {
                        length: (hole - pos) as u32,
                        kind: ExtentKind::Data,
                    });
                    pos = hole;
                }
            }
        }
        Ok(extents)
    }
}
