pub use daemoncore_ntfs_core::storage::BlockSource;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[repr(C)]
#[derive(Default)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    size_high: u32,
    size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
}

pub struct Image {
    file: Mutex<File>,
    length: u64,
    modified: std::time::SystemTime,
    pub path: PathBuf,
}

impl Image {
    pub fn open(path: &Path) -> io::Result<Self> {
        // Keep the file identity stable and deny normal write/delete handles.
        let file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Select a nonempty regular raw disk image.",
            ));
        }
        Ok(Self {
            file: Mutex::new(file),
            length: metadata.len(),
            // Missing timestamp metadata must not silently weaken the stability check.
            modified: metadata.modified()?,
            path: path.canonicalize()?,
        })
    }
    pub fn verify_unchanged(&self) -> io::Result<()> {
        let file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Evidence handle lock failed"))?;
        let metadata = file.metadata()?;
        if metadata.len() != self.length || metadata.modified()? != self.modified {
            return Err(io::Error::other(
                "Evidence image changed during examination. Reopen a stable working copy.",
            ));
        }
        Ok(())
    }

    // Canonical paths miss hard links; Windows identifies the opened target by
    // its volume serial and file index.
    pub fn file_identity(&self) -> io::Result<(u32, u64)> {
        let file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Evidence handle lock failed"))?;
        let mut information = ByHandleFileInformation::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let file_index =
            (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
        Ok((information.volume_serial_number, file_index))
    }
}

impl BlockSource for Image {
    fn len(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        checked_range(self.length, offset, buffer.len())?;
        // The seek and read share one lock; callers never share a stream cursor.
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("Evidence handle lock failed"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buffer)
    }
}

pub fn checked_range(length: u64, offset: u64, count: usize) -> io::Result<()> {
    if offset
        .checked_add(count as u64)
        .is_none_or(|end| end > length)
    {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Read extends beyond evidence bounds",
        ));
    }
    Ok(())
}

pub struct SourceCursor<'a> {
    source: &'a dyn BlockSource,
    position: u64,
}
impl<'a> SourceCursor<'a> {
    pub fn new(source: &'a dyn BlockSource) -> Self {
        Self {
            source,
            position: 0,
        }
    }
}
impl Read for SourceCursor<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count =
            (self.source.len().saturating_sub(self.position)).min(buffer.len() as u64) as usize;
        self.source
            .read_exact_at(self.position, &mut buffer[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for SourceCursor<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let value = match position {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.source.len() as i128 + n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
        };
        if value < 0 || value > self.source.len() as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek is outside evidence bounds",
            ));
        }
        self.position = value as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
pub struct MemorySource(pub Vec<u8>);
#[cfg(test)]
impl BlockSource for MemorySource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        checked_range(self.len(), offset, buffer.len())?;
        buffer.copy_from_slice(&self.0[offset as usize..offset as usize + buffer.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_cursors_and_bounds() {
        let source = MemorySource(b"0123456789".to_vec());
        let mut a = SourceCursor::new(&source);
        let mut b = SourceCursor::new(&source);
        a.seek(SeekFrom::Start(6)).unwrap();
        b.seek(SeekFrom::Start(1)).unwrap();
        let mut out = [0; 2];
        a.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"67");
        b.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"12");
        assert!(source.read_exact_at(u64::MAX, &mut out).is_err());
        assert!(a.seek(SeekFrom::End(1)).is_err());
    }
}
