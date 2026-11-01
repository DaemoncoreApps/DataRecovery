#![no_main]

use daemoncore_ntfs_core::{ntfs::scan, storage::BlockSource};
use libfuzzer_sys::fuzz_target;
use std::{io, sync::atomic::AtomicBool};

struct Image<'a>(&'a [u8]);

impl BlockSource for Image<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        let start =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let end = start
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let source = self
            .0
            .get(start..end)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buffer.copy_from_slice(source);
        Ok(())
    }
}

const MAX_IMAGE_SIZE: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 || data.len() > MAX_IMAGE_SIZE {
        return;
    }

    let image = Image(data);
    let _ = scan(&image, 0, &AtomicBool::new(false), |_, _, _| {});
});
