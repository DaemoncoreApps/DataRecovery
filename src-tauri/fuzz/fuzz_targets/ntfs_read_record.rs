#![no_main]

use daemoncore_ntfs_core::{
    ntfs::{read_record, Boot, Content, Run, Stream},
    storage::BlockSource,
};
use libfuzzer_sys::fuzz_target;
use std::io;

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

const RECORD_SIZE: u64 = 1024;
const MAX_IMAGE_SIZE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < RECORD_SIZE as usize || data.len() > MAX_IMAGE_SIZE {
        return;
    }

    let image = Image(data);
    let clusters = (data.len() as u64).div_ceil(512);
    let boot = Boot {
        offset: 0,
        sector_size: 512,
        cluster_size: 512,
        record_size: RECORD_SIZE,
        volume_size: (data.len() as u64) & !511,
        mft_offset: 0,
        serial: "fuzz".into(),
    };
    let mft = Stream {
        size: clusters * 512,
        initialized: clusters * 512,
        content: Content::Runs(vec![Run {
            vcn: 0,
            clusters,
            lcn: Some(0),
        }]),
        blocked: None,
    };

    let _ = read_record(&image, &boot, &mft, 0);
});
