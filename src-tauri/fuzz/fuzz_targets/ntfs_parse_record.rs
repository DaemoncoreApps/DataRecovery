#![no_main]

use daemoncore_ntfs_core::ntfs::{parse_record, Boot};
use libfuzzer_sys::fuzz_target;

const RECORD_SIZE: u64 = 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() != RECORD_SIZE as usize {
        return;
    }

    let boot = Boot {
        offset: 0,
        sector_size: 512,
        cluster_size: 512,
        record_size: RECORD_SIZE,
        volume_size: 1 << 40,
        mft_offset: 0,
        serial: "fuzz".into(),
    };
    let _ = parse_record(data, 16, &boot);
});
