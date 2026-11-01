#![no_main]

use daemoncore_ntfs_core::partition::analyze;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const SECTOR_SIZE: usize = 512;
const EXFAT_REGION_SIZE: usize = SECTOR_SIZE * 12;
const IMAGE_SECTORS: usize = 2501;
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;

fn exfat_region() -> Vec<u8> {
    let mut region = vec![0; EXFAT_REGION_SIZE];
    let boot = &mut region[..SECTOR_SIZE];
    boot[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    boot[3..11].copy_from_slice(b"EXFAT   ");
    boot[72..80].copy_from_slice(&2048_u64.to_le_bytes());
    boot[80..84].copy_from_slice(&24_u32.to_le_bytes());
    boot[84..88].copy_from_slice(&16_u32.to_le_bytes());
    boot[88..92].copy_from_slice(&56_u32.to_le_bytes());
    boot[92..96].copy_from_slice(&1992_u32.to_le_bytes());
    boot[96..100].copy_from_slice(&2_u32.to_le_bytes());
    boot[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
    boot[108] = 9;
    boot[109] = 0;
    boot[110] = 1;
    boot[112] = 50;
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    for sector_index in 1..=8 {
        let end = (sector_index + 1) * SECTOR_SIZE;
        region[end - 4..end].copy_from_slice(&[0xaa, 0x55, 0, 0]);
    }
    update_exfat_checksum(&mut region);
    region
}

fn update_exfat_checksum(region: &mut [u8]) {
    let mut checksum = 0_u32;
    for (index, byte) in region[..SECTOR_SIZE * 11].iter().enumerate() {
        if matches!(index, 106 | 107 | 112) {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
    }
    for word in region[SECTOR_SIZE * 11..].chunks_mut(4) {
        word.copy_from_slice(&checksum.to_le_bytes());
    }
}

fn partitioned_exfat_image(data: &[u8]) -> Vec<u8> {
    let mut image = vec![0; IMAGE_SECTORS * SECTOR_SIZE];
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    image[446 + 4] = 0x07;
    image[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
    image[446 + 12..446 + 16].copy_from_slice(&2500_u32.to_le_bytes());

    let main_offset = SECTOR_SIZE;
    let backup_offset = main_offset + EXFAT_REGION_SIZE;
    let mut main = exfat_region();
    let mut backup = main.clone();
    for (index, byte) in data.iter().take(4096).enumerate() {
        let field = 64 + index % 48;
        if !matches!(field, 106 | 107 | 112) {
            main[field] ^= byte;
            backup[field] ^= byte;
        }
    }
    update_exfat_checksum(&mut main);
    update_exfat_checksum(&mut backup);
    image[main_offset..main_offset + EXFAT_REGION_SIZE].copy_from_slice(&main);
    image[backup_offset..backup_offset + EXFAT_REGION_SIZE].copy_from_slice(&backup);
    image
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    if data.len() >= SECTOR_SIZE {
        let _ = analyze(&mut Cursor::new(data), data.len() as u64);
    }

    let mut structured = partitioned_exfat_image(data);
    let size = structured.len() as u64;
    let _ = analyze(&mut Cursor::new(&mut structured), size);
});
