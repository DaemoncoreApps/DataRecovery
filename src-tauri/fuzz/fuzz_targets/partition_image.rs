#![no_main]

use daemoncore_ntfs_core::partition::analyze;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const SECTOR_SIZE: usize = 512;
const EXFAT_REGION_SIZE: usize = SECTOR_SIZE * 12;
const IMAGE_SECTORS: usize = 2501;
const GPT_IMAGE_SECTORS: usize = 512;
const GPT_ENTRY_COUNT: usize = 16;
const GPT_ENTRY_SIZE: usize = 128;
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

fn set_gpt_header_crc(header: &mut [u8]) {
    header[16..20].fill(0);
    let crc = crc32fast::hash(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
}

fn write_gpt_header(
    image: &mut [u8],
    current_lba: usize,
    backup_lba: usize,
    entries_lba: usize,
    entries_crc: u32,
) {
    let offset = current_lba * SECTOR_SIZE;
    let header = &mut image[offset..offset + SECTOR_SIZE];
    header[..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    header[12..16].copy_from_slice(&92_u32.to_le_bytes());
    header[24..32].copy_from_slice(&(current_lba as u64).to_le_bytes());
    header[32..40].copy_from_slice(&(backup_lba as u64).to_le_bytes());
    header[40..48].copy_from_slice(&34_u64.to_le_bytes());
    header[48..56].copy_from_slice(&((GPT_IMAGE_SECTORS - 6) as u64).to_le_bytes());
    header[56..72].copy_from_slice(b"DaemonCoreGPT!!!");
    header[72..80].copy_from_slice(&(entries_lba as u64).to_le_bytes());
    header[80..84].copy_from_slice(&(GPT_ENTRY_COUNT as u32).to_le_bytes());
    header[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    set_gpt_header_crc(header);
}

fn partitioned_gpt_image(data: &[u8]) -> Vec<u8> {
    let mut image = vec![0; GPT_IMAGE_SECTORS * SECTOR_SIZE];
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    image[446 + 4] = 0xee;
    image[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
    image[446 + 12..446 + 16].copy_from_slice(&((GPT_IMAGE_SECTORS - 1) as u32).to_le_bytes());

    let entries_bytes = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE;
    let primary_entries_lba = 2;
    let backup_entries_lba = GPT_IMAGE_SECTORS - 1 - entries_bytes / SECTOR_SIZE;
    let primary_entries_offset = primary_entries_lba * SECTOR_SIZE;
    let backup_entries_offset = backup_entries_lba * SECTOR_SIZE;
    let entries = &mut image[primary_entries_offset..primary_entries_offset + entries_bytes];
    let first = &mut entries[..GPT_ENTRY_SIZE];
    first[..16].copy_from_slice(b"FAT32-GPT-TYPE!!");
    first[16..32].copy_from_slice(b"DaemonCoreEntry!");
    first[32..40].copy_from_slice(&40_u64.to_le_bytes());
    first[40..48].copy_from_slice(&300_u64.to_le_bytes());
    first[48..56].copy_from_slice(&0_u64.to_le_bytes());
    for (index, byte) in data.iter().take(56).enumerate() {
        first[index] ^= byte;
    }
    let entries_crc = crc32fast::hash(entries);
    image.copy_within(
        primary_entries_offset..primary_entries_offset + entries_bytes,
        backup_entries_offset,
    );
    write_gpt_header(
        &mut image,
        1,
        GPT_IMAGE_SECTORS - 1,
        primary_entries_lba,
        entries_crc,
    );
    write_gpt_header(
        &mut image,
        GPT_IMAGE_SECTORS - 1,
        1,
        backup_entries_lba,
        entries_crc,
    );
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

    let mut gpt = partitioned_gpt_image(data);
    let size = gpt.len() as u64;
    let report = analyze(&mut Cursor::new(&mut gpt), size)
        .expect("structured GPT fuzz input must retain parseable headers");
    assert_eq!(report.scheme, "GPT");
    assert_eq!(report.primary_gpt_valid, Some(true));
    assert_eq!(report.backup_gpt_valid, Some(true));
});
