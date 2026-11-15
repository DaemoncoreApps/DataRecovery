#![no_main]

use daemoncore_ntfs_core::{
    exfat::Volume as ExfatVolume, fat32::Volume as Fat32Volume, partition::analyze,
    storage::BlockSource,
};
use libfuzzer_sys::fuzz_target;
use std::io::{self, Cursor};
use std::sync::OnceLock;

const SECTOR_SIZE: usize = 512;
const EXFAT_REGION_SIZE: usize = SECTOR_SIZE * 12;
const IMAGE_SECTORS: usize = 2501;
const GPT_IMAGE_SECTORS: usize = 512;
const GPT_ENTRY_COUNT: usize = 16;
const GPT_ENTRY_SIZE: usize = 128;
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;
const FAT32_SECTORS_PER_FAT: u32 = 512;
const FAT32_CLUSTER_COUNT: u32 = 65_525;
const FAT32_TOTAL_SECTORS: u32 = 32 + 2 * FAT32_SECTORS_PER_FAT + FAT32_CLUSTER_COUNT;
const FAT32_IMAGE_SIZE: u64 = FAT32_TOTAL_SECTORS as u64 * SECTOR_SIZE as u64;
const FAT32_FAT_PREFIX_BYTES: usize = 66 * 4;

struct SliceBlockSource<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceBlockSource<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl BlockSource for SliceBlockSource<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset is too large"))?;
        let end = start
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read range overflows"))?;
        let source = self
            .bytes
            .get(start..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "read exceeds image"))?;
        buffer.copy_from_slice(source);
        Ok(())
    }
}

struct VirtualFat32Image {
    boot: [u8; SECTOR_SIZE],
    fats: [[u8; FAT32_FAT_PREFIX_BYTES]; 2],
    root_directory: [u8; SECTOR_SIZE],
}

impl VirtualFat32Image {
    fn new(data: &[u8]) -> Self {
        let mut boot = [0; SECTOR_SIZE];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        boot[16] = 2;
        boot[32..36].copy_from_slice(&FAT32_TOTAL_SECTORS.to_le_bytes());
        boot[36..40].copy_from_slice(&FAT32_SECTORS_PER_FAT.to_le_bytes());
        boot[40..42].copy_from_slice(&0_u16.to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);

        let mut fat = [0; FAT32_FAT_PREFIX_BYTES];
        fat[..4].copy_from_slice(&0x0fff_fff8_u32.to_le_bytes());
        fat[4..8].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
        fat[8..12].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
        for (index, byte) in data.iter().skip(5).take(fat.len() - 12).enumerate() {
            fat[12 + index] ^= *byte;
        }
        let mut second_fat = fat;
        if let Some(byte) = data.get(1) {
            second_fat[40] ^= *byte;
        }

        let mut root_directory = [0; SECTOR_SIZE];
        root_directory[..11].copy_from_slice(b"FUZZ    TXT");
        root_directory[11] = 0x20;
        root_directory[32..43].copy_from_slice(b"DELETED TXT");
        root_directory[32] = 0xe5;
        root_directory[43] = 0x20;
        root_directory[58..60].copy_from_slice(&10_u16.to_le_bytes());
        root_directory[60..64].copy_from_slice(&512_u32.to_le_bytes());
        if let Some(first) = data.first() {
            root_directory[58..60].copy_from_slice(&(2_u16 + u16::from(*first % 64)).to_le_bytes());
        }
        if data.len() >= 5 {
            let size = u32::from_le_bytes(data[1..5].try_into().unwrap()) % 4097;
            root_directory[60..64].copy_from_slice(&size.to_le_bytes());
        }
        for (index, byte) in data.iter().skip(5).take(SECTOR_SIZE - 64).enumerate() {
            let position = 64 + index;
            root_directory[position] ^= *byte;
        }
        if root_directory[0] == 0 {
            root_directory[0] = b'F';
        }
        if root_directory[32] == 0 {
            root_directory[32] = b'G';
        }

        Self {
            boot,
            fats: [fat, second_fat],
            root_directory,
        }
    }

    fn byte_at(&self, offset: u64) -> u8 {
        if offset < SECTOR_SIZE as u64 {
            return self.boot[offset as usize];
        }
        if (6 * SECTOR_SIZE as u64..7 * SECTOR_SIZE as u64).contains(&offset) {
            return self.boot[(offset - 6 * SECTOR_SIZE as u64) as usize];
        }

        let fat_start = 32 * SECTOR_SIZE as u64;
        let fat_size = u64::from(FAT32_SECTORS_PER_FAT) * SECTOR_SIZE as u64;
        let fat_area_end = fat_start + 2 * fat_size;
        if (fat_start..fat_area_end).contains(&offset) {
            let relative = offset - fat_start;
            let fat_index = (relative / fat_size) as usize;
            let index = (relative % fat_size) as usize;
            return self.fats[fat_index].get(index).copied().unwrap_or(0);
        }

        let root_start = (32 + 2 * FAT32_SECTORS_PER_FAT) as u64 * SECTOR_SIZE as u64;
        if (root_start..root_start + SECTOR_SIZE as u64).contains(&offset) {
            return self.root_directory[(offset - root_start) as usize];
        }
        0
    }
}

impl BlockSource for VirtualFat32Image {
    fn len(&self) -> u64 {
        FAT32_IMAGE_SIZE
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
        offset
            .checked_add(buffer.len() as u64)
            .filter(|end| *end <= FAT32_IMAGE_SIZE)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "outside virtual image"))?;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = self.byte_at(offset + index as u64);
        }
        Ok(())
    }
}

fn fuzz_fat32_tree(data: &[u8]) {
    // Model the minimum legal FAT32 geometry on demand; allocating its 34 MB
    // backing image for every fuzz input would hide parser coverage behind IO.
    let image = VirtualFat32Image::new(data);
    let volume = Fat32Volume::open(&image, 0, image.len())
        .expect("virtual FAT32 fixture must retain valid boot metadata");
    let _ = volume.read_tree(&image);
    if let Ok(entries) = volume.read_tree_including_deleted(&image) {
        for entry in entries.iter().filter(|entry| entry.entry.deleted) {
            let _ = volume.map_deleted_file_contiguous(
                &image,
                entry.entry.first_cluster,
                u64::from(entry.entry.size),
            );
        }
    }
}

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

fn exfat_entry_set_checksum(entries: &[[u8; 32]]) -> u16 {
    let mut checksum = 0u16;
    for (record_index, record) in entries.iter().enumerate() {
        for (byte_index, byte) in record.iter().enumerate() {
            if record_index == 0 && matches!(byte_index, 2 | 3) {
                continue;
            }
            checksum = checksum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
    }
    checksum
}

fn exfat_checksum32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |checksum, byte| {
        checksum.rotate_right(1).wrapping_add(u32::from(*byte))
    })
}

fn exfat_volume_fixture() -> Vec<u8> {
    const SECTOR: usize = 512;
    const IMAGE_SECTORS: usize = 2048;
    const FAT_OFFSET: usize = 24;
    const FAT_SECTORS: usize = 16;
    const HEAP_OFFSET: usize = 40;
    let mut image = vec![0; IMAGE_SECTORS * SECTOR];

    for boot_start in [0, 12 * SECTOR] {
        let region = &mut image[boot_start..boot_start + 12 * SECTOR];
        let boot = &mut region[..SECTOR];
        boot[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        boot[3..11].copy_from_slice(b"EXFAT   ");
        boot[72..80].copy_from_slice(&(IMAGE_SECTORS as u64).to_le_bytes());
        boot[80..84].copy_from_slice(&(FAT_OFFSET as u32).to_le_bytes());
        boot[84..88].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
        boot[88..92].copy_from_slice(&(HEAP_OFFSET as u32).to_le_bytes());
        boot[92..96].copy_from_slice(&((IMAGE_SECTORS - HEAP_OFFSET) as u32).to_le_bytes());
        boot[96..100].copy_from_slice(&2_u32.to_le_bytes());
        boot[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        boot[108] = 9;
        boot[110] = 1;
        boot[112] = 0xff;
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        for sector in 1..=8 {
            let end = (sector + 1) * SECTOR;
            region[end - 4..end].copy_from_slice(&[0, 0, 0x55, 0xaa]);
        }
        update_exfat_checksum(region);
    }

    let fat_start = FAT_OFFSET * SECTOR;
    for cluster in 2..=5 {
        let offset = fat_start + cluster * 4;
        image[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }

    let mut upcase = Vec::with_capacity(250);
    for unit in 0..97_u16 {
        upcase.extend_from_slice(&unit.to_le_bytes());
    }
    for unit in b'A' as u16..=b'Z' as u16 {
        upcase.extend_from_slice(&unit.to_le_bytes());
    }
    upcase.extend_from_slice(&0xffff_u16.to_le_bytes());
    upcase.extend_from_slice(&65_413_u16.to_le_bytes());

    let mut root = [0u8; SECTOR];
    root[0] = 0x81;
    root[20..24].copy_from_slice(&4_u32.to_le_bytes());
    root[24..32].copy_from_slice(&251_u64.to_le_bytes());
    root[32] = 0x82;
    root[36..40].copy_from_slice(&exfat_checksum32(&upcase).to_le_bytes());
    root[52..56].copy_from_slice(&3_u32.to_le_bytes());
    root[56..64].copy_from_slice(&(upcase.len() as u64).to_le_bytes());

    let primary = &mut root[64..96];
    primary[0] = 0x85;
    primary[1] = 2;
    primary[4..6].copy_from_slice(&0x20_u16.to_le_bytes());
    let stream = &mut root[96..128];
    stream[0] = 0xc0;
    stream[1] = 1;
    stream[3] = 8;
    stream[8..16].copy_from_slice(&4_u64.to_le_bytes());
    stream[20..24].copy_from_slice(&5_u32.to_le_bytes());
    stream[24..32].copy_from_slice(&4_u64.to_le_bytes());
    let filename = &mut root[128..160];
    filename[0] = 0xc1;
    for (index, unit) in "ROOT.TXT".encode_utf16().enumerate() {
        filename[2 + index * 2..4 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut name_hash = 0u16;
    for unit in "ROOT.TXT".encode_utf16() {
        for byte in unit.to_le_bytes() {
            name_hash = name_hash.rotate_right(1).wrapping_add(u16::from(byte));
        }
    }
    root[100..102].copy_from_slice(&name_hash.to_le_bytes());
    let entries: Vec<[u8; 32]> = root[64..160]
        .chunks_exact(32)
        .map(|entry| entry.try_into().unwrap())
        .collect();
    root[66..68].copy_from_slice(&exfat_entry_set_checksum(&entries).to_le_bytes());

    let heap = HEAP_OFFSET * SECTOR;
    image[heap..heap + SECTOR].copy_from_slice(&root);
    image[heap + SECTOR..heap + SECTOR + upcase.len()].copy_from_slice(&upcase);
    image[heap + 2 * SECTOR] = 0b0000_1111;
    image[heap + 3 * SECTOR..heap + 3 * SECTOR + 4].copy_from_slice(b"DATA");
    image
}

fn fuzz_exfat_volume(data: &[u8]) {
    static VALID_FIXTURE: OnceLock<Vec<u8>> = OnceLock::new();
    const SECTOR: usize = 512;
    const FAT_START: usize = 24 * SECTOR;
    const HEAP_START: usize = 40 * SECTOR;
    const ROOT_LENGTH: usize = SECTOR;
    const BITMAP_LENGTH: usize = 251;
    const UPCASE_LENGTH: usize = 250;
    let fixture = VALID_FIXTURE.get_or_init(|| {
        let image = exfat_volume_fixture();
        let source = SliceBlockSource::new(&image);
        let volume = ExfatVolume::open(&source, 0, source.len())
            .expect("generated exFAT fuzz fixture must be valid");
        assert_eq!(
            volume
                .read_tree(&source)
                .expect("generated exFAT root directory must be valid")
                .len(),
            1
        );
        image
    });
    let mut image = fixture.clone();
    let mut root_changed = false;
    let mut upcase_changed = false;

    for chunk in data.chunks_exact(4).take(256) {
        let position = usize::from(u16::from_le_bytes([chunk[1], chunk[2]]));
        let mask = chunk[3];
        match chunk[0] % 5 {
            0 => {
                image[HEAP_START + position % ROOT_LENGTH] ^= mask;
                root_changed = true;
            }
            1 => image[FAT_START + position % (16 * SECTOR)] ^= mask,
            2 => image[HEAP_START + 2 * SECTOR + position % BITMAP_LENGTH] ^= mask,
            3 => {
                image[HEAP_START + SECTOR + position % UPCASE_LENGTH] ^= mask;
                upcase_changed = true;
            }
            _ => {
                let boot_offset = position % SECTOR;
                image[boot_offset] ^= mask;
                image[12 * SECTOR + boot_offset] ^= mask;
            }
        }
    }

    if upcase_changed {
        let checksum =
            exfat_checksum32(&image[HEAP_START + SECTOR..HEAP_START + SECTOR + UPCASE_LENGTH]);
        image[HEAP_START + 36..HEAP_START + 40].copy_from_slice(&checksum.to_le_bytes());
    }
    if root_changed && image[HEAP_START + 96] == 0xc0 && image[HEAP_START + 128] == 0xc1 {
        let name_length = usize::from(image[HEAP_START + 99]).min(15);
        let mut name_hash = 0u16;
        for index in 0..name_length {
            let offset = HEAP_START + 130 + index * 2;
            let mut unit = u16::from_le_bytes([image[offset], image[offset + 1]]);
            if (b'a' as u16..=b'z' as u16).contains(&unit) {
                unit -= 0x20;
            }
            for byte in unit.to_le_bytes() {
                name_hash = name_hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        image[HEAP_START + 100..HEAP_START + 102].copy_from_slice(&name_hash.to_le_bytes());
    }
    if root_changed && image[HEAP_START + 64] == 0x85 && image[HEAP_START + 65] <= 2 {
        let count = usize::from(image[HEAP_START + 65]);
        let end = HEAP_START + 64 + (count + 1) * 32;
        if end <= HEAP_START + ROOT_LENGTH {
            let entries: Vec<[u8; 32]> = image[HEAP_START + 64..end]
                .chunks_exact(32)
                .map(|entry| entry.try_into().unwrap())
                .collect();
            let checksum = exfat_entry_set_checksum(&entries);
            image[HEAP_START + 66..HEAP_START + 68].copy_from_slice(&checksum.to_le_bytes());
        }
    }
    for boot_start in [0, 12 * SECTOR] {
        update_exfat_checksum(&mut image[boot_start..boot_start + 12 * SECTOR]);
    }

    let size = image.len() as u64;
    let source = SliceBlockSource::new(&image);
    if let Ok(volume) = ExfatVolume::open(&source, 0, size) {
        let _ = volume.read_tree(&source);
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

    fuzz_fat32_tree(data);
    fuzz_exfat_volume(data);

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
