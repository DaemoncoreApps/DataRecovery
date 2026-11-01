use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

const ENTRY_LIMIT: u64 = 4096;
const ARRAY_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Partition {
    pub index: usize,
    pub type_id: String,
    pub unique_guid: Option<String>,
    pub start_lba: u64,
    pub end_lba: u64,
    pub size_bytes: u64,
    pub bootable: bool,
    pub filesystem_hint: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PartitionReport {
    pub scheme: String,
    pub sector_size: u32,
    pub primary_gpt_valid: Option<bool>,
    pub backup_gpt_valid: Option<bool>,
    pub partitions: Vec<Partition>,
    pub warnings: Vec<String>,
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Backup VolumeFlags and PercentInUse may be stale, so omit them from copy comparison.
struct ExfatBootMetadata {
    bytes_per_sector: u32,
    sectors_per_cluster: u64,
    partition_offset: u64,
    volume_length: u64,
    fat_offset: u64,
    fat_length: u64,
    cluster_heap_offset: u64,
    cluster_count: u64,
    root_cluster: u32,
    number_of_fats: u8,
    revision: u16,
    volume_serial: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fat32BootMetadata {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fat_count: u8,
    total_sectors: u32,
    sectors_per_fat: u32,
    root_cluster: u32,
    fsinfo_sector: u16,
    backup_boot_sector: u16,
    volume_serial: u32,
}

fn parse_fat32_boot_sector(
    boot: &[u8],
    expected_sector_size: u32,
    partition_sectors: u64,
) -> Option<Fat32BootMetadata> {
    if boot.len() < 512
        || !matches!(boot.get(..3)?, [0xeb, _, 0x90] | [0xe9, _, _])
        || boot.get(510..512)? != [0x55, 0xaa]
    {
        return None;
    }

    let bytes_per_sector = u16::from_le_bytes(boot.get(11..13)?.try_into().ok()?);
    let sectors_per_cluster = *boot.get(13)?;
    let reserved_sectors = u16::from_le_bytes(boot.get(14..16)?.try_into().ok()?);
    let fat_count = *boot.get(16)?;
    let root_entry_count = u16::from_le_bytes(boot.get(17..19)?.try_into().ok()?);
    let total_sectors_16 = u16::from_le_bytes(boot.get(19..21)?.try_into().ok()?);
    let fat_size_16 = u16::from_le_bytes(boot.get(22..24)?.try_into().ok()?);
    let total_sectors = u32_at(boot, 32)?;
    let sectors_per_fat = u32_at(boot, 36)?;
    let extended_flags = u16::from_le_bytes(boot.get(40..42)?.try_into().ok()?);
    let filesystem_version = u16::from_le_bytes(boot.get(42..44)?.try_into().ok()?);
    let root_cluster = u32_at(boot, 44)?;
    let fsinfo_sector = u16::from_le_bytes(boot.get(48..50)?.try_into().ok()?);
    let backup_boot_sector = u16::from_le_bytes(boot.get(50..52)?.try_into().ok()?);
    let volume_serial = u32_at(boot, 67)?;

    if u32::from(bytes_per_sector) != expected_sector_size
        || !(512..=4096).contains(&bytes_per_sector)
        || !bytes_per_sector.is_power_of_two()
        || !sectors_per_cluster.is_power_of_two()
        || sectors_per_cluster > 128
        || reserved_sectors == 0
        || !matches!(fat_count, 1 | 2)
        || root_entry_count != 0
        || total_sectors_16 != 0
        || fat_size_16 != 0
        || total_sectors == 0
        || u64::from(total_sectors) > partition_sectors
        || sectors_per_fat == 0
        || extended_flags & !0x008f != 0
        || (extended_flags & 0x0080 != 0
            && u8::try_from(extended_flags & 0x000f)
                .ok()
                .is_none_or(|active_fat| active_fat >= fat_count))
        || filesystem_version != 0
        || !(2..=0x0fff_fff6).contains(&root_cluster)
        || (fsinfo_sector != u16::MAX && (fsinfo_sector == 0 || fsinfo_sector >= reserved_sectors))
        || !matches!(backup_boot_sector, 0 | 6)
        || (backup_boot_sector == 6
            && (backup_boot_sector >= reserved_sectors || backup_boot_sector == fsinfo_sector))
        || boot.get(52..64)?.iter().any(|byte| *byte != 0)
    {
        return None;
    }

    let fat_area_sectors = u64::from(fat_count).checked_mul(u64::from(sectors_per_fat))?;
    let data_start = u64::from(reserved_sectors).checked_add(fat_area_sectors)?;
    if data_start >= u64::from(total_sectors) {
        return None;
    }
    let data_sectors = u64::from(total_sectors).checked_sub(data_start)?;
    let cluster_count = data_sectors.checked_div(u64::from(sectors_per_cluster))?;
    let fat_capacity_entries = u64::from(sectors_per_fat)
        .checked_mul(u64::from(bytes_per_sector))?
        .checked_div(4)?;
    if !(65_525..=0x0fff_fff5).contains(&cluster_count)
        || u64::from(root_cluster) > cluster_count.checked_add(1)?
        || fat_capacity_entries < cluster_count.checked_add(2)?
    {
        return None;
    }

    Some(Fat32BootMetadata {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        total_sectors,
        sectors_per_fat,
        root_cluster,
        fsinfo_sector,
        backup_boot_sector,
        volume_serial,
    })
}

fn fat32_geometry_hint<R: Read + Seek>(
    r: &mut R,
    volume_offset: u64,
    partition_sectors: u64,
    sector_size: u32,
    image_size: u64,
    primary_boot: &[u8],
) -> Option<String> {
    let primary = parse_fat32_boot_sector(primary_boot, sector_size, partition_sectors)?;
    if primary.backup_boot_sector == 0 {
        return Some(
            "FAT32 main boot geometry validated (backup boot sector not declared; file parser unavailable)"
                .into(),
        );
    }
    let backup_offset = volume_offset
        .checked_add(u64::from(primary.backup_boot_sector).checked_mul(u64::from(sector_size))?)?;
    let backup_boot = read_at(
        r,
        backup_offset,
        usize::try_from(sector_size).ok()?,
        image_size,
    )
    .ok()?;
    let backup = parse_fat32_boot_sector(&backup_boot, sector_size, partition_sectors);
    match backup {
        Some(backup) if backup == primary => Some(
            "FAT32 main and backup boot geometry validated (file parser unavailable)".into(),
        ),
        Some(_) => Some(
            "FAT32 main boot geometry validated; backup boot metadata differs (file parser unavailable)"
                .into(),
        ),
        None => Some(
            "FAT32 main boot geometry validated; backup boot sector invalid (file parser unavailable)"
                .into(),
        ),
    }
}

fn exfat_boot_checksum(region: &[u8], bytes_per_sector: usize) -> Option<u32> {
    if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        return None;
    }
    let checksum_bytes = bytes_per_sector.checked_mul(11)?;
    let checksum_sector = bytes_per_sector.checked_mul(11)?;
    if region.len() != bytes_per_sector.checked_mul(12)? {
        return None;
    }
    // The exFAT specification excludes VolumeFlags and PercentInUse from this checksum.
    let mut checksum = 0_u32;
    for (index, byte) in region[..checksum_bytes].iter().enumerate() {
        if matches!(index, 106 | 107 | 112) {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
    }
    let stored = region.get(checksum_sector..)?;
    if stored
        .chunks(4)
        .any(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]) != checksum)
    {
        return None;
    }
    Some(checksum)
}

fn parse_exfat_boot_region(
    region: &[u8],
    expected_sector_size: u32,
    partition_sectors: u64,
) -> Option<ExfatBootMetadata> {
    let sector_size = usize::try_from(expected_sector_size).ok()?;
    if !(512..=4096).contains(&sector_size)
        || !sector_size.is_power_of_two()
        || region.len() != sector_size.checked_mul(12)?
    {
        return None;
    }
    let boot = region.get(..sector_size)?;
    if boot.get(..3)? != [0xeb, 0x76, 0x90]
        || boot.get(3..11)? != b"EXFAT   "
        || boot.get(11..64)?.iter().any(|byte| *byte != 0)
        || boot.get(510..512)? != [0x55, 0xaa]
        || usize::from(*boot.get(108)?) != sector_size.trailing_zeros() as usize
    {
        return None;
    }
    for sector_index in 1_usize..=8 {
        let end = (sector_index + 1).checked_mul(sector_size)?;
        if region.get(end.checked_sub(4)?..end)? != [0xaa, 0x55, 0, 0] {
            return None;
        }
    }
    exfat_boot_checksum(region, sector_size)?;

    let bytes_shift = *boot.get(108)?;
    let cluster_shift = *boot.get(109)?;
    if !(9..=12).contains(&bytes_shift)
        || cluster_shift > 25_u8.checked_sub(bytes_shift)?
        || boot.get(113..120)?.iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let volume_length = u64_at(boot, 72)?;
    let fat_offset = u64::from(u32_at(boot, 80)?);
    let fat_length = u64::from(u32_at(boot, 84)?);
    let cluster_heap_offset = u64::from(u32_at(boot, 88)?);
    let cluster_count = u64::from(u32_at(boot, 92)?);
    let root_cluster = u32_at(boot, 96)?;
    let revision = u16::from_le_bytes(boot.get(104..106)?.try_into().ok()?);
    let volume_flags = u16::from_le_bytes(boot.get(106..108)?.try_into().ok()?);
    let number_of_fats = *boot.get(110)?;
    let percent_in_use = *boot.get(112)?;
    let bytes_per_sector = 1_u32.checked_shl(u32::from(bytes_shift))?;
    let sectors_per_cluster = 1_u64.checked_shl(u32::from(cluster_shift))?;
    let volume_minimum_sectors = (1_u64 << 20) / u64::from(bytes_per_sector);
    let expected_cluster_count = volume_length
        .checked_sub(cluster_heap_offset)?
        .checked_div(sectors_per_cluster)?
        .min(u64::from(u32::MAX) - 10);
    let required_fat_bytes = cluster_count.checked_add(2)?.checked_mul(4)?;
    let minimum_fat_sectors = required_fat_bytes
        .checked_add(u64::from(bytes_per_sector) - 1)?
        .checked_div(u64::from(bytes_per_sector))?;
    let fats_end = fat_offset.checked_add(fat_length.checked_mul(u64::from(number_of_fats))?)?;
    let cluster_heap_end =
        cluster_heap_offset.checked_add(cluster_count.checked_mul(sectors_per_cluster)?)?;
    let major_revision = (revision >> 8) as u8;
    let minor_revision = revision as u8;

    if major_revision != 1
        || minor_revision > 99
        || !matches!(number_of_fats, 1 | 2)
        || (number_of_fats == 1 && volume_flags & 1 != 0)
        || volume_flags & 0xfff0 != 0
        || !(percent_in_use <= 100 || percent_in_use == 0xff)
        || volume_length < volume_minimum_sectors
        || volume_length > partition_sectors
        || fat_offset < 24
        || fat_length == 0
        || fat_length < minimum_fat_sectors
        || fats_end > cluster_heap_offset
        || cluster_heap_offset > u64::from(u32::MAX)
        || cluster_count != expected_cluster_count
        || !(2..=cluster_count.checked_add(1)?).contains(&u64::from(root_cluster))
        || cluster_heap_end > volume_length
    {
        return None;
    }

    Some(ExfatBootMetadata {
        bytes_per_sector,
        sectors_per_cluster,
        partition_offset: u64_at(boot, 64)?,
        volume_length,
        fat_offset,
        fat_length,
        cluster_heap_offset,
        cluster_count,
        root_cluster,
        number_of_fats,
        revision,
        volume_serial: u32_at(boot, 100)?,
    })
}

fn exfat_geometry_hint<R: Read + Seek>(
    r: &mut R,
    volume_offset: u64,
    partition_sectors: u64,
    sector_size: u32,
    image_size: u64,
) -> Option<String> {
    let sector_size_usize = usize::try_from(sector_size).ok()?;
    if !(512..=4096).contains(&sector_size_usize) || !sector_size_usize.is_power_of_two() {
        return None;
    }
    let boot_region_length = sector_size_usize.checked_mul(12)?;
    let boot_region_sectors = 12_u64;
    if partition_sectors < boot_region_sectors.checked_mul(2)? {
        return None;
    }
    let main_region = read_at(r, volume_offset, boot_region_length, image_size).ok()?;
    let backup_offset =
        volume_offset.checked_add(boot_region_sectors.checked_mul(u64::from(sector_size))?)?;
    let backup_region = read_at(r, backup_offset, boot_region_length, image_size).ok()?;
    let primary = parse_exfat_boot_region(&main_region, sector_size, partition_sectors);
    let backup = parse_exfat_boot_region(&backup_region, sector_size, partition_sectors);

    match (primary, backup) {
        (Some(primary), Some(backup)) if primary == backup => Some(
            "exFAT boot regions validated (main and backup checksums and geometry; directory parser unavailable)".into(),
        ),
        (Some(_), Some(_)) => Some(
            "exFAT main boot region validated; backup boot metadata differs (directory parser unavailable)".into(),
        ),
        (Some(_), None) => Some(
            "exFAT main boot region validated; backup boot region invalid (directory parser unavailable)".into(),
        ),
        (None, Some(_)) => Some(
            "exFAT backup boot region validated; main boot region invalid (directory parser unavailable)".into(),
        ),
        (None, None) => None,
    }
}

fn read_at<R: Read + Seek>(
    r: &mut R,
    offset: u64,
    length: usize,
    size: u64,
) -> Result<Vec<u8>, String> {
    let end = offset
        .checked_add(length as u64)
        .ok_or("Read offset overflow")?;
    if end > size {
        return Err("Partition metadata extends beyond the image".into());
    }
    r.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut bytes = vec![0; length];
    r.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn guid(bytes: &[u8]) -> String {
    let a = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let b = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let c = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    format!(
        "{a:08x}-{b:04x}-{c:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn filesystem_hint<R: Read + Seek>(
    r: &mut R,
    start_lba: u64,
    partition_sectors: u64,
    sector_size: u32,
    image_size: u64,
) -> Option<String> {
    let offset = start_lba.checked_mul(sector_size as u64)?;
    let b = read_at(r, offset, (sector_size as usize).min(4096), image_size).ok()?;
    if b.get(3..11) == Some(b"EXFAT   ") {
        return exfat_geometry_hint(r, offset, partition_sectors, sector_size, image_size);
    }
    if b.get(510..512) != Some(&[0x55, 0xaa]) {
        return None;
    }
    let bps = u16::from_le_bytes(b.get(11..13)?.try_into().ok()?) as u32;
    if bps != sector_size {
        return None;
    }
    let spc = *b.get(13)?;
    if !spc.is_power_of_two() || spc > 128 {
        return None;
    }
    if b.get(3..11) == Some(b"NTFS    ") {
        let total = u64_at(&b, 40)?;
        if total > 0 && total <= partition_sectors {
            return Some("NTFS boot signature (basic geometry checked; parser unavailable)".into());
        }
    } else {
        return fat32_geometry_hint(r, offset, partition_sectors, sector_size, image_size, &b);
    }
    None
}

fn parse_gpt_header(bytes: &[u8], sector_size: u32) -> Result<GptHeader, String> {
    if bytes.get(..8) != Some(b"EFI PART") {
        return Err("GPT signature is missing".into());
    }
    if u32_at(bytes, 8) != Some(0x0001_0000)
        || u32_at(bytes, 20) != Some(0)
        || bytes
            .get(56..72)
            .is_none_or(|guid| guid.iter().all(|byte| *byte == 0))
    {
        return Err("GPT header revision, reserved field, or disk GUID is invalid".into());
    }
    let header_size = u32_at(bytes, 12).ok_or("GPT header is truncated")? as usize;
    if !(92..=sector_size as usize).contains(&header_size) {
        return Err("GPT header size is invalid".into());
    }
    let expected_crc = u32_at(bytes, 16).ok_or("GPT header CRC is missing")?;
    let mut checked = bytes[..header_size].to_vec();
    checked[16..20].fill(0);
    if crc32fast::hash(&checked) != expected_crc {
        return Err("GPT header CRC does not match".into());
    }
    let entry_size = u32_at(bytes, 84).ok_or("GPT entry size is missing")?;
    let entry_count = u32_at(bytes, 80).ok_or("GPT entry count is missing")?;
    if entry_count == 0
        || !(128..=1024).contains(&entry_size)
        || entry_size % 128 != 0
        || !(entry_size / 128).is_power_of_two()
        || entry_count as u64 > ENTRY_LIMIT
    {
        return Err("GPT partition entry dimensions exceed safe limits".into());
    }
    let array_len = (entry_size as u64)
        .checked_mul(entry_count as u64)
        .ok_or("GPT entry array size overflow")?;
    if array_len > ARRAY_LIMIT {
        return Err("GPT entry array is larger than the 4 MiB safety limit".into());
    }
    Ok(GptHeader {
        current_lba: u64_at(bytes, 24).ok_or("GPT current LBA is missing")?,
        backup_lba: u64_at(bytes, 32).ok_or("GPT backup LBA is missing")?,
        first_usable_lba: u64_at(bytes, 40).ok_or("GPT first usable LBA is missing")?,
        last_usable_lba: u64_at(bytes, 48).ok_or("GPT last usable LBA is missing")?,
        entries_lba: u64_at(bytes, 72).ok_or("GPT entries LBA is missing")?,
        entry_count,
        entry_size,
        entries_crc: u32_at(bytes, 88).ok_or("GPT entries CRC is missing")?,
    })
}

fn gpt_header_layout_valid(
    header: &GptHeader,
    observed_lba: u64,
    last_lba: u64,
    sector_size: u32,
) -> bool {
    let backup_reference_valid = if observed_lba == 1 {
        header.backup_lba > 1 && header.backup_lba != observed_lba
    } else {
        header.backup_lba == 1
    };
    let Some(entries_length) =
        u64::from(header.entry_count).checked_mul(u64::from(header.entry_size))
    else {
        return false;
    };
    let Some(entries_start) = header.entries_lba.checked_mul(u64::from(sector_size)) else {
        return false;
    };
    let Some(entries_end) = entries_start.checked_add(entries_length) else {
        return false;
    };
    let Some(image_end) = last_lba
        .checked_add(1)
        .and_then(|sectors| sectors.checked_mul(u64::from(sector_size)))
    else {
        return false;
    };
    if entries_length == 0 || entries_end == 0 {
        return false;
    }
    let entries_start_lba = entries_start / u64::from(sector_size);
    let entries_end_lba = (entries_end - 1) / u64::from(sector_size);
    let overlaps_usable =
        entries_start_lba <= header.last_usable_lba && entries_end_lba >= header.first_usable_lba;
    let overlaps_header = (entries_start_lba..=entries_end_lba).contains(&header.current_lba)
        || (entries_start_lba..=entries_end_lba).contains(&header.backup_lba);
    let entries_on_expected_side = if observed_lba == 1 {
        entries_start_lba > header.current_lba && entries_end_lba < header.first_usable_lba
    } else {
        entries_start_lba > header.last_usable_lba && entries_end_lba < header.current_lba
    };

    header.current_lba == observed_lba
        && backup_reference_valid
        && header.first_usable_lba >= 2
        && header.first_usable_lba <= header.last_usable_lba
        && header.entries_lba > 1
        && entries_end <= image_end
        && !overlaps_usable
        && !overlaps_header
        && entries_on_expected_side
}

struct GptHeader {
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    entries_lba: u64,
    entry_count: u32,
    entry_size: u32,
    entries_crc: u32,
}

fn parse_gpt<R: Read + Seek>(
    r: &mut R,
    image_size: u64,
    sector_size: u32,
) -> Option<PartitionReport> {
    let sector = sector_size as u64;
    if image_size < sector * 2 || !image_size.is_multiple_of(sector) {
        return None;
    }
    let last_lba = image_size / sector - 1;
    let primary_bytes = read_at(r, sector, sector_size as usize, image_size).ok()?;
    let primary = parse_gpt_header(&primary_bytes, sector_size)
        .ok()
        .filter(|header| gpt_header_layout_valid(header, 1, last_lba, sector_size));
    let backup_bytes = read_at(r, last_lba * sector, sector_size as usize, image_size).ok()?;
    let backup = parse_gpt_header(&backup_bytes, sector_size)
        .ok()
        .filter(|header| gpt_header_layout_valid(header, last_lba, last_lba, sector_size));
    if primary.is_none() && backup.is_none() {
        return None;
    }

    let read_entries = |r: &mut R, header: &GptHeader| {
        let length = header.entry_count as usize * header.entry_size as usize;
        let offset = header.entries_lba.checked_mul(sector)?;
        let entries = read_at(r, offset, length, image_size).ok()?;
        (crc32fast::hash(&entries) == header.entries_crc).then_some(entries)
    };
    let primary_entries = primary.as_ref().and_then(|h| read_entries(r, h));
    let backup_entries = backup.as_ref().and_then(|h| read_entries(r, h));
    let mut warnings = Vec::new();
    let primary_valid = primary.is_some() && primary_entries.is_some();
    let backup_valid = backup.is_some() && backup_entries.is_some();
    if primary.is_none() {
        warnings
            .push("Primary GPT header is missing or invalid; inspected the backup header.".into());
    } else if primary_entries.is_none() {
        warnings
            .push("Primary GPT partition entry array is missing or its CRC does not match.".into());
    }
    if backup.is_none() {
        warnings.push("Backup GPT header is missing or invalid.".into());
    } else if backup_entries.is_none() {
        warnings
            .push("Backup GPT partition entry array is missing or its CRC does not match.".into());
    }
    if let (Some(p), Some(b)) = (&primary, &backup) {
        if p.current_lba != 1 || b.current_lba != last_lba {
            warnings.push("GPT header is not at its expected primary or backup location.".into());
        }
        if p.backup_lba != b.current_lba || b.backup_lba != p.current_lba {
            warnings.push("Primary and backup GPT headers disagree about their locations.".into());
        }
    }
    if let (Some(p), Some(b)) = (&primary_entries, &backup_entries) {
        if p != b {
            warnings.push("Primary and backup GPT partition entry arrays differ.".into());
        }
    }

    let (selected, entries) = if let (Some(h), Some(e)) = (primary.as_ref(), primary_entries) {
        (h, e)
    } else if let (Some(h), Some(e)) = (backup.as_ref(), backup_entries) {
        (h, e)
    } else {
        let empty = Vec::new();
        return Some(PartitionReport {
            scheme: "GPT".into(),
            sector_size,
            primary_gpt_valid: Some(primary_valid),
            backup_gpt_valid: Some(backup_valid),
            partitions: empty,
            warnings,
        });
    };
    let mut partitions = Vec::new();
    let mut unique_guids = HashMap::new();
    {
        for i in 0..selected.entry_count as usize {
            let at = i * selected.entry_size as usize;
            let item = &entries[at..at + selected.entry_size as usize];
            if item[..16].iter().all(|v| *v == 0) {
                continue;
            }
            let unique_guid: [u8; 16] = item[16..32].try_into().ok()?;
            if unique_guid.iter().all(|byte| *byte == 0) {
                warnings.push(format!(
                    "GPT entry {} has a zero unique partition GUID.",
                    i + 1
                ));
            } else if let Some(previous) = unique_guids.insert(unique_guid, i + 1) {
                warnings.push(format!(
                    "GPT entries {previous} and {} share a unique partition GUID.",
                    i + 1
                ));
            }
            let start = u64_at(item, 32)?;
            let end = u64_at(item, 40)?;
            if start > end
                || start < selected.first_usable_lba
                || end > selected.last_usable_lba
                || end > last_lba
            {
                warnings.push(format!(
                    "GPT entry {} has invalid or out-of-image bounds.",
                    i + 1
                ));
                continue;
            }
            let size_bytes = (end - start + 1).checked_mul(sector)?;
            let partition_sectors = end - start + 1;
            let fs_hint = filesystem_hint(r, start, partition_sectors, sector_size, image_size);
            partitions.push(Partition {
                index: i + 1,
                type_id: guid(&item[..16]),
                unique_guid: Some(guid(&unique_guid)),
                start_lba: start,
                end_lba: end,
                size_bytes,
                bootable: false,
                filesystem_hint: fs_hint,
            });
        }
        find_overlaps(&partitions, &mut warnings);
    }
    Some(PartitionReport {
        scheme: "GPT".into(),
        sector_size,
        primary_gpt_valid: Some(primary_valid),
        backup_gpt_valid: Some(backup_valid),
        partitions,
        warnings,
    })
}

fn find_overlaps(partitions: &[Partition], warnings: &mut Vec<String>) {
    let mut sorted = partitions.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|p| p.start_lba);
    for pair in sorted.windows(2) {
        if pair[1].start_lba <= pair[0].end_lba {
            warnings.push(format!(
                "Partitions {} and {} overlap.",
                pair[0].index, pair[1].index
            ));
        }
    }
}

fn parse_mbr<R: Read + Seek>(r: &mut R, image_size: u64) -> Result<PartitionReport, String> {
    let sector = read_at(r, 0, 512, image_size)?;
    if sector[510..512] != [0x55, 0xaa] {
        return Err("No valid MBR or GPT signature was found.".into());
    }
    let mut partitions = Vec::new();
    let mut warnings = Vec::new();
    let mut extended = Vec::new();
    for i in 0..4 {
        let at = 446 + i * 16;
        let entry = &sector[at..at + 16];
        let kind = entry[4];
        let start = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let count = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as u64;
        if kind == 0 && count == 0 {
            continue;
        }
        if kind == 0 || count == 0 {
            warnings.push(format!("MBR entry {} is partially populated.", i + 1));
            continue;
        }
        if !matches!(entry[0], 0x00 | 0x80) {
            warnings.push(format!("MBR entry {} has an invalid status byte.", i + 1));
            continue;
        }
        let end = match start.checked_add(count - 1) {
            Some(v) => v,
            None => {
                warnings.push(format!("MBR entry {} has overflowing bounds.", i + 1));
                continue;
            }
        };
        if end
            .checked_add(1)
            .and_then(|v| v.checked_mul(512))
            .is_none_or(|v| v > image_size)
        {
            warnings.push(format!("MBR entry {} extends beyond the image.", i + 1));
            continue;
        }
        if matches!(kind, 0x05 | 0x0f | 0x85) {
            extended.push((i + 1, start, count));
            partitions.push(Partition {
                index: i + 1,
                type_id: format!("MBR extended container 0x{kind:02x}"),
                unique_guid: None,
                start_lba: start,
                end_lba: end,
                size_bytes: count * 512,
                bootable: entry[0] == 0x80,
                filesystem_hint: None,
            });
            continue;
        }
        let fs_hint = filesystem_hint(r, start, count, 512, image_size);
        partitions.push(Partition {
            index: i + 1,
            type_id: format!("MBR 0x{kind:02x}"),
            unique_guid: None,
            start_lba: start,
            end_lba: end,
            size_bytes: count * 512,
            bootable: entry[0] == 0x80,
            filesystem_hint: fs_hint,
        });
    }
    find_overlaps(&partitions, &mut warnings);
    let mut logical_index = 5;
    let mut logical_partitions = Vec::new();
    for (container_index, base, length) in extended {
        let container_end = match base.checked_add(length) {
            Some(v) => v,
            None => {
                warnings.push(format!(
                    "Extended MBR container {container_index} has overflowing bounds."
                ));
                continue;
            }
        };
        let mut ebr_lba = base;
        let mut visited = std::collections::HashSet::new();
        for _ in 0..128 {
            if !visited.insert(ebr_lba) {
                warnings.push(format!(
                    "Extended MBR container {container_index} contains an EBR cycle."
                ));
                break;
            }
            let ebr_offset = match ebr_lba.checked_mul(512) {
                Some(v) if v < image_size => v,
                _ => {
                    warnings.push(format!(
                        "Logical partition table at LBA {ebr_lba} is outside the image."
                    ));
                    break;
                }
            };
            let ebr = match read_at(r, ebr_offset, 512, image_size) {
                Ok(v) if v[510..512] == [0x55, 0xaa] => v,
                _ => {
                    warnings.push(format!(
                        "Logical partition table at LBA {ebr_lba} is missing or invalid."
                    ));
                    break;
                }
            };
            let logical = &ebr[446..462];
            let logical_kind = logical[4];
            let relative_start = u32::from_le_bytes(logical[8..12].try_into().unwrap()) as u64;
            let count = u32::from_le_bytes(logical[12..16].try_into().unwrap()) as u64;
            if logical_kind != 0 && count != 0 {
                let start = match ebr_lba.checked_add(relative_start) {
                    Some(v) => v,
                    None => {
                        warnings.push(format!(
                            "Logical partition {logical_index} has overflowing bounds."
                        ));
                        break;
                    }
                };
                let end = match start.checked_add(count - 1) {
                    Some(v)
                        if v < container_end
                            && v.checked_add(1)
                                .and_then(|n| n.checked_mul(512))
                                .is_some_and(|n| n <= image_size) =>
                    {
                        v
                    }
                    _ => {
                        warnings.push(format!("Logical partition {logical_index} extends beyond its container or image."));
                        break;
                    }
                };
                let fs_hint = filesystem_hint(r, start, count, 512, image_size);
                let logical_partition = Partition {
                    index: logical_index,
                    type_id: format!("MBR 0x{logical_kind:02x}"),
                    unique_guid: None,
                    start_lba: start,
                    end_lba: end,
                    size_bytes: count * 512,
                    bootable: logical[0] == 0x80,
                    filesystem_hint: fs_hint,
                };
                logical_partitions.push(logical_partition.clone());
                partitions.push(logical_partition);
                logical_index += 1;
            }
            let link = &ebr[462..478];
            let link_kind = link[4];
            let next_relative = u32::from_le_bytes(link[8..12].try_into().unwrap()) as u64;
            if !matches!(link_kind, 0x05 | 0x0f | 0x85) {
                break;
            }
            ebr_lba = match base.checked_add(next_relative) {
                Some(v) if v >= base && v < container_end => v,
                _ => {
                    warnings.push(format!(
                        "Extended partition link in container {container_index} is out of bounds."
                    ));
                    break;
                }
            };
        }
        if visited.len() == 128 && !visited.contains(&ebr_lba) {
            warnings.push(format!(
                "Extended MBR container {container_index} exceeded the 128-entry scan limit."
            ));
        }
    }
    find_overlaps(&logical_partitions, &mut warnings);
    Ok(PartitionReport {
        scheme: "MBR".into(),
        sector_size: 512,
        primary_gpt_valid: None,
        backup_gpt_valid: None,
        partitions,
        warnings,
    })
}

pub fn analyze<R: Read + Seek>(r: &mut R, image_size: u64) -> Result<PartitionReport, String> {
    if image_size < 512 {
        return Err("Image is too small to contain partition metadata.".into());
    }
    for sector_size in [512_u32, 4096] {
        if let Some(report) = parse_gpt(r, image_size, sector_size) {
            return Ok(report);
        }
    }
    let mbr = read_at(r, 0, 512, image_size)?;
    if mbr[510..512] == [0x55, 0xaa] && (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xee) {
        return Ok(PartitionReport {
            scheme: "GPT (headers damaged)".into(),
            sector_size: 512,
            primary_gpt_valid: Some(false),
            backup_gpt_valid: Some(false),
            partitions: Vec::new(),
            warnings: vec!["A protective MBR was found, but neither GPT header passed CRC and structure validation. No GPT partitions are reported.".into()],
        });
    }
    parse_mbr(r, image_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn write_exfat_boot_checksum(region: &mut [u8], sector_size: usize) {
        let mut checksum = 0_u32;
        for (index, byte) in region[..sector_size * 11].iter().enumerate() {
            if matches!(index, 106 | 107 | 112) {
                continue;
            }
            checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
        }
        let checksum_sector = &mut region[sector_size * 11..sector_size * 12];
        for word in checksum_sector.chunks_mut(4) {
            word.copy_from_slice(&checksum.to_le_bytes());
        }
    }

    fn exfat_boot_region(sector_size: usize) -> Vec<u8> {
        let mut region = vec![0; sector_size * 12];
        let boot = &mut region[..sector_size];
        boot[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        boot[3..11].copy_from_slice(b"EXFAT   ");
        boot[72..80].copy_from_slice(&2048_u64.to_le_bytes());
        boot[80..84].copy_from_slice(&24_u32.to_le_bytes());
        boot[84..88].copy_from_slice(&16_u32.to_le_bytes());
        boot[88..92].copy_from_slice(&56_u32.to_le_bytes());
        boot[92..96].copy_from_slice(&1992_u32.to_le_bytes());
        boot[96..100].copy_from_slice(&2_u32.to_le_bytes());
        boot[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        boot[108] = sector_size.trailing_zeros() as u8;
        boot[109] = 0;
        boot[110] = 1;
        boot[112] = 50;
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        for sector_index in 1..=8 {
            let end = (sector_index + 1) * sector_size;
            region[end - 4..end].copy_from_slice(&[0xaa, 0x55, 0, 0]);
        }
        write_exfat_boot_checksum(&mut region, sector_size);
        region
    }

    fn mbr_with_exfat(main_region: &[u8], backup_region: &[u8]) -> Vec<u8> {
        let sector_size = 512;
        let mut image = vec![0; 2501 * sector_size];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[446 + 4] = 0x07;
        image[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[446 + 12..446 + 16].copy_from_slice(&2500_u32.to_le_bytes());
        image[sector_size..sector_size + main_region.len()].copy_from_slice(main_region);
        let backup_start = sector_size + 12 * sector_size;
        image[backup_start..backup_start + backup_region.len()].copy_from_slice(backup_region);
        image
    }

    fn fat32_boot_sector() -> Vec<u8> {
        let mut boot = vec![0; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&66_581_u32.to_le_bytes());
        boot[36..40].copy_from_slice(&512_u32.to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        boot
    }

    fn mbr_with_fat32(boot: &[u8], backup_boot: &[u8]) -> Vec<u8> {
        let sector_size = 512_usize;
        let total_sectors = 66_581_usize;
        let mut image = vec![0; (total_sectors + 1) * sector_size];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[446 + 4] = 0x0b;
        image[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[446 + 12..446 + 16].copy_from_slice(&(total_sectors as u32).to_le_bytes());
        image[sector_size..sector_size + boot.len()].copy_from_slice(boot);
        let backup_start = sector_size + 6 * sector_size;
        image[backup_start..backup_start + backup_boot.len()].copy_from_slice(backup_boot);
        image
    }

    #[test]
    fn validates_fat32_primary_and_backup_boot_geometry() {
        let boot = fat32_boot_sector();
        let metadata = parse_fat32_boot_sector(&boot, 512, 66_581).unwrap();
        assert_eq!(metadata.bytes_per_sector, 512);
        assert_eq!(metadata.sectors_per_cluster, 1);
        assert_eq!(metadata.reserved_sectors, 32);
        assert_eq!(metadata.fat_count, 2);
        assert_eq!(metadata.total_sectors, 66_581);
        assert_eq!(metadata.sectors_per_fat, 512);
        assert_eq!(metadata.root_cluster, 2);
        assert_eq!(metadata.fsinfo_sector, 1);
        assert_eq!(metadata.backup_boot_sector, 6);
        assert_eq!(metadata.volume_serial, 0x1234_5678);

        let image = mbr_with_fat32(&boot, &boot);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("main and backup boot geometry validated"));
    }

    #[test]
    fn reports_invalid_fat32_backup_without_trusting_it() {
        let boot = fat32_boot_sector();
        let mut backup = boot.clone();
        backup[510] ^= 1;
        let image = mbr_with_fat32(&boot, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("backup boot sector invalid"));
    }

    #[test]
    fn reports_when_valid_fat32_boot_copies_have_different_metadata() {
        let primary = fat32_boot_sector();
        let mut backup = fat32_boot_sector();
        backup[67..71].copy_from_slice(&0x8765_4321_u32.to_le_bytes());
        let image = mbr_with_fat32(&primary, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("backup boot metadata differs"));
    }

    #[test]
    fn recognizes_fat32_geometry_without_the_informational_type_label() {
        let mut primary = fat32_boot_sector();
        let mut backup = fat32_boot_sector();
        primary[82..90].copy_from_slice(b"NO NAME ");
        backup[82..90].copy_from_slice(b"NO NAME ");
        let image = mbr_with_fat32(&primary, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("main and backup boot geometry validated"));
    }

    #[test]
    fn accepts_fat32_without_a_declared_backup_or_fsinfo_sector() {
        let mut boot = fat32_boot_sector();
        boot[48..50].copy_from_slice(&u16::MAX.to_le_bytes());
        boot[50..52].copy_from_slice(&0_u16.to_le_bytes());
        let image = mbr_with_fat32(&boot, &[]);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("backup boot sector not declared"));
    }

    #[test]
    fn rejects_fat32_boot_geometry_with_inconsistent_bounds() {
        let valid = fat32_boot_sector();
        assert!(parse_fat32_boot_sector(&valid, 512, 66_581).is_some());

        let mut uninformative_label = valid.clone();
        uninformative_label[82..90].copy_from_slice(b"NO NAME ");
        assert!(parse_fat32_boot_sector(&uninformative_label, 512, 66_581).is_some());

        let mut undersized_volume = valid.clone();
        undersized_volume[32..36].copy_from_slice(&66_580_u32.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&undersized_volume, 512, 66_581),
            None
        );

        let mut undersized_fat = valid.clone();
        undersized_fat[36..40].copy_from_slice(&511_u32.to_le_bytes());
        assert_eq!(parse_fat32_boot_sector(&undersized_fat, 512, 66_581), None);

        let mut invalid_root = valid.clone();
        invalid_root[44..48].copy_from_slice(&65_527_u32.to_le_bytes());
        assert_eq!(parse_fat32_boot_sector(&invalid_root, 512, 66_581), None);

        let mut invalid_backup = valid;
        invalid_backup[50..52].copy_from_slice(&32_u16.to_le_bytes());
        assert_eq!(parse_fat32_boot_sector(&invalid_backup, 512, 66_581), None);

        let mut backup_outside_reserved = fat32_boot_sector();
        backup_outside_reserved[14..16].copy_from_slice(&6_u16.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&backup_outside_reserved, 512, 66_581),
            None
        );

        let mut fsinfo_overlaps_backup = fat32_boot_sector();
        fsinfo_overlaps_backup[48..50].copy_from_slice(&6_u16.to_le_bytes());
        assert_eq!(
            parse_fat32_boot_sector(&fsinfo_overlaps_backup, 512, 66_581),
            None
        );
    }

    #[test]
    fn validates_exfat_main_and_backup_boot_regions() {
        let region = exfat_boot_region(512);
        assert_eq!(exfat_boot_checksum(&region, 512), Some(0x1197_4f12));
        let image = mbr_with_exfat(&region, &region);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        let hint = report.partitions[0].filesystem_hint.as_deref().unwrap();
        assert!(hint.contains("main and backup checksums and geometry"));
        assert!(hint.contains("directory parser unavailable"));
    }

    #[test]
    fn accepts_exfat_backup_when_main_boot_checksum_is_invalid() {
        let mut main = exfat_boot_region(512);
        main[11 * 512] ^= 1;
        let backup = exfat_boot_region(512);
        let image = mbr_with_exfat(&main, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        let hint = report.partitions[0].filesystem_hint.as_deref().unwrap();
        assert!(hint.contains("backup boot region validated"));
        assert!(hint.contains("main boot region invalid"));
    }

    #[test]
    fn reports_when_valid_exfat_boot_metadata_copies_disagree() {
        let main = exfat_boot_region(512);
        let mut backup = exfat_boot_region(512);
        backup[96..100].copy_from_slice(&3_u32.to_le_bytes());
        write_exfat_boot_checksum(&mut backup, 512);
        let image = mbr_with_exfat(&main, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        let hint = report.partitions[0].filesystem_hint.as_deref().unwrap();
        assert!(hint.contains("backup boot metadata differs"));
    }

    #[test]
    fn allows_exfat_boot_fields_excluded_from_checksum_to_differ() {
        let main = exfat_boot_region(512);
        let mut backup = exfat_boot_region(512);
        backup[106..108].copy_from_slice(&2_u16.to_le_bytes());
        backup[112] = 0xff;
        let image = mbr_with_exfat(&main, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .contains("main and backup checksums and geometry"));
    }

    #[test]
    fn validates_exfat_boot_regions_with_4k_sectors() {
        let region = exfat_boot_region(4096);
        let parsed = parse_exfat_boot_region(&region, 4096, 2500).unwrap();
        assert_eq!(parsed.bytes_per_sector, 4096);
        assert_eq!(parsed.sectors_per_cluster, 1);
        assert_eq!(parsed.partition_offset, 0);
        assert_eq!(parsed.volume_length, 2048);
        assert_eq!(parsed.fat_offset, 24);
        assert_eq!(parsed.fat_length, 16);
        assert_eq!(parsed.cluster_heap_offset, 56);
        assert_eq!(parsed.cluster_count, 1992);
        assert_eq!(parsed.root_cluster, 2);
        assert_eq!(parsed.number_of_fats, 1);
        assert_eq!(parsed.revision, 0x0100);
        assert_eq!(parsed.volume_serial, 0);
        assert_eq!(exfat_boot_checksum(&[], 0), None);
    }

    #[test]
    fn retains_a_valid_exfat_primary_when_backup_checksum_fails() {
        let main = exfat_boot_region(512);
        let mut backup = exfat_boot_region(512);
        backup[11 * 512] ^= 1;
        let image = mbr_with_exfat(&main, &backup);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        let hint = report.partitions[0].filesystem_hint.as_deref().unwrap();
        assert!(hint.contains("main boot region validated"));
        assert!(hint.contains("backup boot region invalid"));
    }

    #[test]
    fn rejects_exfat_regions_with_invalid_checksum_or_root_cluster() {
        let mut invalid_checksum = exfat_boot_region(512);
        invalid_checksum[11 * 512] ^= 1;
        let image = mbr_with_exfat(&invalid_checksum, &invalid_checksum);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.partitions[0].filesystem_hint, None);

        let mut invalid_geometry = exfat_boot_region(512);
        invalid_geometry[96..100].copy_from_slice(&0_u32.to_le_bytes());
        write_exfat_boot_checksum(&mut invalid_geometry, 512);
        let image = mbr_with_exfat(&invalid_geometry, &invalid_geometry);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.partitions[0].filesystem_hint, None);
    }

    #[test]
    fn parses_mbr_bounds_and_boot_flag() {
        let mut image = vec![0; 4096];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[446] = 0x80;
        image[450] = 0x07;
        image[454..458].copy_from_slice(&1_u32.to_le_bytes());
        image[458..462].copy_from_slice(&2_u32.to_le_bytes());
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.scheme, "MBR");
        assert_eq!(report.partitions[0].start_lba, 1);
        assert!(report.partitions[0].bootable);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn labels_mbr_partition_overlap_without_claiming_gpt() {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        for (index, start) in [(0, 1_u32), (1, 10_u32)] {
            let entry = 446 + index * 16;
            image[entry + 4] = 0x07;
            image[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
            image[entry + 12..entry + 16].copy_from_slice(&20_u32.to_le_bytes());
        }

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.scheme, "MBR");
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning == "Partitions 1 and 2 overlap."));
        assert!(report
            .warnings
            .iter()
            .all(|warning| !warning.contains("GPT")));
    }

    #[test]
    fn follows_bounded_extended_partition_chain() {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0x0f;
        image[454..458].copy_from_slice(&10_u32.to_le_bytes());
        image[458..462].copy_from_slice(&50_u32.to_le_bytes());
        let ebr = 10 * 512;
        image[ebr + 510..ebr + 512].copy_from_slice(&[0x55, 0xaa]);
        image[ebr + 446 + 4] = 0x07;
        image[ebr + 446 + 8..ebr + 446 + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[ebr + 446 + 12..ebr + 446 + 16].copy_from_slice(&5_u32.to_le_bytes());
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.partitions.len(), 2);
        assert!(report.partitions[0].type_id.contains("container"));
        assert_eq!(report.partitions[1].index, 5);
        assert_eq!(report.partitions[1].start_lba, 11);
        assert_eq!(report.partitions[1].end_lba, 15);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn detects_extended_partition_cycles() {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0x0f;
        image[454..458].copy_from_slice(&10_u32.to_le_bytes());
        image[458..462].copy_from_slice(&50_u32.to_le_bytes());
        let ebr = 10 * 512;
        image[ebr + 510..ebr + 512].copy_from_slice(&[0x55, 0xaa]);
        image[ebr + 462 + 4] = 0x0f;
        image[ebr + 462 + 8..ebr + 462 + 12].copy_from_slice(&0_u32.to_le_bytes());
        image[ebr + 462 + 12..ebr + 462 + 16].copy_from_slice(&40_u32.to_le_bytes());
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("cycle")));
    }

    #[test]
    fn checks_ntfs_boot_geometry_before_reporting_a_hint() {
        let mut image = vec![0; 4096];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[446 + 4] = 0x07;
        image[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[446 + 12..446 + 16].copy_from_slice(&7_u32.to_le_bytes());
        image[512 + 3..512 + 11].copy_from_slice(b"NTFS    ");
        image[512 + 11..512 + 13].copy_from_slice(&512_u16.to_le_bytes());
        image[512 + 13] = 8;
        image[512 + 40..512 + 48].copy_from_slice(&7_u64.to_le_bytes());
        image[512 + 510..512 + 512].copy_from_slice(&[0x55, 0xaa]);
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions[0]
            .filesystem_hint
            .as_deref()
            .unwrap()
            .starts_with("NTFS"));
        let mut invalid = image.clone();
        invalid[512 + 11..512 + 13].copy_from_slice(&4096_u16.to_le_bytes());
        let report = analyze(&mut Cursor::new(invalid.clone()), invalid.len() as u64).unwrap();
        assert_eq!(report.partitions[0].filesystem_hint, None);
    }

    fn gpt_header(
        current: u64,
        backup: u64,
        entries_lba: u64,
        entry_crc: u32,
        sector_size: usize,
    ) -> Vec<u8> {
        let mut h = vec![0; sector_size];
        h[..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        h[12..16].copy_from_slice(&92_u32.to_le_bytes());
        h[24..32].copy_from_slice(&current.to_le_bytes());
        h[32..40].copy_from_slice(&backup.to_le_bytes());
        h[40..48].copy_from_slice(&34_u64.to_le_bytes());
        h[48..56].copy_from_slice(&90_u64.to_le_bytes());
        h[56..72].copy_from_slice(&[1; 16]);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&4_u32.to_le_bytes());
        h[84..88].copy_from_slice(&128_u32.to_le_bytes());
        h[88..92].copy_from_slice(&entry_crc.to_le_bytes());
        let crc = crc32fast::hash(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn valid_gpt_image() -> Vec<u8> {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0xee;
        image[454..458].copy_from_slice(&1_u32.to_le_bytes());
        image[458..462].copy_from_slice(&99_u32.to_le_bytes());
        let mut entries = vec![0; 4 * 128];
        entries[..16].copy_from_slice(&[
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9,
            0x3b,
        ]);
        entries[16..32].copy_from_slice(&[0x42; 16]);
        entries[32..40].copy_from_slice(&34_u64.to_le_bytes());
        entries[40..48].copy_from_slice(&70_u64.to_le_bytes());
        let entries_crc = crc32fast::hash(&entries);
        image[1024..1024 + entries.len()].copy_from_slice(&entries);
        image[98 * 512..98 * 512 + entries.len()].copy_from_slice(&entries);
        image[512..1024].copy_from_slice(&gpt_header(1, 99, 2, entries_crc, 512));
        image[99 * 512..100 * 512].copy_from_slice(&gpt_header(99, 1, 98, entries_crc, 512));
        image
    }

    fn update_gpt_header_crc(image: &mut [u8], lba: usize) {
        let offset = lba * 512;
        let header = &mut image[offset..offset + 512];
        header[16..20].fill(0);
        let crc = crc32fast::hash(&header[..92]);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    fn update_gpt_entry_array_crc(image: &mut [u8], header_lba: usize) {
        let header_offset = header_lba * 512;
        let header = &image[header_offset..header_offset + 512];
        let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap()) as usize;
        let entry_count = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
        let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
        let entries_offset = entries_lba * 512;
        let entries_length = entry_count * entry_size;
        let entries_crc = crc32fast::hash(&image[entries_offset..entries_offset + entries_length]);
        image[header_offset + 88..header_offset + 92].copy_from_slice(&entries_crc.to_le_bytes());
        update_gpt_header_crc(image, header_lba);
    }

    #[test]
    fn validates_gpt_headers_and_entry_array() {
        let image = valid_gpt_image();
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.scheme, "GPT");
        assert_eq!(report.primary_gpt_valid, Some(true));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.partitions[0].start_lba, 34);
        assert_eq!(report.partitions[0].end_lba, 70);
        assert_eq!(report.partitions[0].unique_guid, Some(guid(&[0x42; 16])));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn reports_zero_gpt_unique_partition_guid() {
        let mut image = valid_gpt_image();
        image[2 * 512 + 16..2 * 512 + 32].fill(0);
        image[98 * 512 + 16..98 * 512 + 32].fill(0);
        update_gpt_entry_array_crc(&mut image, 1);
        update_gpt_entry_array_crc(&mut image, 99);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(true));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions[0].unique_guid, Some(guid(&[0; 16])));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("zero unique partition GUID")));
    }

    #[test]
    fn reports_duplicate_gpt_unique_partition_guids() {
        let mut image = valid_gpt_image();
        for entries_lba in [2, 98] {
            let entries_offset = entries_lba * 512;
            image.copy_within(entries_offset..entries_offset + 128, entries_offset + 128);
            image[entries_offset + 128 + 32..entries_offset + 128 + 40]
                .copy_from_slice(&71_u64.to_le_bytes());
            image[entries_offset + 128 + 40..entries_offset + 128 + 48]
                .copy_from_slice(&80_u64.to_le_bytes());
        }
        update_gpt_entry_array_crc(&mut image, 1);
        update_gpt_entry_array_crc(&mut image, 99);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.partitions.len(), 2);
        assert_eq!(
            report.partitions[0].unique_guid,
            report.partitions[1].unique_guid
        );
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("share a unique partition GUID")));
    }

    #[test]
    fn uses_backup_entry_array_when_primary_array_crc_fails() {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut entries = vec![0; 4 * 128];
        entries[..16].copy_from_slice(&[
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9,
            0x3b,
        ]);
        entries[16..32].copy_from_slice(&[0x42; 16]);
        entries[32..40].copy_from_slice(&34_u64.to_le_bytes());
        entries[40..48].copy_from_slice(&70_u64.to_le_bytes());
        let checksum = crc32fast::hash(&entries);
        image[1024..1024 + entries.len()].copy_from_slice(&entries);
        image[98 * 512..98 * 512 + entries.len()].copy_from_slice(&entries);
        image[1024] ^= 0xff;
        image[512..1024].copy_from_slice(&gpt_header(1, 99, 2, checksum, 512));
        image[99 * 512..100 * 512].copy_from_slice(&gpt_header(99, 1, 98, checksum, 512));
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.partitions[0].start_lba, 34);
        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("Primary GPT partition entry array")));
    }

    #[test]
    fn rejects_gpt_header_with_unsupported_revision_and_uses_backup() {
        let mut image = valid_gpt_image();
        image[512 + 8..512 + 12].copy_from_slice(&0x0002_0000_u32.to_le_bytes());
        update_gpt_header_crc(&mut image, 1);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("Primary GPT header is missing or invalid")));
    }

    #[test]
    fn rejects_gpt_entry_size_outside_uefi_power_of_two_multiples() {
        let mut image = valid_gpt_image();
        image[512 + 84..512 + 88].copy_from_slice(&136_u32.to_le_bytes());
        update_gpt_header_crc(&mut image, 1);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("Primary GPT header is missing or invalid")));
    }

    #[test]
    fn rejects_gpt_header_with_reserved_bits_or_zero_disk_guid() {
        for (field_offset, field_length) in [(20, 4), (56, 16)] {
            let mut image = valid_gpt_image();
            image[512 + field_offset..512 + field_offset + field_length].fill(0);
            if field_offset == 20 {
                image[512 + field_offset] = 1;
            }
            update_gpt_header_crc(&mut image, 1);

            let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

            assert_eq!(report.primary_gpt_valid, Some(false));
            assert_eq!(report.backup_gpt_valid, Some(true));
            assert_eq!(report.partitions.len(), 1);
        }
    }

    #[test]
    fn rejects_gpt_entry_array_overlapping_usable_partition_space() {
        let mut image = valid_gpt_image();
        image.copy_within(2 * 512..3 * 512, 34 * 512);
        image[512 + 72..512 + 80].copy_from_slice(&34_u64.to_le_bytes());
        update_gpt_header_crc(&mut image, 1);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
    }

    #[test]
    fn rejects_primary_gpt_entry_array_after_usable_space() {
        let mut image = valid_gpt_image();
        image.copy_within(2 * 512..3 * 512, 91 * 512);
        image[512 + 72..512 + 80].copy_from_slice(&91_u64.to_le_bytes());
        update_gpt_header_crc(&mut image, 1);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
    }

    #[test]
    fn rejects_backup_gpt_entry_array_before_usable_space() {
        let mut image = valid_gpt_image();
        image.copy_within(98 * 512..99 * 512, 2 * 512);
        image[99 * 512 + 72..99 * 512 + 80].copy_from_slice(&2_u64.to_le_bytes());
        update_gpt_header_crc(&mut image, 99);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(true));
        assert_eq!(report.backup_gpt_valid, Some(false));
        assert_eq!(report.partitions.len(), 1);
    }

    #[test]
    fn rejects_gpt_header_whose_current_lba_disagrees_with_its_location() {
        let mut image = valid_gpt_image();
        image[512 + 24..512 + 32].copy_from_slice(&3_u64.to_le_bytes());
        update_gpt_header_crc(&mut image, 1);

        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();

        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
    }

    #[test]
    fn accepts_gpt_images_with_4k_sectors() {
        let sector = 4096;
        let mut image = vec![0; 100 * sector];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0xee;
        image[454..458].copy_from_slice(&1_u32.to_le_bytes());
        image[458..462].copy_from_slice(&99_u32.to_le_bytes());
        let mut entries = vec![0; 4 * 128];
        entries[..16].copy_from_slice(&[
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9,
            0x3b,
        ]);
        entries[16..32].copy_from_slice(&[0x42; 16]);
        entries[32..40].copy_from_slice(&34_u64.to_le_bytes());
        entries[40..48].copy_from_slice(&70_u64.to_le_bytes());
        let checksum = crc32fast::hash(&entries);
        image[2 * sector..2 * sector + entries.len()].copy_from_slice(&entries);
        image[98 * sector..98 * sector + entries.len()].copy_from_slice(&entries);
        image[sector..2 * sector].copy_from_slice(&gpt_header(1, 99, 2, checksum, sector));
        image[99 * sector..100 * sector].copy_from_slice(&gpt_header(99, 1, 98, checksum, sector));
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.scheme, "GPT");
        assert_eq!(report.sector_size, 4096);
        assert_eq!(report.partitions[0].size_bytes, 37 * 4096);
    }

    #[test]
    fn refuses_truncated_and_bad_partition_metadata() {
        assert!(analyze(&mut Cursor::new(vec![0; 20]), 20).is_err());
        let mut image = vec![0; 512];
        assert!(analyze(&mut Cursor::new(image.clone()), image.len() as u64).is_err());
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0x07;
        image[454..458].copy_from_slice(&1_u32.to_le_bytes());
        image[458..462].copy_from_slice(&u32::MAX.to_le_bytes());
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert!(report.partitions.is_empty());
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn protective_mbr_does_not_hide_damaged_gpt_as_legacy_mbr() {
        let mut image = vec![0; 100 * 512];
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[450] = 0xee;
        image[454..458].copy_from_slice(&1_u32.to_le_bytes());
        image[458..462].copy_from_slice(&99_u32.to_le_bytes());
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.scheme, "GPT (headers damaged)");
        assert!(report.partitions.is_empty());
        assert_eq!(report.primary_gpt_valid, Some(false));
        assert_eq!(report.backup_gpt_valid, Some(false));
    }
}
