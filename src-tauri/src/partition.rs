use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};

const ENTRY_LIMIT: u64 = 4096;
const ARRAY_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Partition {
    pub index: usize,
    pub type_id: String,
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
    } else if b.get(3..11) == Some(b"EXFAT   ") {
        let bytes_shift = *b.get(108)?;
        let cluster_shift = *b.get(109)?;
        let volume_sectors = u64_at(&b, 72)?;
        if (9..=12).contains(&bytes_shift)
            && bytes_shift == sector_size.trailing_zeros() as u8
            && cluster_shift <= 25
            && volume_sectors > 0
            && volume_sectors <= partition_sectors
        {
            return Some(
                "exFAT boot signature (basic geometry checked; parser unavailable)".into(),
            );
        }
    } else if b.get(82..90) == Some(b"FAT32   ") {
        let total = u32_at(&b, 32)? as u64;
        if total > 0 && total <= partition_sectors {
            return Some(
                "FAT32 boot signature (basic geometry checked; parser unavailable)".into(),
            );
        }
    }
    None
}

fn parse_gpt_header(bytes: &[u8], sector_size: u32) -> Result<GptHeader, String> {
    if bytes.get(..8) != Some(b"EFI PART") {
        return Err("GPT signature is missing".into());
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
    if !(128..=1024).contains(&entry_size)
        || entry_size % 8 != 0
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
    let primary = parse_gpt_header(&primary_bytes, sector_size).ok();
    let backup_bytes = read_at(r, last_lba * sector, sector_size as usize, image_size).ok()?;
    let backup = parse_gpt_header(&backup_bytes, sector_size).ok();
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
    {
        for i in 0..selected.entry_count as usize {
            let at = i * selected.entry_size as usize;
            let item = &entries[at..at + selected.entry_size as usize];
            if item[..16].iter().all(|v| *v == 0) {
                continue;
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
                "GPT partitions {} and {} overlap.",
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
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&4_u32.to_le_bytes());
        h[84..88].copy_from_slice(&128_u32.to_le_bytes());
        h[88..92].copy_from_slice(&entry_crc.to_le_bytes());
        let crc = crc32fast::hash(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    #[test]
    fn validates_gpt_headers_and_entry_array() {
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
        entries[32..40].copy_from_slice(&34_u64.to_le_bytes());
        entries[40..48].copy_from_slice(&70_u64.to_le_bytes());
        let entries_crc = crc32fast::hash(&entries);
        image[1024..1024 + entries.len()].copy_from_slice(&entries);
        image[98 * 512..98 * 512 + entries.len()].copy_from_slice(&entries);
        image[512..1024].copy_from_slice(&gpt_header(1, 99, 2, entries_crc, 512));
        image[99 * 512..100 * 512].copy_from_slice(&gpt_header(99, 1, 98, entries_crc, 512));
        let report = analyze(&mut Cursor::new(image.clone()), image.len() as u64).unwrap();
        assert_eq!(report.scheme, "GPT");
        assert_eq!(report.primary_gpt_valid, Some(true));
        assert_eq!(report.backup_gpt_valid, Some(true));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.partitions[0].start_lba, 34);
        assert_eq!(report.partitions[0].end_lba, 70);
        assert!(report.warnings.is_empty());
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
