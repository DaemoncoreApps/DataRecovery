use crate::storage::BlockSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_RUNS: usize = 4096;
const MAX_RECORDS: u64 = 1_000_000;
const MAX_RESULTS: usize = 10_000;
const MAX_DIRECTORY_REFERENCES: usize = 100_000;
type Result<T> = std::result::Result<T, String>;
fn bytes(b: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    b.get(offset..offset.checked_add(length).ok_or("Field overflow")?)
        .ok_or_else(|| "Truncated NTFS structure".into())
}
fn u16le(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(b, o, 2)?.try_into().unwrap()))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(b, o, 4)?.try_into().unwrap()))
}
fn u64le(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(b, o, 8)?.try_into().unwrap()))
}
fn unicode(b: &[u8]) -> Result<String> {
    let values = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&values).map_err(|_| "Invalid UTF-16 filename".into())
}

#[derive(Clone, Debug, Serialize)]
pub struct Boot {
    pub offset: u64,
    pub sector_size: u64,
    pub cluster_size: u64,
    pub record_size: u64,
    pub volume_size: u64,
    pub mft_offset: u64,
    pub serial: String,
}
impl Boot {
    pub fn read(source: &dyn BlockSource, offset: u64) -> Result<Self> {
        let mut b = [0; 512];
        source
            .read_exact_at(offset, &mut b)
            .map_err(|e| e.to_string())?;
        if &b[3..11] != b"NTFS    " || b[510..512] != [0x55, 0xaa] {
            return Err("No NTFS boot sector at this offset. Select the NTFS partition start, not the disk MBR.".into());
        }
        let sector_size = u16le(&b, 11)? as u64;
        let spc = b[13] as u64;
        if ![512, 1024, 2048, 4096].contains(&sector_size) || !spc.is_power_of_two() || spc > 128 {
            return Err("Invalid or unsupported NTFS sector/cluster geometry".into());
        }
        let cluster_size = sector_size
            .checked_mul(spc)
            .ok_or("Cluster size overflow")?;
        let volume_size = u64le(&b, 40)?
            .checked_mul(sector_size)
            .ok_or("Volume size overflow")?;
        if volume_size < sector_size
            || offset
                .checked_add(volume_size)
                .is_none_or(|n| n > source.len())
        {
            return Err("NTFS volume extends beyond the selected image".into());
        }
        let encoded = b[64] as i8;
        let record_size = if encoded < 0 {
            1u64.checked_shl(-(encoded as i16) as u32)
                .ok_or("MFT record size overflow")?
        } else {
            cluster_size
                .checked_mul(encoded as u64)
                .ok_or("MFT record size overflow")?
        };
        if !(512..=65536).contains(&record_size) || !record_size.is_multiple_of(512) {
            return Err("Unsupported or invalid MFT record size".into());
        }
        let mft_relative = u64le(&b, 48)?
            .checked_mul(cluster_size)
            .ok_or("MFT offset overflow")?;
        if mft_relative
            .checked_add(record_size)
            .is_none_or(|n| n > volume_size)
        {
            return Err("MFT bootstrap record is outside the NTFS volume".into());
        }
        Ok(Self {
            offset,
            sector_size,
            cluster_size,
            record_size,
            volume_size,
            mft_offset: offset + mft_relative,
            serial: format!("{:016x}", u64le(&b, 72)?),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Run {
    pub vcn: u64,
    pub clusters: u64,
    pub lcn: Option<u64>,
}
#[derive(Clone, Debug)]
pub enum Content {
    Resident(Vec<u8>),
    Runs(Vec<Run>),
}
#[derive(Clone, Debug)]
pub struct Stream {
    pub size: u64,
    pub initialized: u64,
    pub content: Content,
    pub blocked: Option<String>,
}
pub(crate) fn mft_record_count(mft: &Stream, boot: &Boot) -> Result<u64> {
    if boot.record_size == 0
        || mft.size == 0
        || mft.size > boot.volume_size
        || !mft.size.is_multiple_of(boot.record_size)
        || mft.initialized == 0
        || mft.initialized > mft.size
        || !mft.initialized.is_multiple_of(boot.record_size)
    {
        return Err("MFT size or initialized size does not align to complete NTFS records".into());
    }
    Ok(mft.initialized / boot.record_size)
}
impl Stream {
    pub fn read_at(
        &self,
        source: &dyn BlockSource,
        boot: &Boot,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if self.blocked.is_some() {
            return Err(self.blocked.clone().unwrap());
        }
        if offset
            .checked_add(buffer.len() as u64)
            .is_none_or(|n| n > self.size)
        {
            return Err("Stream read exceeds logical file size".into());
        }
        match &self.content {
            Content::Resident(data) => {
                buffer.copy_from_slice(bytes(data, offset as usize, buffer.len())?);
            }
            Content::Runs(runs) => {
                let mut done = 0;
                while done < buffer.len() {
                    let position = offset + done as u64;
                    if position >= self.initialized {
                        buffer[done..].fill(0);
                        break;
                    }
                    let vcn = position / boot.cluster_size;
                    let run = runs
                        .iter()
                        .find(|r| vcn >= r.vcn && vcn - r.vcn < r.clusters)
                        .ok_or("Data mapping has a gap")?;
                    let within = position - run.vcn * boot.cluster_size;
                    let remaining = run.clusters * boot.cluster_size - within;
                    let count = remaining
                        .min(self.initialized - position)
                        .min((buffer.len() - done) as u64) as usize;
                    if let Some(lcn) = run.lcn {
                        let physical = boot
                            .offset
                            .checked_add(
                                lcn.checked_mul(boot.cluster_size)
                                    .ok_or("Extent offset overflow")?,
                            )
                            .and_then(|n| n.checked_add(within))
                            .ok_or("Extent offset overflow")?;
                        source
                            .read_exact_at(physical, &mut buffer[done..done + count])
                            .map_err(|e| e.to_string())?;
                    } else {
                        buffer[done..done + count].fill(0);
                    }
                    done += count;
                }
            }
        }
        Ok(())
    }
}

pub fn decode_runs(data: &[u8], boot: &Boot, highest: u64) -> Result<Vec<Run>> {
    decode_runs_from(data, boot, 0, highest)
}

fn decode_runs_from(data: &[u8], boot: &Boot, lowest: u64, highest: u64) -> Result<Vec<Run>> {
    let mut pos = 0;
    let mut vcn = lowest;
    let mut lcn = 0i64;
    let mut runs = Vec::new();
    let mut terminated = false;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        if header == 0 {
            terminated = true;
            break;
        }
        let length_bytes = (header & 15) as usize;
        let offset_bytes = (header >> 4) as usize;
        if length_bytes == 0 || length_bytes > 8 || offset_bytes > 8 || runs.len() >= MAX_RUNS {
            return Err("Invalid or excessive NTFS data runs".into());
        }
        let mut length = [0; 8];
        length[..length_bytes].copy_from_slice(bytes(data, pos, length_bytes)?);
        pos += length_bytes;
        let clusters = u64::from_le_bytes(length);
        if clusters == 0 {
            return Err("Zero-length NTFS data run".into());
        }
        let physical = if offset_bytes == 0 {
            None
        } else {
            let raw = bytes(data, pos, offset_bytes)?;
            pos += offset_bytes;
            let mut signed = if raw[offset_bytes - 1] & 0x80 != 0 {
                [0xff; 8]
            } else {
                [0; 8]
            };
            signed[..offset_bytes].copy_from_slice(raw);
            lcn = lcn
                .checked_add(i64::from_le_bytes(signed))
                .ok_or("Relative LCN overflow")?;
            if lcn < 0 {
                return Err("Negative physical cluster in data run".into());
            }
            let end = (lcn as u64)
                .checked_add(clusters)
                .and_then(|n| n.checked_mul(boot.cluster_size))
                .ok_or("Extent length overflow")?;
            if end > boot.volume_size {
                return Err("File extent exceeds NTFS volume".into());
            }
            Some(lcn as u64)
        };
        runs.push(Run {
            vcn,
            clusters,
            lcn: physical,
        });
        vcn = vcn.checked_add(clusters).ok_or("VCN overflow")?;
    }
    if !terminated || runs.is_empty() || highest.checked_add(1) != Some(vcn) {
        return Err("Incomplete or inconsistent NTFS data-run coverage".into());
    }
    Ok(runs)
}

#[derive(Clone, Debug)]
pub struct Record {
    pub number: u64,
    pub sequence: u16,
    base_reference: Option<(u64, u16)>,
    pub name: String,
    pub parent: u64,
    pub parent_sequence: u16,
    pub parent_ambiguous: bool,
    pub deleted: bool,
    pub directory: bool,
    pub stream: Option<Stream>,
    pub notes: Vec<String>,
    pub fingerprint: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub ads: usize,
    data_attributes: Vec<DataAttribute>,
    attribute_list: Option<AttributeList>,
}

#[derive(Clone, Debug)]
struct DataAttribute {
    name: String,
    lowest_vcn: u64,
    highest_vcn: u64,
    allocated: u64,
    flags: u16,
    stream: Stream,
}

#[derive(Clone, Debug)]
enum AttributeList {
    Resident(Vec<u8>),
    NonResident(DataAttribute),
}

#[derive(Debug)]
struct AttributeListEntry {
    attribute_type: u32,
    name: String,
    lowest_vcn: u64,
    record: u64,
    sequence: u16,
}

const MAX_ATTRIBUTE_LIST_ENTRIES: usize = 4096;
const MAX_ATTRIBUTE_LIST_RECORDS: usize = 256;
const MAX_ATTRIBUTE_LIST_RUNS: usize = 65_536;
const MAX_ATTRIBUTE_LIST_BYTES: u64 = 16 * 1024 * 1024;

fn parse_nonresident_attribute(
    a: &[u8],
    name: String,
    flags: u16,
    boot: &Boot,
) -> Result<DataAttribute> {
    if a.len() < 64 {
        return Err("Truncated nonresident header".into());
    }
    let lowest_vcn = u64le(a, 16)?;
    let highest_vcn = u64le(a, 24)?;
    let run_offset = u16le(a, 32)? as usize;
    if run_offset < 64 || run_offset >= a.len() {
        return Err("Data run offset is outside its attribute".into());
    }
    let mapping_pairs = bytes(a, run_offset, a.len() - run_offset)?;
    let runs = if lowest_vcn == 0 {
        decode_runs(mapping_pairs, boot, highest_vcn)?
    } else {
        decode_runs_from(mapping_pairs, boot, lowest_vcn, highest_vcn)?
    };
    let size = if lowest_vcn == 0 { u64le(a, 48)? } else { 0 };
    let initialized = if lowest_vcn == 0 { u64le(a, 56)? } else { 0 };
    let allocated = if lowest_vcn == 0 { u64le(a, 40)? } else { 0 };
    if lowest_vcn == 0 && initialized > size {
        return Err("Initialized stream size exceeds its logical size".into());
    }
    let blocked = if flags & 0x4000 != 0 {
        Some("Encrypted NTFS stream is unsupported".into())
    } else if flags & 0x00ff != 0 {
        Some("Compressed NTFS stream is unsupported".into())
    } else {
        None
    };
    Ok(DataAttribute {
        name,
        lowest_vcn,
        highest_vcn,
        allocated,
        flags,
        stream: Stream {
            size,
            initialized,
            content: Content::Runs(runs),
            blocked,
        },
    })
}

fn read_nonresident_attribute_list(
    source: &dyn BlockSource,
    boot: &Boot,
    mft: &Stream,
    base: &Record,
    attribute: &DataAttribute,
) -> Result<Vec<AttributeListEntry>> {
    if !attribute.name.is_empty()
        || attribute.lowest_vcn != 0
        || attribute.flags != 0
        || attribute.stream.blocked.is_some()
    {
        return Err("Nonresident attribute-list stream has unsupported flags or layout".into());
    }
    if attribute.stream.size == 0
        || attribute.stream.size > MAX_ATTRIBUTE_LIST_BYTES
        || attribute.stream.initialized != attribute.stream.size
    {
        return Err("Nonresident attribute-list size or initialized length is invalid".into());
    }
    let mut segments = vec![attribute.clone()];
    let mut extension_records = BTreeMap::new();
    let mut seen_records = std::collections::BTreeSet::new();
    loop {
        let expected_vcn = segments
            .last()
            .and_then(|segment| segment.highest_vcn.checked_add(1))
            .ok_or("Nonresident attribute-list VCN overflow")?;
        let mapped_bytes = expected_vcn
            .checked_mul(boot.cluster_size)
            .ok_or("Nonresident attribute-list coverage overflow")?;
        if mapped_bytes >= attribute.stream.size {
            break;
        }
        let prefix_stream = combine_attribute_list_segments(&segments, attribute)?;
        let mut prefix = vec![0; mapped_bytes as usize];
        prefix_stream.read_at(source, boot, 0, &mut prefix)?;
        let entries = parse_attribute_list_prefix(&prefix, true)?.0;
        if !entries.iter().any(|entry| {
            entry.attribute_type == 0x20
                && entry.name.is_empty()
                && entry.lowest_vcn == 0
                && entry.record == base.number
                && entry.sequence == base.sequence
        }) {
            return Err("Nonresident attribute list does not reference its base extent".into());
        }
        let continuation = entries
            .iter()
            .filter(|entry| {
                entry.attribute_type == 0x20
                    && entry.name.is_empty()
                    && entry.lowest_vcn == expected_vcn
            })
            .collect::<Vec<_>>();
        if continuation.len() != 1 {
            return Err("Nonresident attribute-list continuation is missing or ambiguous".into());
        }
        let entry = continuation[0];
        if entry.record == base.number || !seen_records.insert(entry.record) {
            return Err("Nonresident attribute-list continuation repeats a record".into());
        }
        if !extension_records.contains_key(&entry.record) {
            if extension_records.len() >= MAX_ATTRIBUTE_LIST_RECORDS {
                return Err("Attribute list references too many extension records".into());
            }
            extension_records.insert(
                entry.record,
                read_record_raw(source, boot, mft, entry.record)?,
            );
        }
        let extension = extension_records
            .get(&entry.record)
            .ok_or("Attribute-list extension record is unavailable")?;
        if extension.sequence != entry.sequence
            || extension.base_reference != Some((base.number, base.sequence))
        {
            return Err("Attribute-list extension record identity does not match".into());
        }
        let Some(AttributeList::NonResident(segment)) = extension.attribute_list.as_ref() else {
            return Err("Attribute-list continuation record has no nonresident list extent".into());
        };
        let Content::Runs(segment_runs) = &segment.stream.content else {
            return Err("Nonresident attribute-list continuation has no mapping".into());
        };
        if !segment.name.is_empty()
            || segment.lowest_vcn != expected_vcn
            || segment.highest_vcn < segment.lowest_vcn
            || segment.flags != 0
            || segment.stream.blocked.is_some()
            || segment_runs
                .first()
                .is_none_or(|run| run.vcn != expected_vcn)
            || segment_runs.iter().any(|run| run.lcn.is_none())
        {
            return Err("Nonresident attribute-list continuation extent is invalid".into());
        }
        segments.push(segment.clone());
        if segments.len() > MAX_ATTRIBUTE_LIST_RECORDS + 1 {
            return Err("Attribute list contains too many continuation extents".into());
        }
    }

    let stream = combine_attribute_list_segments(&segments, attribute)?;
    if stream.initialized != stream.size {
        return Err("Nonresident attribute-list initialized length is incomplete".into());
    }
    let Content::Runs(runs) = &stream.content else {
        return Err("Nonresident attribute list has no run mapping".into());
    };
    if runs.is_empty() || runs.iter().any(|run| run.lcn.is_none()) {
        return Err("Sparse nonresident attribute lists are unsupported".into());
    }
    let coverage = segments
        .last()
        .and_then(|segment| segment.highest_vcn.checked_add(1))
        .and_then(|clusters| clusters.checked_mul(boot.cluster_size))
        .ok_or("Nonresident attribute-list coverage overflow")?;
    if attribute.allocated != coverage || attribute.allocated < stream.size {
        return Err("Nonresident attribute-list allocation metadata is inconsistent".into());
    }
    let mut bytes = vec![0; stream.size as usize];
    stream.read_at(source, boot, 0, &mut bytes)?;
    let parsed = parse_attribute_list(&bytes)?;
    let expected_refs = segments
        .iter()
        .map(|segment| {
            if segment.lowest_vcn == 0 {
                Ok((segment.lowest_vcn, base.number, base.sequence))
            } else {
                extension_records
                    .iter()
                    .find(|(_, record)| {
                        matches!(record.attribute_list.as_ref(), Some(AttributeList::NonResident(candidate)) if candidate.lowest_vcn == segment.lowest_vcn)
                    })
                    .map(|(record_number, record)| {
                        (segment.lowest_vcn, *record_number, record.sequence)
                    })
                    .ok_or_else(|| "Attribute-list continuation identity is unavailable".to_string())
            }
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let actual_refs = parsed
        .iter()
        .filter(|entry| entry.attribute_type == 0x20)
        .map(|entry| {
            if !entry.name.is_empty() {
                return Err("Named attribute-list streams are unsupported".into());
            }
            Ok((entry.lowest_vcn, entry.record, entry.sequence))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    if actual_refs != expected_refs {
        return Err("Nonresident attribute-list references do not match its extents".into());
    }
    Ok(parsed)
}

fn combine_attribute_list_segments(
    segments: &[DataAttribute],
    first: &DataAttribute,
) -> Result<Stream> {
    let mut runs = Vec::new();
    let mut expected_vcn = 0u64;
    for segment in segments {
        if segment.lowest_vcn != expected_vcn || segment.flags != 0 {
            return Err("Nonresident attribute-list extents have a VCN gap or flags".into());
        }
        let Content::Runs(segment_runs) = &segment.stream.content else {
            return Err("Nonresident attribute-list extent has no run mapping".into());
        };
        if segment_runs
            .first()
            .is_none_or(|run| run.vcn != segment.lowest_vcn)
            || segment_runs.iter().any(|run| run.lcn.is_none())
        {
            return Err("Nonresident attribute-list mapping is sparse or inconsistent".into());
        }
        if runs
            .len()
            .checked_add(segment_runs.len())
            .is_none_or(|count| count > MAX_ATTRIBUTE_LIST_RUNS)
        {
            return Err("Nonresident attribute list contains too many runs".into());
        }
        expected_vcn = segment
            .highest_vcn
            .checked_add(1)
            .ok_or("Nonresident attribute-list VCN overflow")?;
        runs.extend(segment_runs.iter().cloned());
    }
    if first.stream.initialized > first.stream.size {
        return Err("Nonresident attribute-list initialized size exceeds its stream".into());
    }
    Ok(Stream {
        size: first.stream.size,
        initialized: first.stream.initialized,
        content: Content::Runs(runs),
        blocked: None,
    })
}

fn parse_attribute_list(data: &[u8]) -> Result<Vec<AttributeListEntry>> {
    let (entries, complete) = parse_attribute_list_prefix(data, false)?;
    if !complete || entries.is_empty() {
        return Err("Attribute list is empty or incomplete".into());
    }
    Ok(entries)
}

fn parse_attribute_list_prefix(
    data: &[u8],
    allow_partial_tail: bool,
) -> Result<(Vec<AttributeListEntry>, bool)> {
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut position = 0usize;
    while position < data.len() {
        if entries.len() >= MAX_ATTRIBUTE_LIST_ENTRIES {
            return Err("Attribute list contains too many entries".into());
        }
        let remaining = &data[position..];
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        if remaining.len() < 26 {
            if allow_partial_tail {
                return Ok((entries, false));
            }
            return Err("Truncated attribute-list entry".into());
        }
        let attribute_type = u32le(remaining, 0)?;
        let length = u16le(remaining, 4)? as usize;
        let name_length = *remaining.get(6).ok_or("Truncated attribute-list entry")? as usize;
        let name_offset = *remaining.get(7).ok_or("Truncated attribute-list entry")? as usize;
        if length < 26 || !length.is_multiple_of(8) {
            return Err("Invalid attribute-list entry length".into());
        }
        if length > remaining.len() {
            if allow_partial_tail {
                return Ok((entries, false));
            }
            return Err("Truncated attribute-list entry".into());
        }
        let entry = &remaining[..length];
        let name = if name_length == 0 {
            String::new()
        } else {
            if name_offset < 26 {
                return Err("Attribute-list name overlaps its entry header".into());
            }
            unicode(bytes(entry, name_offset, name_length * 2)?)?
        };
        let lowest_vcn = u64le(entry, 8)?;
        let reference = u64le(entry, 16)?;
        if u16le(entry, 24)? != 0 {
            return Err("Attribute-list reserved field is not zero".into());
        }
        let record = reference & 0x0000_ffff_ffff_ffff;
        let sequence = (reference >> 48) as u16;
        if !seen.insert((attribute_type, name.clone(), lowest_vcn)) {
            return Err("Attribute list contains an invalid or duplicate reference".into());
        }
        entries.push(AttributeListEntry {
            attribute_type,
            name,
            lowest_vcn,
            record,
            sequence,
        });
        position += length;
    }
    Ok((entries, true))
}

fn assemble_unnamed_data(
    source: &dyn BlockSource,
    boot: &Boot,
    mft: &Stream,
    base: &Record,
    entries: &[AttributeListEntry],
) -> Result<Stream> {
    let data_entries = entries
        .iter()
        .filter(|entry| entry.attribute_type == 0x80 && entry.name.is_empty())
        .collect::<Vec<_>>();
    if data_entries.is_empty() {
        return Err("Attribute list does not reference an unnamed data stream".into());
    }
    let base_data_refs = data_entries
        .iter()
        .filter(|entry| entry.record == base.number && entry.sequence == base.sequence)
        .map(|entry| entry.lowest_vcn)
        .collect::<std::collections::BTreeSet<_>>();
    let base_data_attributes = base
        .data_attributes
        .iter()
        .filter(|attribute| attribute.name.is_empty())
        .map(|attribute| attribute.lowest_vcn)
        .collect::<std::collections::BTreeSet<_>>();
    if base_data_refs != base_data_attributes {
        return Err("Attribute list does not exactly reference base-record data extents".into());
    }

    let mut segments = Vec::with_capacity(data_entries.len());
    let mut extension_cache = BTreeMap::new();
    for entry in data_entries {
        let record = if entry.record == base.number {
            if entry.sequence != base.sequence {
                return Err("Attribute list contains a stale base-record sequence".into());
            }
            base
        } else {
            if !extension_cache.contains_key(&entry.record) {
                if extension_cache.len() >= MAX_ATTRIBUTE_LIST_RECORDS {
                    return Err("Attribute list references too many extension records".into());
                }
                extension_cache.insert(
                    entry.record,
                    read_record_raw(source, boot, mft, entry.record)?,
                );
            }
            let extension = extension_cache
                .get(&entry.record)
                .ok_or("Attribute-list extension record is unavailable")?;
            if extension.sequence != entry.sequence
                || extension.base_reference != Some((base.number, base.sequence))
            {
                return Err("Attribute-list extension record identity does not match".into());
            }
            extension
        };
        let mut matches = record.data_attributes.iter().filter(|attribute| {
            attribute.name.is_empty() && attribute.lowest_vcn == entry.lowest_vcn
        });
        let attribute = matches
            .next()
            .ok_or("Attribute-list reference does not identify a data extent")?;
        if matches.next().is_some() || attribute.highest_vcn < attribute.lowest_vcn {
            return Err("Attribute-list reference is ambiguous or has invalid VCN bounds".into());
        }
        segments.push(attribute.clone());
    }
    segments.sort_by_key(|segment| segment.lowest_vcn);
    if segments
        .first()
        .is_none_or(|segment| segment.lowest_vcn != 0)
    {
        return Err("Attribute-list data stream has no VCN-zero extent".into());
    }
    let first = &segments[0];
    if let Content::Resident(_) = first.stream.content {
        if segments.len() != 1 {
            return Err("Resident data cannot have continuation extents".into());
        }
        return Ok(first.stream.clone());
    }

    let mut runs = Vec::new();
    let mut expected_vcn = 0u64;
    let flags = first.flags & 0xC0FF;
    for segment in &segments {
        if segment.lowest_vcn != expected_vcn || (segment.flags & 0xC0FF) != flags {
            return Err("Attribute-list data extents have a gap or conflicting flags".into());
        }
        let Content::Runs(segment_runs) = &segment.stream.content else {
            return Err("Resident and nonresident data extents conflict".into());
        };
        if segment_runs
            .first()
            .is_none_or(|run| run.vcn != segment.lowest_vcn)
        {
            return Err("Attribute-list extent mapping does not start at its declared VCN".into());
        }
        if runs
            .len()
            .checked_add(segment_runs.len())
            .is_none_or(|count| count > MAX_ATTRIBUTE_LIST_RUNS)
        {
            return Err("Attribute list maps too many data runs".into());
        }
        expected_vcn = segment
            .highest_vcn
            .checked_add(1)
            .ok_or("Attribute-list VCN overflow")?;
        runs.extend(segment_runs.iter().cloned());
    }
    let coverage = expected_vcn
        .checked_mul(boot.cluster_size)
        .ok_or("Attribute-list stream coverage overflow")?;
    if first.stream.size > coverage || first.stream.initialized > first.stream.size {
        return Err("Attribute-list extents do not cover the stream size".into());
    }
    Ok(Stream {
        size: first.stream.size,
        initialized: first.stream.initialized,
        content: Content::Runs(runs),
        blocked: if flags & 0x4000 != 0 {
            Some("Encrypted NTFS stream is unsupported".into())
        } else if flags & 0x00ff != 0 {
            Some("Compressed NTFS stream is unsupported".into())
        } else {
            None
        },
    })
}
fn fixup(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.get(..4) != Some(b"FILE") {
        return Err("MFT record is not a FILE record".into());
    }
    let usa = u16le(raw, 4)? as usize;
    let count = u16le(raw, 6)? as usize;
    if count != raw.len() / 512 + 1 || usa < 8 || usa.checked_add(count * 2).is_none_or(|n| n > 510)
    {
        return Err("Invalid MFT update sequence array".into());
    }
    let sequence = bytes(raw, usa, 2)?.to_vec();
    let mut fixed = raw.to_vec();
    for i in 1..count {
        let end = i * 512 - 2;
        if bytes(raw, end, 2)? != sequence {
            return Err("MFT update sequence check failed (torn/corrupt record)".into());
        }
        fixed[end..end + 2].copy_from_slice(bytes(raw, usa + i * 2, 2)?);
    }
    Ok(fixed)
}
pub fn parse_record(raw: &[u8], number: u64, boot: &Boot) -> Result<Record> {
    if raw.len() as u64 != boot.record_size {
        return Err("FILE record length does not match NTFS geometry".into());
    }
    let b = fixup(raw)?;
    let used = u32le(&b, 24)? as usize;
    let allocated = u32le(&b, 28)? as usize;
    let mut pos = u16le(&b, 20)? as usize;
    if used > b.len()
        || allocated > b.len()
        || used > allocated
        || pos < 42
        || !pos.is_multiple_of(8)
        || pos >= used
    {
        return Err("Invalid MFT record bounds".into());
    }
    let base_reference = u64le(&b, 32)?;
    let base_reference = (base_reference != 0).then_some((
        base_reference & 0x0000_ffff_ffff_ffff,
        (base_reference >> 48) as u16,
    ));
    let flags = u16le(&b, 22)?;
    let mut record = Record {
        number,
        sequence: u16le(&b, 16)?,
        base_reference,
        name: format!("record_{number}"),
        parent: 0,
        parent_sequence: 0,
        parent_ambiguous: false,
        deleted: flags & 1 == 0,
        directory: flags & 2 != 0,
        stream: None,
        notes: Vec::new(),
        fingerprint: format!("{:x}", Sha256::digest(raw)),
        created: None,
        modified: None,
        ads: 0,
        data_attributes: Vec::new(),
        attribute_list: None,
    };
    let mut namespace = 0u8;
    let mut has_name = false;
    let mut ended = false;
    for _ in 0..1024 {
        let kind = u32le(bytes(&b, 0, used)?, pos)?;
        if kind == u32::MAX {
            ended = true;
            break;
        }
        let length = u32le(&b, pos + 4)? as usize;
        if length < 24
            || !length.is_multiple_of(8)
            || pos.checked_add(length).is_none_or(|end| end > used)
        {
            return Err("Invalid attribute record bounds".into());
        }
        let a = bytes(&b, pos, length)?;
        let form = a[8];
        let name_len = a[9] as usize;
        let name_offset = u16le(a, 10)? as usize;
        let attr_flags = u16le(a, 12)?;
        let attribute_name = if name_len > 0 {
            if name_offset < 16 {
                return Err("Attribute name overlaps its header".into());
            }
            unicode(bytes(a, name_offset, name_len * 2)?)?
        } else {
            String::new()
        };
        let resident = if form == 0 {
            let value_len = u32le(a, 16)? as usize;
            let value_offset = u16le(a, 20)? as usize;
            if value_offset < 24 {
                return Err("Resident value overlaps attribute header".into());
            }
            Some(bytes(a, value_offset, value_len)?)
        } else if form == 1 {
            if length < 64 {
                return Err("Truncated nonresident header".into());
            }
            None
        } else {
            return Err("Invalid attribute form".into());
        };
        match kind {
            0x10 => {
                if let Some(value) = resident {
                    if value.len() >= 32 {
                        record.created = Some(u64le(value, 0)?.to_string());
                        record.modified = Some(u64le(value, 8)?.to_string());
                    }
                }
            }
            0x20 => {
                if !attribute_name.is_empty() || record.attribute_list.is_some() {
                    return Err("Named or duplicate attribute lists are unsupported".into());
                }
                record.attribute_list = Some(match resident {
                    Some(value) => AttributeList::Resident(value.to_vec()),
                    None => AttributeList::NonResident(parse_nonresident_attribute(
                        a,
                        attribute_name,
                        attr_flags,
                        boot,
                    )?),
                });
            }
            0x30 => {
                if let Some(value) = resident {
                    let name_header = bytes(value, 64, 2)?;
                    let chars = name_header[0] as usize;
                    let ns = name_header[1];
                    let text = unicode(bytes(value, 66, chars * 2)?)?;
                    let parent_reference = u64le(value, 0)?;
                    let parent = parent_reference & 0x0000_ffff_ffff_ffff;
                    let parent_sequence = (parent_reference >> 48) as u16;
                    if has_name
                        && (record.parent != parent || record.parent_sequence != parent_sequence)
                    {
                        record.parent_ambiguous = true;
                    }
                    if !has_name || (namespace == 2 && ns != 2) {
                        record.name = text;
                        record.parent = parent;
                        record.parent_sequence = parent_sequence;
                        namespace = ns;
                        has_name = true;
                    }
                }
            }
            0x80 => {
                if !attribute_name.is_empty() {
                    record.ads += 1;
                } else {
                    let stream_attribute = if let Some(value) = resident {
                        if record
                            .data_attributes
                            .iter()
                            .any(|attr| attr.name.is_empty())
                        {
                            return Err(
                                "Resident and continued unnamed data attributes conflict".into()
                            );
                        }
                        let stream = Stream {
                            size: value.len() as u64,
                            initialized: value.len() as u64,
                            content: Content::Resident(value.to_vec()),
                            blocked: None,
                        };
                        DataAttribute {
                            name: attribute_name,
                            lowest_vcn: 0,
                            highest_vcn: 0,
                            allocated: 0,
                            flags: attr_flags,
                            stream,
                        }
                    } else {
                        parse_nonresident_attribute(a, attribute_name, attr_flags, boot)?
                    };
                    if record.stream.is_none() {
                        record.stream = Some(stream_attribute.stream.clone());
                    }
                    record.data_attributes.push(stream_attribute);
                }
            }
            _ => {}
        }
        pos += length;
    }
    if !ended {
        return Err("Missing attribute end marker".into());
    }
    if record.attribute_list.is_none() {
        for attribute in record
            .data_attributes
            .iter()
            .filter(|attribute| attribute.name.is_empty() && attribute.lowest_vcn == 0)
        {
            if let Content::Runs(runs) = &attribute.stream.content {
                let coverage = runs
                    .last()
                    .and_then(|run| run.vcn.checked_add(run.clusters))
                    .and_then(|clusters| clusters.checked_mul(boot.cluster_size))
                    .ok_or("Stream coverage overflow")?;
                if attribute.stream.size > coverage {
                    return Err("Stream size exceeds its mapped data".into());
                }
            }
        }
        if record
            .data_attributes
            .iter()
            .filter(|attribute| attribute.name.is_empty())
            .count()
            > 1
        {
            if let Some(stream) = record.stream.as_mut() {
                stream.blocked = Some(
                    "Multiple unnamed data attributes require a verified attribute list".into(),
                );
            }
        }
    }
    if record.ads > 0 {
        record.notes.push(format!(
            "{} alternate data streams detected; only unnamed data is listed",
            record.ads
        ));
    }
    Ok(record)
}

#[derive(Clone, Serialize, serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: u64,
    pub name: String,
    pub parent_record: u64,
    #[serde(default)]
    pub parent_sequence: u16,
    #[serde(default)]
    pub parent_ambiguous: bool,
    #[serde(default)]
    pub parent_path: Option<Vec<DirectoryComponent>>,
    pub size: u64,
    pub deleted: bool,
    pub storage: String,
    pub allocation: String,
    pub exportable: bool,
    pub notes: Vec<String>,
    pub fingerprint: String,
    pub created_filetime: Option<String>,
    pub modified_filetime: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryComponent {
    pub record: u64,
    pub name: String,
    pub sequence: u16,
    pub parent_record: u64,
    pub parent_sequence: u16,
}
#[derive(Clone, Debug)]
struct DirectoryReference {
    sequence: u16,
    name: String,
    parent: u64,
    parent_sequence: u16,
    ambiguous: bool,
}
fn resolve_parent_path(
    mut parent: u64,
    mut parent_sequence: u16,
    directories: &BTreeMap<u64, DirectoryReference>,
) -> Option<Vec<DirectoryComponent>> {
    const ROOT_RECORD: u64 = 5;
    const MAX_DIRECTORY_DEPTH: usize = 256;
    let mut visited = std::collections::BTreeSet::new();
    let mut reversed = Vec::new();
    for _ in 0..MAX_DIRECTORY_DEPTH {
        if !visited.insert(parent) {
            return None;
        }
        let directory = directories.get(&parent)?;
        if directory.sequence != parent_sequence {
            return None;
        }
        if directory.ambiguous {
            return None;
        }
        if parent == ROOT_RECORD {
            reversed.reverse();
            reversed.push(DirectoryComponent {
                record: parent,
                name: directory.name.clone(),
                sequence: directory.sequence,
                parent_record: directory.parent,
                parent_sequence: directory.parent_sequence,
            });
            return Some(reversed);
        }
        if directory.name.is_empty() || directory.name == "." || directory.name == ".." {
            return None;
        }
        reversed.push(DirectoryComponent {
            record: parent,
            name: directory.name.clone(),
            sequence: directory.sequence,
            parent_record: directory.parent,
            parent_sequence: directory.parent_sequence,
        });
        parent = directory.parent;
        parent_sequence = directory.parent_sequence;
    }
    None
}
pub struct ScanResult {
    pub boot: Boot,
    pub mft: Stream,
    pub candidates: Vec<Candidate>,
    pub records: u64,
    pub invalid_records: u64,
    pub limited: bool,
    pub cancelled: bool,
}

fn read_record_raw(
    source: &dyn BlockSource,
    boot: &Boot,
    mft: &Stream,
    index: u64,
) -> Result<Record> {
    let mut raw = vec![0; boot.record_size as usize];
    let offset = index
        .checked_mul(boot.record_size)
        .ok_or("Record offset overflow")?;
    mft.read_at(source, boot, offset, &mut raw)?;
    parse_record(&raw, index, boot)
}

pub fn read_record(
    source: &dyn BlockSource,
    boot: &Boot,
    mft: &Stream,
    index: u64,
) -> Result<Record> {
    let mut record = read_record_raw(source, boot, mft, index)?;
    if record.base_reference.is_none() && !record.directory {
        if let Some(attribute_list) = record.attribute_list.clone() {
            let assembled = match attribute_list {
                AttributeList::Resident(bytes) => {
                    parse_attribute_list(&bytes).and_then(|entries| {
                        assemble_unnamed_data(source, boot, mft, &record, &entries)
                    })
                }
                AttributeList::NonResident(attribute) => {
                    read_nonresident_attribute_list(source, boot, mft, &record, &attribute)
                        .and_then(|entries| {
                            assemble_unnamed_data(source, boot, mft, &record, &entries)
                        })
                }
            };
            match assembled {
                Ok(stream) => record.stream = Some(stream),
                Err(reason) => {
                    if let Some(stream) = record.stream.as_mut() {
                        stream.blocked = Some(format!(
                            "Attribute-list stream reconstruction failed: {reason}"
                        ));
                    } else {
                        return Err(format!(
                            "Attribute-list stream reconstruction failed: {reason}"
                        ));
                    }
                    record.notes.push(format!(
                        "Attribute-list stream reconstruction failed: {reason}"
                    ));
                }
            }
        }
    }
    Ok(record)
}
fn allocation(
    source: &dyn BlockSource,
    boot: &Boot,
    bitmap: Option<&Stream>,
    stream: &Stream,
    cancel: &AtomicBool,
) -> Result<String> {
    let Content::Runs(runs) = &stream.content else {
        return Ok("resident".into());
    };
    let Some(bitmap) = bitmap else {
        return Ok("unknown".into());
    };
    let mut budget = 16 * 1024 * 1024usize;
    for run in runs {
        let Some(lcn) = run.lcn else {
            continue;
        };
        let last = lcn + run.clusters - 1;
        let mut start_byte = lcn / 8;
        let end_byte = last / 8;
        while start_byte <= end_byte {
            if cancel.load(Ordering::Relaxed) {
                return Err("Scan cancelled".into());
            }
            let count = (end_byte - start_byte + 1).min(4096) as usize;
            if count > budget {
                return Ok("unknown".into());
            }
            budget -= count;
            if start_byte
                .checked_add(count as u64)
                .is_none_or(|n| n > bitmap.size)
            {
                return Ok("unknown".into());
            }
            let mut b = vec![0; count];
            if bitmap.read_at(source, boot, start_byte, &mut b).is_err() {
                return Ok("unknown".into());
            }
            for (i, value) in b.into_iter().enumerate() {
                let byte = start_byte + i as u64;
                let first = if byte == lcn / 8 { (lcn % 8) as u32 } else { 0 };
                let end = if byte == last / 8 {
                    (last % 8) as u32 + 1
                } else {
                    8
                };
                let mask = (((1u16 << end) - 1) & !((1u16 << first) - 1)) as u8;
                if value & mask != 0 {
                    return Ok("reused".into());
                }
            }
            start_byte += count as u64;
        }
    }
    Ok("unallocated".into())
}

pub fn scan(
    source: &dyn BlockSource,
    offset: u64,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64, usize),
) -> Result<ScanResult> {
    let boot = Boot::read(source, offset)?;
    let mut first = vec![0; boot.record_size as usize];
    source
        .read_exact_at(boot.mft_offset, &mut first)
        .map_err(|e| e.to_string())?;
    let root = parse_record(&first, 0, &boot)?;
    let mft = root
        .stream
        .ok_or("The MFT bootstrap has no unnamed data stream")?;
    if mft.blocked.is_some() || matches!(&mft.content, Content::Resident(_)) {
        return Err(
            "The MFT layout is unsupported (resident, compressed, encrypted, or continued).".into(),
        );
    }
    if let Content::Runs(runs) = &mft.content {
        if runs.iter().any(|r| r.lcn.is_none()) {
            return Err("Sparse MFT mappings are unsupported".into());
        }
    }
    let record_count = mft_record_count(&mft, &boot)?;
    let limit = record_count.min(MAX_RECORDS);
    let bitmap = read_record(source, &boot, &mft, 6)
        .ok()
        .filter(|record| !record.deleted && !record.directory)
        .and_then(|r| r.stream)
        .filter(|s| s.blocked.is_none());
    let mut result = ScanResult {
        boot,
        mft,
        candidates: Vec::new(),
        records: 0,
        invalid_records: 0,
        limited: record_count > limit,
        cancelled: false,
    };
    let mut directories = BTreeMap::new();
    for index in 0..limit {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        match read_record(source, &result.boot, &result.mft, index) {
            Ok(record) => {
                if record.base_reference.is_none()
                    && record.directory
                    && directories.len() < MAX_DIRECTORY_REFERENCES
                {
                    directories.insert(
                        record.number,
                        DirectoryReference {
                            sequence: record.sequence,
                            name: record.name.clone(),
                            parent: record.parent,
                            parent_sequence: record.parent_sequence,
                            ambiguous: record.parent_ambiguous,
                        },
                    );
                } else if record.base_reference.is_none() && record.directory {
                    result.limited = true;
                }
                if index >= 16
                    && record.base_reference.is_none()
                    && record.deleted
                    && !record.directory
                {
                    if let Some(stream) = record.stream {
                        let alloc = match allocation(
                            source,
                            &result.boot,
                            bitmap.as_ref(),
                            &stream,
                            cancel,
                        ) {
                            Ok(v) => v,
                            Err(_) => {
                                result.cancelled = true;
                                break;
                            }
                        };
                        let exportable = stream.blocked.is_none() && alloc != "reused";
                        let mut notes = record.notes;
                        if let Some(reason) = &stream.blocked {
                            notes.push(reason.clone());
                        }
                        if alloc == "reused" {
                            notes.push("At least one referenced cluster is currently allocated; extraction is blocked.".into());
                        }
                        if alloc == "unknown" {
                            notes.push("Allocation state could not be established. Extracted content would be unverified.".into());
                        }
                        if alloc == "unallocated" {
                            notes.push("Extents are currently unallocated; prior overwrites and file content integrity remain unverified.".into());
                        }
                        result.candidates.push(Candidate {
                            id: record.number,
                            name: record.name,
                            parent_record: record.parent,
                            parent_sequence: record.parent_sequence,
                            parent_ambiguous: record.parent_ambiguous,
                            parent_path: None,
                            size: stream.size,
                            deleted: record.deleted,
                            storage: match &stream.content {
                                Content::Resident(_) => "resident",
                                Content::Runs(_) => "nonresident",
                            }
                            .into(),
                            allocation: alloc,
                            exportable,
                            notes,
                            fingerprint: record.fingerprint,
                            created_filetime: record.created,
                            modified_filetime: record.modified,
                        });
                        if result.candidates.len() >= MAX_RESULTS {
                            result.limited = true;
                            result.records = index + 1;
                            break;
                        }
                    }
                }
            }
            Err(_) => result.invalid_records += 1,
        }
        result.records = index + 1;
        if index % 64 == 0 {
            progress(
                result.records * result.boot.record_size,
                result.mft.size,
                result.candidates.len(),
            );
        }
    }
    for candidate in &mut result.candidates {
        candidate.parent_path = if !candidate.parent_ambiguous {
            resolve_parent_path(
                candidate.parent_record,
                candidate.parent_sequence,
                &directories,
            )
        } else {
            None
        };
        if candidate.parent_path.is_none() {
            candidate.notes.push(
                "Original directory path could not be verified from matching NTFS parent sequence references; export will use a flat generated name.".into(),
            );
        }
    }
    progress(
        result.records * result.boot.record_size,
        result.mft.size,
        result.candidates.len(),
    );
    Ok(result)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn directory(
        sequence: u16,
        name: &str,
        parent: u64,
        parent_sequence: u16,
    ) -> DirectoryReference {
        DirectoryReference {
            sequence,
            name: name.into(),
            parent,
            parent_sequence,
            ambiguous: false,
        }
    }

    #[test]
    fn parent_path_requires_a_matching_sequence_at_every_ancestor() {
        let directories = BTreeMap::from([
            (5, directory(4, ".", 5, 4)),
            (30, directory(9, "Exhibit", 5, 4)),
            (31, directory(7, "Nested", 30, 9)),
        ]);
        let path = resolve_parent_path(31, 7, &directories).unwrap();
        assert_eq!(
            path,
            vec![
                DirectoryComponent {
                    record: 30,
                    name: "Exhibit".into(),
                    sequence: 9,
                    parent_record: 5,
                    parent_sequence: 4,
                },
                DirectoryComponent {
                    record: 31,
                    name: "Nested".into(),
                    sequence: 7,
                    parent_record: 30,
                    parent_sequence: 9,
                },
                DirectoryComponent {
                    record: 5,
                    name: ".".into(),
                    sequence: 4,
                    parent_record: 5,
                    parent_sequence: 4,
                },
            ]
        );
        assert!(resolve_parent_path(31, 8, &directories).is_none());

        let stale_ancestor = BTreeMap::from([
            (5, directory(4, ".", 5, 4)),
            (30, directory(10, "Reused slot", 5, 4)),
            (31, directory(7, "Nested", 30, 9)),
        ]);
        assert!(resolve_parent_path(31, 7, &stale_ancestor).is_none());

        let ambiguous = BTreeMap::from([
            (5, directory(4, ".", 5, 4)),
            (
                30,
                DirectoryReference {
                    ambiguous: true,
                    ..directory(9, "Exhibit", 5, 4)
                },
            ),
        ]);
        assert!(resolve_parent_path(30, 9, &ambiguous).is_none());
    }

    #[test]
    fn parent_path_rejects_cycles_and_excessive_depth() {
        let cycle = BTreeMap::from([(30, directory(1, "loop", 30, 1))]);
        assert!(resolve_parent_path(30, 1, &cycle).is_none());

        let too_deep = (0..257)
            .map(|index| {
                (
                    30 + index,
                    directory(1, "directory", if index == 256 { 5 } else { 31 + index }, 1),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(resolve_parent_path(30, 1, &too_deep).is_none());
    }
}
