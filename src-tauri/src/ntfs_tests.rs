use crate::{
    ntfs, recovery,
    storage::{BlockSource, MemorySource},
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

fn resident(kind: u32, value: &[u8]) -> Vec<u8> {
    let len = (24 + value.len() + 7) & !7;
    let mut a = vec![0; len];
    a[..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    a[20..22].copy_from_slice(&24u16.to_le_bytes());
    a[24..24 + value.len()].copy_from_slice(value);
    a
}
fn named_resident(kind: u32, name: &str, value: &[u8]) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let value_offset = (24 + name.len() * 2 + 7) & !7;
    let len = (value_offset + value.len() + 7) & !7;
    let mut a = vec![0; len];
    a[..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    a[9] = name.len() as u8;
    a[10..12].copy_from_slice(&24u16.to_le_bytes());
    a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    a[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        a[24 + index * 2..26 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    a[value_offset..value_offset + value.len()].copy_from_slice(value);
    a
}
fn filename(name: &str) -> Vec<u8> {
    filename_ref(name, 5, 1)
}
fn filename_ref(name: &str, parent: u64, parent_sequence: u16) -> Vec<u8> {
    let chars = name.encode_utf16().collect::<Vec<_>>();
    let mut v = vec![0; 66 + chars.len() * 2];
    let reference = parent | (u64::from(parent_sequence) << 48);
    v[..8].copy_from_slice(&reference.to_le_bytes());
    v[64] = chars.len() as u8;
    v[65] = 1;
    for (i, c) in chars.iter().enumerate() {
        v[66 + i * 2..68 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    resident(0x30, &v)
}
#[test]
fn mft_scan_bounds_use_only_initialized_complete_records() {
    let boot = ntfs::Boot {
        offset: 0,
        sector_size: 512,
        cluster_size: 512,
        record_size: 1024,
        volume_size: 100 * 512,
        mft_offset: 0,
        serial: "test".into(),
    };
    let stream = ntfs::Stream {
        size: 48 * 1024,
        initialized: 40 * 1024,
        content: ntfs::Content::Runs(Vec::new()),
        blocked: None,
    };
    assert_eq!(ntfs::mft_record_count(&stream, &boot).unwrap(), 40);

    let mut malformed = stream.clone();
    malformed.size += 1;
    assert!(ntfs::mft_record_count(&malformed, &boot).is_err());
    let mut malformed = stream.clone();
    malformed.initialized += 1;
    assert!(ntfs::mft_record_count(&malformed, &boot).is_err());
    let mut malformed = stream.clone();
    malformed.size = 102 * 512;
    malformed.initialized = malformed.size;
    assert!(ntfs::mft_record_count(&malformed, &boot).is_err());
    let mut malformed = stream;
    malformed.initialized = malformed.size + 1024;
    assert!(ntfs::mft_record_count(&malformed, &boot).is_err());
}

#[test]
fn conflicting_file_name_parents_are_not_treated_as_a_verified_path() {
    let raw = record(
        31,
        3,
        &[
            filename_ref("Exhibit", 5, 1),
            filename_ref("Alternate", 6, 1),
        ],
    );
    let boot = ntfs::Boot {
        offset: 0,
        sector_size: 512,
        cluster_size: 512,
        record_size: 1024,
        volume_size: 100 * 512,
        mft_offset: 0,
        serial: "test".into(),
    };
    let parsed = ntfs::parse_record(&raw, 31, &boot).unwrap();
    assert!(parsed.parent_ambiguous);
    assert_eq!(parsed.parent, 5);
    assert_eq!(parsed.parent_sequence, 1);
    assert_eq!(
        parsed.filename_references,
        vec![
            ntfs::FilenameReference {
                name: "Exhibit".into(),
                attribute_record: 31,
                attribute_record_sequence: 1,
                parent_record: 5,
                parent_sequence: 1,
                namespace: 1,
                attribute_id: 0,
            },
            ntfs::FilenameReference {
                name: "Alternate".into(),
                attribute_record: 31,
                attribute_record_sequence: 1,
                parent_record: 6,
                parent_sequence: 1,
                namespace: 1,
                attribute_id: 1,
            },
        ]
    );

    let same_directory_links = record(
        31,
        3,
        &[
            filename_ref("first-link", 5, 1),
            filename_ref("second-link", 5, 1),
        ],
    );
    let parsed = ntfs::parse_record(&same_directory_links, 31, &boot).unwrap();
    assert!(parsed.parent_ambiguous);
    assert_eq!(parsed.name, "first-link");
    assert_eq!(parsed.filename_references.len(), 2);
    assert_eq!(parsed.filename_references[0].name, "first-link");
    assert_eq!(parsed.filename_references[1].name, "second-link");

    let mut invalid_namespace = filename("invalid-namespace");
    invalid_namespace[24 + 65] = 4;
    assert!(ntfs::parse_record(&record(31, 0, &[invalid_namespace]), 31, &boot).is_err());

    let mut nonresident_name = filename("nonresident-name");
    nonresident_name[8] = 1;
    assert!(ntfs::parse_record(&record(31, 0, &[nonresident_name]), 31, &boot).is_err());

    let mut named_name = filename("named-name");
    named_name[9] = 1;
    named_name[10] = 24;
    assert!(ntfs::parse_record(&record(31, 0, &[named_name]), 31, &boot).is_err());
}

fn nonresident(runs: &[u8], clusters: u64, size: u64, initialized: u64, flags: u16) -> Vec<u8> {
    nonresident_extent(
        runs,
        0,
        clusters - 1,
        clusters * 512,
        size,
        initialized,
        flags,
    )
}
fn nonresident_extent(
    runs: &[u8],
    lowest_vcn: u64,
    highest_vcn: u64,
    allocated: u64,
    size: u64,
    initialized: u64,
    flags: u16,
) -> Vec<u8> {
    nonresident_attribute(
        0x80,
        runs,
        lowest_vcn,
        highest_vcn,
        allocated,
        size,
        initialized,
        flags,
    )
}
fn nonresident_attribute(
    kind: u32,
    runs: &[u8],
    lowest_vcn: u64,
    highest_vcn: u64,
    allocated: u64,
    size: u64,
    initialized: u64,
    flags: u16,
) -> Vec<u8> {
    let len = (64 + runs.len() + 7) & !7;
    let mut a = vec![0; len];
    a[..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    a[8] = 1;
    a[12..14].copy_from_slice(&flags.to_le_bytes());
    a[16..24].copy_from_slice(&lowest_vcn.to_le_bytes());
    a[24..32].copy_from_slice(&highest_vcn.to_le_bytes());
    a[32..34].copy_from_slice(&64u16.to_le_bytes());
    a[40..48].copy_from_slice(&allocated.to_le_bytes());
    a[48..56].copy_from_slice(&size.to_le_bytes());
    a[56..64].copy_from_slice(&initialized.to_le_bytes());
    a[64..64 + runs.len()].copy_from_slice(runs);
    a
}
fn attribute_list_entry(
    attribute_type: u32,
    lowest_vcn: u64,
    record: u64,
    sequence: u16,
) -> Vec<u8> {
    attribute_list_entry_with_id(attribute_type, lowest_vcn, record, sequence, 0)
}
fn attribute_list_entry_with_id(
    attribute_type: u32,
    lowest_vcn: u64,
    record: u64,
    sequence: u16,
    attribute_id: u16,
) -> Vec<u8> {
    let length = 32;
    let mut entry = vec![0; length];
    entry[..4].copy_from_slice(&attribute_type.to_le_bytes());
    entry[4..6].copy_from_slice(&(length as u16).to_le_bytes());
    entry[8..16].copy_from_slice(&lowest_vcn.to_le_bytes());
    let reference = record | (u64::from(sequence) << 48);
    entry[16..24].copy_from_slice(&reference.to_le_bytes());
    entry[24..26].copy_from_slice(&attribute_id.to_le_bytes());
    entry
}
fn record(index: u32, flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut r = vec![0; 1024];
    r[..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&48u16.to_le_bytes());
    r[6..8].copy_from_slice(&3u16.to_le_bytes());
    r[16..18].copy_from_slice(&1u16.to_le_bytes());
    r[20..22].copy_from_slice(&56u16.to_le_bytes());
    r[22..24].copy_from_slice(&flags.to_le_bytes());
    r[28..32].copy_from_slice(&1024u32.to_le_bytes());
    r[44..48].copy_from_slice(&index.to_le_bytes());
    let mut pos = 56;
    for (attribute_id, a) in attributes.iter().enumerate() {
        r[pos..pos + a.len()].copy_from_slice(a);
        r[pos + 14..pos + 16].copy_from_slice(&(attribute_id as u16).to_le_bytes());
        pos += a.len();
    }
    r[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    r[24..28].copy_from_slice(&((pos + 4) as u32).to_le_bytes());
    r[48..50].copy_from_slice(&0xa55au16.to_le_bytes());
    for i in 1..3 {
        let end = i * 512 - 2;
        let saved = [r[end], r[end + 1]];
        r[48 + i * 2..50 + i * 2].copy_from_slice(&saved);
        r[end..end + 2].copy_from_slice(&0xa55au16.to_le_bytes());
    }
    r
}
fn image() -> MemorySource {
    image_with_attribute_list_layout(false, false)
}

struct VirtualMftSource {
    length: u64,
    mft_start: u64,
    record_count: u64,
    boot: [u8; 512],
    bootstrap: Vec<u8>,
    blank_record: Vec<u8>,
}

impl BlockSource for VirtualMftSource {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        buffer.fill(0);
        let mut cursor = offset;
        while cursor < end {
            if cursor < self.boot.len() as u64 {
                let count = (end - cursor).min(self.boot.len() as u64 - cursor) as usize;
                buffer[(cursor - offset) as usize..(cursor - offset) as usize + count]
                    .copy_from_slice(&self.boot[cursor as usize..cursor as usize + count]);
                cursor += count as u64;
                continue;
            }
            let mft_end = self.mft_start + self.record_count * 1024;
            if cursor >= self.mft_start && cursor < mft_end {
                let index = (cursor - self.mft_start) / 1024;
                let within = (cursor - self.mft_start) % 1024;
                let count = (end - cursor).min(1024 - within) as usize;
                if index == 0 {
                    buffer[(cursor - offset) as usize..(cursor - offset) as usize + count]
                        .copy_from_slice(&self.bootstrap[within as usize..within as usize + count]);
                } else {
                    buffer[(cursor - offset) as usize..(cursor - offset) as usize + count]
                        .copy_from_slice(
                            &self.blank_record[within as usize..within as usize + count],
                        );
                    let number_start = within.max(44);
                    let number_end = (within + count as u64).min(48);
                    if number_start < number_end {
                        let number_bytes = (index as u32).to_le_bytes();
                        let from = (number_start - 44) as usize;
                        let to = (number_end - 44) as usize;
                        let output_start =
                            (cursor - offset) as usize + (number_start - within) as usize;
                        buffer[output_start..output_start + to - from]
                            .copy_from_slice(&number_bytes[from..to]);
                    }
                }
                cursor += count as u64;
                continue;
            }
            let next = if cursor < self.mft_start {
                self.mft_start
            } else {
                end
            };
            cursor = next.min(end);
        }
        Ok(())
    }
}

fn virtual_mft_source(record_count: u64) -> VirtualMftSource {
    let mft_clusters = record_count * 2;
    let mft_bytes = record_count * 1024;
    let volume_sectors = 4 + mft_clusters + 8;
    let mut boot = [0; 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[40..48].copy_from_slice(&volume_sectors.to_le_bytes());
    boot[48..56].copy_from_slice(&4u64.to_le_bytes());
    boot[64] = (-10i8) as u8;
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    let runs = [
        0x13,
        (mft_clusters & 0xff) as u8,
        (mft_clusters >> 8) as u8,
        (mft_clusters >> 16) as u8,
        4,
        0,
    ];
    let bootstrap = record(
        0,
        1,
        &[
            filename("$MFT"),
            nonresident(&runs, mft_clusters, mft_bytes, mft_bytes, 0),
        ],
    );
    VirtualMftSource {
        length: volume_sectors * 512,
        mft_start: 4 * 512,
        record_count,
        boot,
        bootstrap,
        blank_record: record(0, 1, &[]),
    }
}

fn image_with_nonresident_attribute_list(nonresident_list: bool) -> MemorySource {
    image_with_attribute_list_layout(nonresident_list, false)
}
fn image_with_attribute_list_layout(nonresident_list: bool, continued_list: bool) -> MemorySource {
    let mut b = vec![0; 128 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = 1;
    b[40..48].copy_from_slice(&128u64.to_le_bytes());
    b[48..56].copy_from_slice(&4u64.to_le_bytes());
    b[56..64].copy_from_slice(&100u64.to_le_bytes());
    b[64] = (-10i8) as u8;
    b[72..80].copy_from_slice(&123456u64.to_le_bytes());
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    let mut bitmap = vec![0u8; 16];
    for cluster in (4..100)
        .chain([110])
        .chain(nonresident_list.then_some(117))
        .chain(continued_list.then_some(118))
    {
        bitmap[cluster / 8] |= 1 << (cluster % 8);
    }
    for index in 0..48 {
        let attrs = match index {
            0 => vec![
                filename("$MFT"),
                nonresident(&[0x11, 96, 4, 0], 96, 48 * 1024, 48 * 1024, 0),
            ],
            6 => vec![filename("$Bitmap"), resident(0x80, &bitmap)],
            5 => vec![filename_ref(".", 5, 1)],
            16 => vec![
                filename_ref("notes_証拠_🧪_e\u{301}.txt", 30, 1),
                resident(0x80, b"NTFS resident evidence\n"),
            ],
            30 => vec![filename_ref("Exhibit", 5, 1)],
            17 => vec![
                filename("fragmented.bin"),
                nonresident(&[0x11, 1, 104, 0x11, 1, 4, 0], 2, 700, 700, 0),
                named_resident(0x80, "case_note", b"alternate stream fixture"),
            ],
            18 => vec![
                filename("reused.bin"),
                nonresident(&[0x11, 1, 110, 0], 1, 100, 100, 0),
            ],
            19 => vec![
                filename("encrypted.bin"),
                nonresident(&[0x11, 1, 112, 0], 1, 100, 100, 0x4000),
            ],
            20 => vec![
                filename("sparse.bin"),
                nonresident(&[0x11, 1, 112, 0x01, 1, 0], 2, 800, 700, 0x8000),
            ],
            21 => vec![
                filename("continued.bin"),
                resident(0x20, &[0; 8]),
                resident(0x80, b"not a complete continued stream"),
            ],
            22 => {
                let mut list = attribute_list_entry_with_id(0x20, 0, 22, 1, 1);
                if continued_list {
                    list.extend(attribute_list_entry_with_id(0x20, 1, 23, 1, 1));
                }
                list.extend(attribute_list_entry(0x30, 0, 22, 1));
                list.extend(attribute_list_entry_with_id(0x30, 0, 23, 1, 0));
                list.extend(attribute_list_entry_with_id(0x80, 0, 22, 1, 2));
                list.extend(attribute_list_entry_with_id(
                    0x80,
                    1,
                    23,
                    1,
                    if continued_list { 2 } else { 1 },
                ));
                let list_attribute = if nonresident_list {
                    b[117 * 512..117 * 512 + list.len()].copy_from_slice(&list);
                    nonresident_attribute(
                        0x20,
                        &[0x11, 1, 117, 0],
                        0,
                        0,
                        if continued_list { 1024 } else { 512 },
                        if continued_list {
                            700
                        } else {
                            list.len() as u64
                        },
                        if continued_list {
                            700
                        } else {
                            list.len() as u64
                        },
                        0,
                    )
                } else {
                    resident(0x20, &list)
                };
                vec![
                    filename_ref("continued-extents.bin", 30, 1),
                    list_attribute,
                    nonresident_extent(&[0x11, 1, 115, 0], 0, 0, 1024, 700, 700, 0),
                ]
            }
            23 => {
                let mut short_alias = filename_ref("CONTIN~1.BIN", 30, 1);
                short_alias[24 + 65] = 2;
                let mut attributes = vec![short_alias];
                if continued_list {
                    attributes.push(nonresident_attribute(
                        0x20,
                        &[0x11, 1, 118, 0],
                        1,
                        1,
                        0,
                        0,
                        0,
                        0,
                    ));
                }
                attributes.push(nonresident_extent(&[0x11, 1, 120, 0], 1, 1, 0, 0, 0, 0));
                attributes
            }
            _ => vec![],
        };
        let mut raw = record(
            index,
            if (16..=22).contains(&index) {
                0
            } else if index == 5 || index == 30 {
                3
            } else {
                1
            },
            &attrs,
        );
        if index == 23 {
            let base_reference = 22u64 | (1u64 << 48);
            raw[32..40].copy_from_slice(&base_reference.to_le_bytes());
        }
        let start = 4 * 512 + index as usize * 1024;
        b[start..start + 1024].copy_from_slice(&raw);
    }
    b[104 * 512..105 * 512].fill(b'A');
    b[108 * 512..109 * 512].fill(b'B');
    b[112 * 512..113 * 512].fill(b'C');
    b[115 * 512..116 * 512].fill(b'D');
    b[120 * 512..121 * 512].fill(b'E');
    MemorySource(b)
}

fn image_hash(source: &MemorySource) -> String {
    format!("{:x}", Sha256::digest(&source.0))
}
fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::current_dir()
        .unwrap()
        .join("target")
        .join("test-temp")
        .join(format!("daemoncore-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::create_dir(&p).unwrap();
    p
}

#[test]
fn synthetic_ntfs_scan_classifies_real_record_data() {
    let source = image();
    let result = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    assert_eq!(result.records, 48);
    assert_eq!(result.candidates.len(), 7);
    let resident = result.candidates.iter().find(|c| c.id == 16).unwrap();
    assert_eq!(resident.name, "notes_証拠_🧪_e\u{301}.txt");
    assert_eq!(
        resident.filename_references,
        vec![ntfs::FilenameReference {
            name: "notes_証拠_🧪_e\u{301}.txt".into(),
            attribute_record: 16,
            attribute_record_sequence: 1,
            parent_record: 30,
            parent_sequence: 1,
            namespace: 1,
            attribute_id: 0,
        }]
    );
    let continued = result
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap();
    assert!(continued.filename_references.iter().any(|reference| {
        reference.name == "CONTIN~1.BIN"
            && reference.attribute_record == 23
            && reference.attribute_record_sequence == 1
            && reference.namespace == 2
            && reference.attribute_id == 0
    }));
    assert_eq!(
        resident.parent_path,
        Some(vec![
            ntfs::DirectoryComponent {
                record: 30,
                name: "Exhibit".into(),
                sequence: 1,
                parent_record: 5,
                parent_sequence: 1,
            },
            ntfs::DirectoryComponent {
                record: 5,
                name: ".".into(),
                sequence: 1,
                parent_record: 5,
                parent_sequence: 1,
            }
        ])
    );
    assert_eq!(resident.allocation, "resident");
    assert!(resident.exportable);
    let fragmented = result.candidates.iter().find(|c| c.id == 17).unwrap();
    assert_eq!(fragmented.allocation, "unallocated");
    assert!(fragmented
        .notes
        .iter()
        .any(|note| { note == "1 alternate data stream detected; only unnamed data is listed" }));
    assert_eq!(
        result
            .candidates
            .iter()
            .find(|c| c.id == 18)
            .unwrap()
            .allocation,
        "reused"
    );
    assert!(
        !result
            .candidates
            .iter()
            .find(|c| c.id == 18)
            .unwrap()
            .exportable
    );
    assert!(
        !result
            .candidates
            .iter()
            .find(|c| c.id == 19)
            .unwrap()
            .exportable
    );
    assert!(
        !result
            .candidates
            .iter()
            .find(|c| c.id == 21)
            .unwrap()
            .exportable
    );
}

#[test]
fn synthetic_ntfs_scan_traverses_large_virtual_mft_without_materializing_image() {
    let source = virtual_mft_source(100_000);
    let result = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();

    assert_eq!(result.records, 100_000);
    assert_eq!(result.invalid_records, 0);
    assert!(result.candidates.is_empty());
    assert!(!result.limited);
}

#[test]
fn synthetic_ntfs_scan_marks_truncation_at_the_mft_record_cap() {
    let source = virtual_mft_source(1_000_001);
    let result = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();

    assert_eq!(result.records, 1_000_000);
    assert_eq!(result.invalid_records, 0);
    assert!(result.candidates.is_empty());
    assert!(result.limited);
}

#[test]
fn nonresident_reads_cross_fragmented_and_sparse_4k_clusters() {
    let cluster_size = 4096u64;
    let mut source = MemorySource(vec![0; 8 * cluster_size as usize]);
    source.0[2 * cluster_size as usize..3 * cluster_size as usize].fill(b'A');
    source.0[5 * cluster_size as usize..6 * cluster_size as usize].fill(b'B');

    let boot = ntfs::Boot {
        offset: 0,
        sector_size: 512,
        cluster_size,
        record_size: 1024,
        volume_size: source.0.len() as u64,
        mft_offset: 0,
        serial: "test".into(),
    };
    let stream = ntfs::Stream {
        size: 3 * cluster_size,
        initialized: 2 * cluster_size + 512,
        content: ntfs::Content::Runs(vec![
            ntfs::Run {
                vcn: 0,
                clusters: 1,
                lcn: Some(2),
            },
            ntfs::Run {
                vcn: 1,
                clusters: 1,
                lcn: Some(5),
            },
            ntfs::Run {
                vcn: 2,
                clusters: 1,
                lcn: None,
            },
        ]),
        blocked: None,
    };

    let mut boundary = vec![0; 300];
    stream
        .read_at(&source, &boot, cluster_size - 100, &mut boundary)
        .unwrap();
    assert_eq!(&boundary[..100], &[b'A'; 100]);
    assert_eq!(&boundary[100..], &[b'B'; 200]);

    let mut sparse = vec![0xff; 64];
    stream
        .read_at(&source, &boot, 2 * cluster_size + 128, &mut sparse)
        .unwrap();
    assert_eq!(sparse, [0; 64]);
}

#[test]
fn extraction_matches_known_bytes_for_resident_fragmented_and_sparse_files() {
    let source = image();
    let original = Sha256::digest(&source.0);
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let selected = scan
        .candidates
        .iter()
        .filter(|c| [16, 17, 20].contains(&c.id))
        .cloned()
        .collect::<Vec<_>>();
    let directory = temp_dir("roundtrip");
    let summary = recovery::export_to(
        &source,
        &scan,
        &selected,
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(
        summary.exported,
        3,
        "{}",
        std::fs::read_to_string(std::path::Path::new(&summary.directory).join("inventory.jsonl"))
            .unwrap()
    );
    assert_eq!(summary.failed, 0);
    let out = std::path::Path::new(&summary.directory);
    let restored_dir = recovery::safe_name(30, "Exhibit");
    assert_eq!(
        std::fs::read(
            out.join(&restored_dir)
                .join(recovery::safe_name(16, "notes_証拠_🧪_e\u{301}.txt"))
        )
        .unwrap(),
        b"NTFS resident evidence\n"
    );
    let mut fragmented = vec![b'A'; 512];
    fragmented.extend(vec![b'B'; 188]);
    assert_eq!(
        std::fs::read(out.join(recovery::safe_name(17, "fragmented.bin"))).unwrap(),
        fragmented
    );
    let mut sparse = vec![b'C'; 512];
    sparse.extend(vec![0; 288]);
    assert_eq!(
        std::fs::read(out.join(recovery::safe_name(20, "sparse.bin"))).unwrap(),
        sparse
    );
    assert_eq!(Sha256::digest(&source.0), original);
    let inventory = std::fs::read_to_string(out.join("inventory.jsonl")).unwrap();
    assert_eq!(inventory.lines().count(), 3);
    assert!(inventory.contains("destination_hash_verified"));
    let resident_inventory: serde_json::Value = inventory
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .find(|entry: &serde_json::Value| entry["record"] == 16)
        .unwrap();
    let resident_candidate = scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 16)
        .unwrap();
    assert_eq!(
        resident_inventory["filename_references"],
        serde_json::to_value(&resident_candidate.filename_references).unwrap()
    );
    let restored_relative_path = recovery::safe_relative_name(
        16,
        "notes_証拠_🧪_e\u{301}.txt",
        scan.candidates
            .iter()
            .find(|candidate| candidate.id == 16)
            .unwrap()
            .parent_path
            .as_deref(),
    );
    assert_eq!(resident_inventory["output_name"], restored_relative_path);
    assert_eq!(resident_inventory["path_restored"], true);
    let manifest = std::fs::read_to_string(out.join("manifest.json")).unwrap();
    assert!(manifest.contains("sha256_before_export"));
    assert!(manifest.contains("evidence_record_id"));
    assert!(manifest.contains("scan_session_id"));
    assert!(manifest.contains("controlled-fixture.img"));
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let resident_manifest = manifest["selected_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["record"] == 16)
        .unwrap();
    assert_eq!(
        resident_manifest["filename_references"],
        resident_inventory["filename_references"]
    );
    let checksums = std::fs::read_to_string(out.join("checksums.sha256")).unwrap();
    assert!(checksums.contains("manifest.json"));
    assert!(checksums.contains("inventory.jsonl"));
    assert!(checksums.lines().any(|line| {
        line.split_once("  ")
            .is_some_and(|(_, path)| path == restored_relative_path)
    }));
    let completion: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("completion.json")).unwrap()).unwrap();
    assert_eq!(completion["state"], "complete");
    let verified = crate::recovery_verify::verify_package(out).unwrap();
    assert_eq!(verified.state, "complete");
    assert_eq!(verified.records, 3);
    assert_eq!(verified.exported, 3);
    assert_eq!(verified.case_id, Some(1));
    assert_eq!(verified.evidence_record_id, Some(1));
    assert_eq!(verified.scan_session_id, Some(1));
    assert_eq!(verified.failed, 0);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn attribute_list_extents_are_sequence_checked_and_exported_as_one_stream() {
    let source = image();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let candidate = scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap()
        .clone();
    assert_eq!(candidate.size, 700);
    assert!(candidate.exportable, "{:?}", candidate.notes);

    let directory = temp_dir("attribute-list-export");
    let summary = recovery::export_to(
        &source,
        &scan,
        &[candidate.clone()],
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.exported, 1);
    assert_eq!(summary.failed, 0);
    let output = std::path::Path::new(&summary.directory)
        .join(recovery::safe_name(30, "Exhibit"))
        .join(recovery::safe_name(22, "continued-extents.bin"));
    let mut expected = vec![b'D'; 512];
    expected.extend(vec![b'E'; 188]);
    assert_eq!(std::fs::read(output).unwrap(), expected);
    let verified =
        crate::recovery_verify::verify_package(std::path::Path::new(&summary.directory)).unwrap();
    assert_eq!(verified.exported, 1);
    std::fs::remove_dir_all(directory).unwrap();

    let mut stale_source = image();
    let extension_base_reference_offset = 4 * 512 + 23 * 1024 + 32;
    let stale_base_reference = 22u64 | (2u64 << 48);
    stale_source.0[extension_base_reference_offset..extension_base_reference_offset + 8]
        .copy_from_slice(&stale_base_reference.to_le_bytes());
    let stale_scan = ntfs::scan(&stale_source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let stale_candidate = stale_scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap();
    assert!(!stale_candidate.exportable);
    assert!(stale_candidate
        .notes
        .iter()
        .any(|note| note.contains("extension record identity does not match")));

    let file_record_offset = 4 * 512 + 22 * 1024;
    let list_attribute_offset =
        file_record_offset + 56 + filename_ref("continued-extents.bin", 30, 1).len();
    let list_value_offset = list_attribute_offset + 24;
    let extension_entry_offset = list_value_offset + 64;

    let candidate_for = |source: &MemorySource| {
        ntfs::scan(source, 0, &AtomicBool::new(false), |_, _, _| {})
            .unwrap()
            .candidates
            .into_iter()
            .find(|candidate| candidate.id == 22)
            .unwrap()
    };

    let mut stale_list_sequence = image();
    let wrong_extension_sequence = 23u64 | (2u64 << 48);
    stale_list_sequence.0[extension_entry_offset + 16..extension_entry_offset + 24]
        .copy_from_slice(&wrong_extension_sequence.to_le_bytes());
    assert!(!candidate_for(&stale_list_sequence).exportable);

    let mut wrong_vcn = image();
    wrong_vcn.0[extension_entry_offset + 8..extension_entry_offset + 16]
        .copy_from_slice(&2u64.to_le_bytes());
    assert!(!candidate_for(&wrong_vcn).exportable);

    let mut nonresident_list = image();
    nonresident_list.0[list_attribute_offset + 8] = 1;
    assert!(
        !ntfs::scan(&nonresident_list, 0, &AtomicBool::new(false), |_, _, _| {})
            .unwrap()
            .candidates
            .iter()
            .any(|candidate| candidate.id == 22 && candidate.exportable)
    );
}

#[test]
fn whole_image_fuzz_seeds_scan_and_resolve_attribute_lists() {
    let seeds: &[(&str, &[u8])] = &[
        (
            "resident attribute list",
            include_bytes!("../fuzz/corpus/ntfs_scan_image/resident_attribute_list.img"),
        ),
        (
            "nonresident attribute list",
            include_bytes!("../fuzz/corpus/ntfs_scan_image/nonresident_attribute_list.img"),
        ),
        (
            "continued nonresident attribute list",
            include_bytes!("../fuzz/corpus/ntfs_scan_image/continued_attribute_list.img"),
        ),
    ];

    for (description, bytes) in seeds {
        let source = MemorySource(bytes.to_vec());
        let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
        let candidate = scan
            .candidates
            .iter()
            .find(|candidate| candidate.id == 22)
            .unwrap_or_else(|| panic!("missing attribute-list candidate in {description}"));
        assert!(candidate.exportable, "{description}: {:?}", candidate.notes);
        assert_eq!(candidate.size, 700, "{description}");
    }
}

#[test]
fn attribute_list_data_reference_must_match_attribute_instance_id() {
    let mut source = image();
    let record_offset = 4 * 512 + 22 * 1024;
    let list_offset = record_offset + 56 + filename_ref("continued-extents.bin", 30, 1).len();
    // The base unnamed-data entry follows the list attribute and both filename entries.
    let data_entry_attribute_id = list_offset + 24 + 3 * 32 + 24;
    source.0[data_entry_attribute_id..data_entry_attribute_id + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    assert!(!scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));

    let mut wrong_filename_reference = image();
    let extension_name_id = list_offset + 24 + 2 * 32 + 24;
    wrong_filename_reference.0[extension_name_id..extension_name_id + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    let scan = ntfs::scan(
        &wrong_filename_reference,
        0,
        &AtomicBool::new(false),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));
}

#[test]
fn bounded_nonresident_attribute_list_stream_resolves_and_rejects_bad_mapping() {
    let source = image_with_nonresident_attribute_list(true);
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let candidate = scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap();
    assert!(candidate.exportable, "{:?}", candidate.notes);

    let directory = temp_dir("nonresident-attribute-list-export");
    let summary = recovery::export_to(
        &source,
        &scan,
        &[candidate.clone()],
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let output = std::path::Path::new(&summary.directory)
        .join(recovery::safe_name(30, "Exhibit"))
        .join(recovery::safe_name(22, "continued-extents.bin"));
    let mut expected = vec![b'D'; 512];
    expected.extend(vec![b'E'; 188]);
    assert_eq!(std::fs::read(output).unwrap(), expected);
    crate::recovery_verify::verify_package(std::path::Path::new(&summary.directory)).unwrap();
    std::fs::remove_dir_all(directory).unwrap();

    let mut invalid_mapping = image_with_nonresident_attribute_list(true);
    let file_record_offset = 4 * 512 + 22 * 1024;
    let list_attribute_offset =
        file_record_offset + 56 + filename_ref("continued-extents.bin", 30, 1).len();
    invalid_mapping.0[list_attribute_offset + 66] = 99;
    let invalid_scan =
        ntfs::scan(&invalid_mapping, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let invalid_candidate = invalid_scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap();
    assert!(!invalid_candidate.exportable);

    let mut oversized = image_with_nonresident_attribute_list(true);
    let oversized_length = 16 * 1024 * 1024 + 1u64;
    oversized.0[list_attribute_offset + 48..list_attribute_offset + 56]
        .copy_from_slice(&oversized_length.to_le_bytes());
    oversized.0[list_attribute_offset + 56..list_attribute_offset + 64]
        .copy_from_slice(&oversized_length.to_le_bytes());
    let oversized_scan = ntfs::scan(&oversized, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    assert!(!oversized_scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));

    let mut partially_initialized = image_with_nonresident_attribute_list(true);
    partially_initialized.0[list_attribute_offset + 56..list_attribute_offset + 64]
        .copy_from_slice(&64u64.to_le_bytes());
    let partial_scan = ntfs::scan(
        &partially_initialized,
        0,
        &AtomicBool::new(false),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!partial_scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));

    let mut unsupported_flags = image_with_nonresident_attribute_list(true);
    unsupported_flags.0[list_attribute_offset + 12..list_attribute_offset + 14]
        .copy_from_slice(&0x0100u16.to_le_bytes());
    let unsupported_scan =
        ntfs::scan(&unsupported_flags, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    assert!(!unsupported_scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));
}

#[test]
fn continued_nonresident_attribute_list_resolves_through_extension_record() {
    let source = image_with_attribute_list_layout(true, true);
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let candidate = scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 22)
        .unwrap();
    assert!(candidate.exportable, "{:?}", candidate.notes);
    assert!(candidate.filename_references.iter().any(|reference| {
        reference.name == "CONTIN~1.BIN"
            && reference.attribute_record == 23
            && reference.attribute_record_sequence == 1
            && reference.namespace == 2
            && reference.attribute_id == 0
    }));

    let directory = temp_dir("continued-nonresident-attribute-list");
    let summary = recovery::export_to(
        &source,
        &scan,
        &[candidate.clone()],
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let output = std::path::Path::new(&summary.directory)
        .join(recovery::safe_name(30, "Exhibit"))
        .join(recovery::safe_name(22, "continued-extents.bin"));
    let mut expected = vec![b'D'; 512];
    expected.extend(vec![b'E'; 188]);
    assert_eq!(std::fs::read(output).unwrap(), expected);
    crate::recovery_verify::verify_package(std::path::Path::new(&summary.directory)).unwrap();
    std::fs::remove_dir_all(directory).unwrap();

    let mut stale_continuation = image_with_attribute_list_layout(true, true);
    let extension_reference = 23u64 | (2u64 << 48);
    stale_continuation.0[117 * 512 + 32 + 16..117 * 512 + 32 + 24]
        .copy_from_slice(&extension_reference.to_le_bytes());
    let stale_scan = ntfs::scan(
        &stale_continuation,
        0,
        &AtomicBool::new(false),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!stale_scan
        .candidates
        .iter()
        .any(|candidate| candidate.id == 22 && candidate.exportable));
}

#[test]
fn overlong_verified_paths_export_flat_with_audited_path_decision() {
    let source = image();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let mut candidate = scan
        .candidates
        .iter()
        .find(|candidate| candidate.id == 16)
        .unwrap()
        .clone();
    let mut parent_path = (0..12)
        .map(|index| ntfs::DirectoryComponent {
            record: 30 + index,
            name: "long-directory-name-".repeat(6),
            sequence: 1,
            parent_record: if index == 11 { 5 } else { 31 + index },
            parent_sequence: 1,
        })
        .collect::<Vec<_>>();
    parent_path.push(ntfs::DirectoryComponent {
        record: 5,
        name: ".".into(),
        sequence: 1,
        parent_record: 5,
        parent_sequence: 1,
    });
    candidate.parent_path = Some(parent_path);
    let directory = temp_dir("long-path-fallback");
    let summary = recovery::export_to(
        &source,
        &scan,
        &[candidate.clone()],
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let export = std::path::Path::new(&summary.directory);
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(export.join("inventory.jsonl")).unwrap()).unwrap();
    assert_eq!(
        inventory["output_name"],
        recovery::safe_name(candidate.id, &candidate.name)
    );
    assert_eq!(inventory["path_restored"], false);
    let verified = crate::recovery_verify::verify_package(export).unwrap();
    assert_eq!(verified.exported, 1);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cancelled_exports_leave_no_partial_or_published_file() {
    let source = image();
    let source_len = source.len();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let selected = vec![scan.candidates.iter().find(|c| c.id == 17).unwrap().clone()];
    let directory = temp_dir("cancel");
    let cancel = AtomicBool::new(false);
    let summary = recovery::export_to(
        &source,
        &scan,
        &selected,
        &directory,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &cancel,
        |processed, _| {
            if processed > source_len {
                cancel.store(true, Ordering::Relaxed);
            }
        },
    )
    .unwrap();
    assert!(summary.cancelled);
    assert_eq!(summary.exported, 0);
    let names = std::fs::read_dir(&summary.directory)
        .unwrap()
        .map(|p| p.unwrap().file_name().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert!(!names
        .iter()
        .any(|n| n.ends_with(".partial") || n.ends_with("fragmented.bin")));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn changed_source_is_rejected_before_creating_recovery_output() {
    let mut source = image();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let candidate = scan.candidates.iter().find(|c| c.id == 17).unwrap().clone();
    let original_hash = image_hash(&source);
    source.0[2000] ^= 0x80;
    let destination = temp_dir("changed-source");
    let result = recovery::export_to(
        &source,
        &scan,
        &[candidate],
        &destination,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &original_hash,
        },
        &AtomicBool::new(false),
        |_, _| {},
    );
    assert!(result
        .unwrap_err()
        .contains("Source SHA-256 changed before export"));
    assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    std::fs::remove_dir_all(destination).unwrap();
}

#[test]
fn torn_records_bad_run_offsets_and_negative_lcns_are_rejected() {
    let source = image();
    let boot = ntfs::Boot::read(&source, 0).unwrap();
    let mut torn = record(16, 0, &[filename("bad.txt"), resident(0x80, b"x")]);
    torn[510] ^= 1;
    assert!(ntfs::parse_record(&torn, 16, &boot).is_err());
    let mut attr = nonresident(&[0x11, 1, 104, 0], 1, 10, 10, 0);
    attr[32..34].copy_from_slice(&65535u16.to_le_bytes());
    assert!(ntfs::parse_record(&record(16, 0, &[filename("bad.txt"), attr]), 16, &boot).is_err());
    assert!(ntfs::decode_runs(&[0x11, 1, 0xff, 0], &boot, 0).is_err());
    let runs = ntfs::decode_runs(&[0x11, 1, 108, 0x11, 1, 0xfc, 0], &boot, 1).unwrap();
    assert_eq!(runs[1].lcn, Some(104));
}

#[test]
fn mft_update_sequence_stride_remains_512_bytes_on_4k_sector_volumes() {
    let boot = ntfs::Boot {
        offset: 0,
        sector_size: 4096,
        cluster_size: 4096,
        record_size: 1024,
        volume_size: 4096 * 128,
        mft_offset: 4 * 4096,
        serial: "4kn-test".into(),
    };
    let valid = record(16, 0, &[filename("four-kn.bin"), resident(0x80, b"known")]);
    let parsed = ntfs::parse_record(&valid, 16, &boot).unwrap();
    assert_eq!(parsed.name, "four-kn.bin");
    assert!(matches!(
        parsed.stream.map(|stream| stream.content),
        Some(ntfs::Content::Resident(value)) if value == b"known"
    ));

    let mut torn = valid;
    torn[510] ^= 1;
    assert!(ntfs::parse_record(&torn, 16, &boot).is_err());
}

#[test]
fn randomized_binary_inputs_do_not_panic() {
    let source = image();
    let boot = ntfs::Boot::read(&source, 0).unwrap();
    let mut seed = 0x5eed_u64;
    for size in (0..4096).step_by(13) {
        let mut b = vec![0; size];
        for byte in &mut b {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        assert!(std::panic::catch_unwind(|| ntfs::parse_record(&b, 16, &boot)).is_ok());
        let memory = MemorySource(b);
        assert!(std::panic::catch_unwind(|| ntfs::Boot::read(&memory, 0)).is_ok());
    }
}

#[test]
fn cancellation_and_source_bounds_are_enforced() {
    let source = image();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(true), |_, _, _| {}).unwrap();
    assert!(scan.cancelled);
    assert!(scan.candidates.is_empty());
    assert!(ntfs::Boot::read(&source, source.len() - 1).is_err());
}

#[test]
fn independently_formatted_ntfs_fixture_matches_upstream_known_contents() {
    let source = MemorySource(include_bytes!("../tests/fixtures/ntfs-testfs1.img").to_vec());
    assert_eq!(
        format!("{:x}", Sha256::digest(&source.0)),
        "e3612c182b8010e3599b5eb93bff427c7d824e85bdc2ddbe46e378e3ba814eb9"
    );
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let mut found = 0;
    for id in 0..scan.mft.size / scan.boot.record_size {
        let Ok(record) = ntfs::read_record(&source, &scan.boot, &scan.mft, id) else {
            continue;
        };
        let expected = match record.name.as_str() {
            "file-with-12345" => Some(b"12345".to_vec()),
            "1000-bytes-file" => Some(b"12345".repeat(200)),
            "sparse-file" => {
                let mut b = vec![0; 500005];
                b[..5].copy_from_slice(b"12345");
                b[500000..].copy_from_slice(b"11111");
                Some(b)
            }
            _ => None,
        };
        if let Some(expected) = expected {
            let stream = record.stream.unwrap();
            let mut actual = vec![0; stream.size as usize];
            stream.read_at(&source, &scan.boot, 0, &mut actual).unwrap();
            assert_eq!(
                actual, expected,
                "independent content mismatch for {}",
                record.name
            );
            found += 1;
        }
    }
    assert_eq!(found, 3);
}

#[test]
#[ignore = "requires an independently formatted and deleted NTFS image cross-checked with Sleuth Kit"]
fn exports_contiguous_and_fragmented_deleted_ntfs_files_against_sleuthkit_bytes() {
    let image_path = std::env::var_os("DAEMONCORE_NTFS_DELETED_IMAGE")
        .expect("set DAEMONCORE_NTFS_DELETED_IMAGE to the independent NTFS image");
    let expected_path = std::env::var_os("DAEMONCORE_NTFS_DELETED_EXPECTED")
        .expect("set DAEMONCORE_NTFS_DELETED_EXPECTED to original file bytes");
    let image_path = std::path::PathBuf::from(image_path);
    let expected = std::fs::read(expected_path).expect("read independently recovered bytes");
    assert_eq!(expected.len(), 65_536);
    assert_eq!(
        format!("{:x}", Sha256::digest(&expected)),
        "6fc179cfd193754e6109ad043f56d146c7e7d7c3623ffceae318266286f58388"
    );

    let source = crate::storage::Image::open(&image_path).expect("open independent NTFS image");
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {})
        .expect("scan independently formatted NTFS volume");
    let selected_names = ["RECOVER.BIN", "RECOVER_FRAGMENTED.BIN"];
    let selected = scan
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.deleted
                && selected_names
                    .iter()
                    .any(|name| candidate.name.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), selected_names.len());
    for candidate in &selected {
        assert!(
            candidate.exportable,
            "{} blocked: {:?}",
            candidate.name, candidate.notes
        );
        assert_eq!(candidate.size as usize, expected.len());
    }

    let fragmented = selected
        .iter()
        .find(|candidate| {
            candidate
                .name
                .eq_ignore_ascii_case("RECOVER_FRAGMENTED.BIN")
        })
        .expect("find fragmented deleted candidate");
    let record = ntfs::read_record(&source, &scan.boot, &scan.mft, fragmented.id)
        .expect("read fragmented deleted MFT record");
    let stream = record.stream.expect("fragmented file has a data stream");
    let ntfs::Content::Runs(runs) = stream.content else {
        panic!("fragmented file should use a nonresident stream");
    };
    assert!(
        runs.windows(2)
            .any(|pair| match (pair[0].lcn, pair[1].lcn) {
                (Some(previous), Some(next)) => {
                    previous.checked_add(pair[0].clusters) != Some(next)
                }
                _ => false,
            }),
        "fixture file must contain non-adjacent NTFS data runs: {runs:?}"
    );

    let digest = crate::hash_source(&source, &AtomicBool::new(false), |_| {})
        .expect("hash independent NTFS image")
        .expect("hash completes");
    let source_path = image_path.to_string_lossy().into_owned();
    let root = temp_dir("ntfs-independent-deleted-export");
    let summary = recovery::export_to(
        &source,
        &scan,
        &selected,
        &root,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: &source_path,
            sha256: &digest,
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .expect("export independently verified deleted NTFS files");

    assert_eq!(summary.exported, 2);
    assert_eq!(summary.failed, 0);
    let package = std::path::PathBuf::from(&summary.directory);
    let verification = crate::recovery_verify::verify_package(&package)
        .expect("native package verifier accepts the recovery output");
    assert_eq!(verification.state, "complete");
    assert_eq!(verification.exported, 2);
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(package.join("manifest.json")).expect("read package manifest"),
    )
    .expect("parse package manifest");
    for name in selected_names {
        let selected_record = manifest["selected_records"]
            .as_array()
            .expect("manifest lists selected records")
            .iter()
            .find(|record| record["original_name"].as_str() == Some(name))
            .expect("manifest contains selected deleted file");
        let output_name = selected_record["output_name"]
            .as_str()
            .expect("manifest records recovered output path");
        assert_eq!(
            std::fs::read(package.join(output_name)).expect("read exported NTFS bytes"),
            expected,
            "exported bytes for {name}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "writes a controlled fixture only when an explicit output path is supplied"]
fn emit_controlled_fixture_for_desktop_smoke() {
    use std::io::Write;
    let path =
        std::env::var_os("DAEMONCORE_FIXTURE_OUTPUT").expect("set DAEMONCORE_FIXTURE_OUTPUT");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(&image().0).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "writes three controlled NTFS parser fuzz seeds to an explicit directory"]
fn emit_ntfs_fuzz_seeds() {
    use std::io::Write;
    let directory = std::env::var_os("DAEMONCORE_FUZZ_SEED_DIRECTORY")
        .expect("set DAEMONCORE_FUZZ_SEED_DIRECTORY");
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    for (name, source) in [
        ("resident_attribute_list.img", image()),
        (
            "nonresident_attribute_list.img",
            image_with_nonresident_attribute_list(true),
        ),
        (
            "continued_attribute_list.img",
            image_with_attribute_list_layout(true, true),
        ),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .unwrap();
        file.write_all(&source.0).unwrap();
        file.sync_all().unwrap();
    }
}

#[test]
fn reused_cluster_candidate_is_never_published() {
    let source = image();
    let scan = ntfs::scan(&source, 0, &AtomicBool::new(false), |_, _, _| {}).unwrap();
    let candidate = scan.candidates.iter().find(|c| c.id == 18).unwrap().clone();
    let root = temp_dir("reused");
    let summary = recovery::export_to(
        &source,
        &scan,
        &[candidate],
        &root,
        recovery::SourceIdentity {
            case_id: 1,
            evidence_record_id: 1,
            scan_session_id: 1,
            id: 1,
            path: "controlled-fixture.img",
            sha256: &image_hash(&source),
        },
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.exported, 0);
    assert_eq!(summary.failed, 1);
    assert!(!std::path::Path::new(&summary.directory)
        .join(recovery::safe_name(18, "reused.bin"))
        .exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn near_valid_record_mutations_are_bounded_and_do_not_panic() {
    let source = image();
    let boot = ntfs::Boot::read(&source, 0).unwrap();
    let valid = record(
        16,
        0,
        &[
            filename("boundary.txt"),
            nonresident(&[0x11, 1, 104, 0x11, 1, 4, 0], 2, 700, 700, 0),
        ],
    );
    for offset in 8..450 {
        let mut damaged = valid.clone();
        damaged[offset] ^= 0xff;
        assert!(
            std::panic::catch_unwind(|| ntfs::parse_record(&damaged, 16, &boot)).is_ok(),
            "parser panic at offset {offset}"
        );
    }
}

#[test]
fn randomized_multi_byte_and_truncated_records_do_not_panic() {
    let source = image();
    let boot = ntfs::Boot::read(&source, 0).unwrap();
    let valid = record(
        16,
        0,
        &[
            filename("mutation-corpus.bin"),
            nonresident(&[0x11, 1, 104, 0x11, 1, 4, 0], 2, 700, 700, 0),
        ],
    );

    // Deterministic structural mutations make failures reproducible without
    // replacing a coverage-guided fuzzing campaign.
    let mut state = 0x7a11_c0de_51a7_u64;
    for trial in 0..6144 {
        let mut damaged = valid.clone();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mutations = 1 + (state as usize & 7);
        for _ in 0..mutations {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let offset = state as usize % damaged.len();
            let mask = ((state >> 32) as u8).max(1);
            damaged[offset] ^= mask;
        }
        if trial % 5 == 0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            damaged.truncate(state as usize % (damaged.len() + 1));
        }
        assert!(
            std::panic::catch_unwind(|| ntfs::parse_record(&damaged, 16, &boot)).is_ok(),
            "parser panicked on deterministic multi-byte mutation {trial}"
        );
    }
}
