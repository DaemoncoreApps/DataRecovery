use crate::{
    audit, err,
    ntfs::{DirectoryComponent, FilenameReference},
    recovery::{safe_name, safe_relative_name},
    AppState, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use tauri::State;

const MAX_ENTRIES: usize = 1005;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_INVENTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKSUMS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EXPORT_RELATIVE_PATH_UTF16: usize = 1024;
const MAX_FILENAME_REFERENCES: usize = 1024;
const MAX_ACQUISITION_ERROR_MAP_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ACQUISITION_ERROR_RANGES: usize = 100_000;

#[derive(Debug, Serialize)]
pub struct RecoveryExportVerification {
    pub package_type: String,
    pub case_id: Option<i64>,
    pub evidence_record_id: Option<i64>,
    pub scan_session_id: Option<i64>,
    pub records: usize,
    pub exported: usize,
    pub failed: usize,
    pub cancelled: bool,
    pub state: String,
    pub checksums_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportSummary {
    directory: String,
    exported: usize,
    failed: usize,
    cancelled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionMarker {
    state: String,
    checksums_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportManifest {
    tool: String,
    version: String,
    hash_algorithm: String,
    export_started_unix_ns: String,
    source: ManifestSource,
    volume: serde_json::Value,
    selected_records: Vec<SelectedRecord>,
    state: String,
    content_validation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSource {
    case_id: Option<i64>,
    evidence_record_id: Option<i64>,
    scan_session_id: Option<i64>,
    session_id: u64,
    path: String,
    size: u64,
    sha256_before_export: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedRecord {
    record: u64,
    name: String,
    parent_record: u64,
    parent_sequence: Option<u16>,
    #[serde(default)]
    parent_path: Option<Vec<DirectoryComponent>>,
    #[serde(default)]
    filename_references: Vec<FilenameReference>,
    #[serde(default)]
    output_name: Option<String>,
    #[serde(default)]
    path_restored: Option<bool>,
    size: u64,
    storage: String,
    allocation: String,
    record_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRecord {
    record: u64,
    parent_record: Option<u64>,
    parent_sequence: Option<u16>,
    original_name: String,
    #[serde(default)]
    filename_references: Vec<FilenameReference>,
    output_name: Option<String>,
    #[serde(default)]
    path_restored: Option<bool>,
    size: u64,
    sha256: Option<String>,
    all_zero: Option<bool>,
    status: String,
    error: Option<String>,
    content_validation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveManifest {
    tool: String,
    version: String,
    package_type: String,
    hash_algorithm: String,
    created_unix_ns: String,
    source: CarveSource,
    selected_candidates: Vec<CarveCandidate>,
    recovery_scope: String,
    completion: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveSource {
    case_id: i64,
    evidence_record_id: i64,
    scan_session_id: i64,
    source_id: u64,
    path: String,
    size: u64,
    sha256_before_export: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveCandidate {
    offset: u64,
    length: u64,
    format: String,
    sha256: String,
    validation: String,
    output_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveInventory {
    scan_session_id: i64,
    offset: u64,
    length: u64,
    format: String,
    output_name: Option<String>,
    source_sha256: String,
    output_sha256: Option<String>,
    validation: String,
    status: String,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveSummary {
    directory: String,
    exported: usize,
    failed: usize,
    cancelled: bool,
    source_sha256_after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionManifest {
    tool: String,
    version: String,
    package_type: String,
    case_id: i64,
    created_unix_ns: String,
    device_number: u32,
    device_identity: crate::acquisition::PhysicalDevice,
    source_size_bytes: u64,
    bytes_per_sector: u32,
    retries_per_range: u8,
    hardware_write_blocker_attested: bool,
    acquisition_method: String,
    image_name: String,
    image_sha256: String,
    read_error_ranges: usize,
    limitations: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionCompletion {
    state: String,
    image_sha256: String,
    checksums_sha256: String,
    read_error_ranges: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionReadError {
    offset: u64,
    length: u64,
    attempts: u8,
    error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RaidManifest {
    tool: String,
    version: String,
    package_type: String,
    case_id: i64,
    created_unix_ns: String,
    level: String,
    member_order_is_operator_supplied: bool,
    members: Vec<RaidMemberManifest>,
    data_offset_bytes: u64,
    bytes_per_sector: u32,
    stripe_size_bytes: Option<u64>,
    reconstructed_size_bytes: u64,
    image_name: String,
    image_sha256: String,
    layout_method: String,
    limitations: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RaidMemberManifest {
    order: usize,
    path: String,
    image_size_bytes: u64,
    image_sha256: String,
    data_offset_bytes: u64,
    data_size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RaidCompletion {
    state: String,
    image_sha256: String,
    checksums_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarveCompletion {
    state: String,
    checksums_sha256: String,
    source_sha256_before: String,
    source_sha256_after: Option<String>,
}

fn read_bounded(
    directory: &Path,
    name: &str,
    maximum: u64,
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<Vec<u8>> {
    let path = directory.join(name);
    let before = fs::symlink_metadata(&path).map_err(err)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > maximum {
        return Err(format!(
            "Recovery package entry {name} is not a bounded regular file."
        ));
    }
    let mut file = crate::safe_file::open_regular_file(&path).map_err(err)?;
    let opened = file.metadata().map_err(err)?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(format!(
            "Recovery package entry {name} changed while opening."
        ));
    }
    let initial_length = opened.len();
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() as u64 > maximum {
        return Err(format!(
            "Recovery package entry {name} exceeds its verification limit."
        ));
    }
    if file.metadata().map_err(err)?.len() != initial_length || bytes.len() as u64 != initial_length
    {
        return Err(format!(
            "Recovery package entry {name} changed while being read."
        ));
    }
    locks.retain_file(file);
    Ok(bytes)
}

fn hash_regular_file(
    path: &Path,
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<(String, u64)> {
    let before = fs::symlink_metadata(path).map_err(err)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(format!(
            "Recovery package entry {} is not a regular file.",
            path.display()
        ));
    }
    let mut file = crate::safe_file::open_regular_file(path).map_err(err)?;
    let opened = file.metadata().map_err(err)?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(format!(
            "Recovery package entry {} changed while opening.",
            path.display()
        ));
    }
    let initial_length = opened.len();
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut count = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(err)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or("Recovery package file size overflow")?;
        digest.update(&buffer[..read]);
    }
    if file.metadata().map_err(err)?.len() != initial_length || count != initial_length {
        return Err(format!(
            "Recovery package entry {} changed while being read.",
            path.display()
        ));
    }
    locks.retain_file(file);
    Ok((format!("{:x}", digest.finalize()), count))
}

fn validate_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_filename_references(references: &[FilenameReference]) -> bool {
    references.len() <= MAX_FILENAME_REFERENCES
        && references.iter().all(|reference| {
            reference.attribute_record <= 0x0000_ffff_ffff_ffff
                && reference.parent_record <= 0x0000_ffff_ffff_ffff
                && reference.name.encode_utf16().count() <= 255
                && reference.namespace <= 3
        })
}

fn safe_relative_package_path(name: &str) -> bool {
    let components = name.split('/').collect::<Vec<_>>();
    !components.is_empty()
        && components.len() <= 257
        && components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && component.encode_utf16().count() <= 255
                && !component
                    .chars()
                    .any(|c| c.is_control() || "<>:\"\\|?*".contains(c))
                && !component.ends_with([' ', '.'])
        })
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}

fn valid_parent_path(
    parent_record: u64,
    parent_sequence: Option<u16>,
    path: Option<&[DirectoryComponent]>,
) -> bool {
    path.is_none_or(|components| {
        let Some(parent_sequence) = parent_sequence else {
            return false;
        };
        let Some(first) = components.first() else {
            return false;
        };
        let Some(root) = components.last() else {
            return false;
        };
        components.len() <= 257
            && first.record == parent_record
            && first.sequence == parent_sequence
            && root.record == 5
            && root.name == "."
            && root.parent_record == 5
            && root.parent_sequence == root.sequence
            && components.iter().all(|part| {
                part.record > 0
                    && !part.name.is_empty()
                    && if part.record == 5 {
                        part.name == "."
                    } else {
                        part.name != "." && part.name != ".."
                    }
            })
            && components.windows(2).all(|pair| {
                pair[0].parent_record == pair[1].record
                    && pair[0].parent_sequence == pair[1].sequence
            })
            && components
                .iter()
                .map(|part| part.record)
                .collect::<BTreeSet<_>>()
                .len()
                == components.len()
    })
}

fn parse_checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| format!("Checksum manifest is not UTF-8: {e}"))?;
    let mut checksums = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or("Malformed recovery checksum entry.")?;
        if !validate_hex_digest(digest)
            || name.is_empty()
            || !safe_relative_package_path(name)
            || matches!(name, "checksums.sha256" | "completion.json")
            || checksums
                .insert(name.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err("Malformed or duplicate recovery checksum entry.".into());
        }
        if checksums.len() > MAX_ENTRIES {
            return Err("Recovery package contains too many checksum entries.".into());
        }
    }
    Ok(checksums)
}

fn enumerate_entries(
    directory: &Path,
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((folder, relative)) = pending.pop() {
        locks
            .retain_directory(&folder)
            .map_err(|error| format!("Unable to lock recovery package directory: {error}"))?;
        for entry in fs::read_dir(folder).map_err(err)? {
            let entry = entry.map_err(err)?;
            let file_type = entry.file_type().map_err(err)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(err)?;
            let component = entry
                .file_name()
                .into_string()
                .map_err(|_| "Recovery package contains a non-UTF-8 entry name.")?;
            let name = if relative.is_empty() {
                component
            } else {
                format!("{relative}/{component}")
            };
            if !safe_relative_package_path(&name)
                || file_type.is_symlink()
                || is_reparse_point(&metadata)
            {
                return Err(format!("Unexpected recovery package entry: {name}"));
            }
            if file_type.is_dir() {
                directories.insert(name.clone());
                pending.push((entry.path(), name));
                if directories.len() > 100_000 {
                    return Err("Recovery package contains too many directories.".into());
                }
            } else if file_type.is_file() {
                files.insert(name);
                if files.len() > MAX_ENTRIES {
                    return Err("Recovery package contains too many files.".into());
                }
            } else {
                return Err(format!("Unexpected recovery package entry: {name}"));
            }
        }
    }
    Ok((files, directories))
}

fn verify_carve_package(
    directory: &Path,
    entries: BTreeSet<String>,
    directories: BTreeSet<String>,
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<RecoveryExportVerification> {
    let manifest_bytes = read_bounded(directory, "manifest.json", MAX_METADATA_BYTES, locks)?;
    let inventory_bytes = read_bounded(directory, "inventory.jsonl", MAX_INVENTORY_BYTES, locks)?;
    let summary_bytes = read_bounded(directory, "summary.json", MAX_METADATA_BYTES, locks)?;
    let checksums_bytes = read_bounded(directory, "checksums.sha256", MAX_CHECKSUMS_BYTES, locks)?;
    let completion_bytes = read_bounded(directory, "completion.json", MAX_METADATA_BYTES, locks)?;
    let manifest: CarveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Invalid carving manifest: {error}"))?;
    let summary: CarveSummary = serde_json::from_slice(&summary_bytes)
        .map_err(|error| format!("Invalid carving summary: {error}"))?;
    let completion: CarveCompletion = serde_json::from_slice(&completion_bytes)
        .map_err(|error| format!("Invalid carving completion marker: {error}"))?;
    let created = manifest
        .created_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid carving package timestamp.")?;
    if manifest.tool != "DaemonCore Data Recovery"
        || manifest.version.is_empty()
        || manifest.package_type != "signature_carving"
        || manifest.hash_algorithm != "SHA-256"
        || !matches!(manifest.recovery_scope.as_str(),
            "PNG file bytes were carved from a raw image and decoded. Original filename, directory, timestamps, allocation state, and deletion status are unknown."
                | "Supported file bytes were carved from a raw image and validated using their format-specific checks. Original filename, directory, timestamps, allocation state, and deletion status are unknown.")
        || manifest.completion != "Treat this package as incomplete unless completion.json exists and verifies."
        || created == 0
        || manifest.source.case_id <= 0
        || manifest.source.evidence_record_id <= 0
        || manifest.source.scan_session_id <= 0
        || manifest.source.source_id == 0
        || manifest.source.path.is_empty()
        || manifest.source.size == 0
        || !validate_hex_digest(&manifest.source.sha256_before_export)
        || manifest.selected_candidates.is_empty()
        || manifest.selected_candidates.len() > 1000
    {
        return Err("Unsupported or inconsistent carving manifest metadata.".into());
    }

    let canonical = directory.canonicalize().map_err(err)?;
    let summary_directory = PathBuf::from(&summary.directory)
        .canonicalize()
        .map_err(|error| format!("Carving summary directory is invalid: {error}"))?;
    if canonical != summary_directory {
        return Err("Carving summary refers to a different output directory.".into());
    }

    let mut selected = BTreeMap::new();
    for candidate in &manifest.selected_candidates {
        let extension = match candidate.format.as_str() {
            "PNG" if candidate.validation == "PNG chunks and CRCs valid; image decoded" => "png",
            "BMP"
                if matches!(
                    candidate.validation.as_str(),
                    "BMP pixels decoded; bounded dimensions and allocation valid"
                        | "BMP header, geometry, and pixel bounds valid"
                ) =>
            {
                "bmp"
            }
            "JPEG"
                if candidate.validation
                    == "JPEG decoded; dimensions and allocation bounds valid" =>
            {
                "jpg"
            }
            _ => {
                return Err(
                    "Carving manifest contains an unsupported format validation claim.".into(),
                )
            }
        };
        let expected_name = format!("carved-{:016x}.{extension}", candidate.offset);
        if candidate.length == 0
            || candidate
                .offset
                .checked_add(candidate.length)
                .is_none_or(|end| end > manifest.source.size)
            || !validate_hex_digest(&candidate.sha256)
            || candidate.output_name != expected_name
            || selected.insert(candidate.offset, candidate).is_some()
        {
            return Err("Carving manifest contains invalid or duplicate candidates.".into());
        }
    }

    let mut inventory = Vec::new();
    if !inventory_bytes.is_empty() {
        for line in inventory_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: CarveInventory = serde_json::from_slice(line)
                .map_err(|error| format!("Invalid carving inventory record: {error}"))?;
            inventory.push(record);
            if inventory.len() > 1000 {
                return Err("Carving inventory exceeds the selected-candidate limit.".into());
            }
        }
        if inventory_bytes.last() != Some(&b'\n')
            || inventory_bytes[..inventory_bytes.len() - 1]
                .split(|byte| *byte == b'\n')
                .any(|line| line.is_empty())
        {
            return Err("Carving inventory has malformed line endings.".into());
        }
    }

    let mut seen = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut exported = 0usize;
    let mut failed = 0usize;
    for record in &inventory {
        let candidate = selected
            .get(&record.offset)
            .ok_or("Carving inventory contains a candidate absent from the manifest.")?;
        if record.scan_session_id != manifest.source.scan_session_id
            || record.format != candidate.format
            || record.validation != candidate.validation
            || record.source_sha256.is_empty()
            || !validate_hex_digest(&record.source_sha256)
            || !seen.insert(record.offset)
        {
            return Err("Carving inventory contains duplicate or unsupported records.".into());
        }
        if record.length != candidate.length
            || record.source_sha256 != candidate.sha256
            || record
                .output_name
                .as_deref()
                .is_some_and(|name| name != candidate.output_name)
        {
            return Err("Carving inventory does not match the selected-candidate manifest.".into());
        }
        match record.status.as_str() {
            "exported" => {
                if record.output_name.as_deref() != Some(candidate.output_name.as_str())
                    || record.output_sha256.as_deref() != Some(candidate.sha256.as_str())
                    || record.error.is_some()
                    || !outputs.insert(candidate.output_name.clone())
                {
                    return Err("Exported carving inventory record is inconsistent.".into());
                }
                exported += 1;
            }
            "failed" => {
                if record.output_sha256.is_some() || record.error.is_none() {
                    return Err("Failed carving inventory record is inconsistent.".into());
                }
                failed += 1;
            }
            _ => return Err("Carving inventory contains an unsupported status.".into()),
        }
    }

    let checksums = parse_checksums(&checksums_bytes)?;
    let mut expected_checksums = BTreeSet::from([
        "manifest.json".to_owned(),
        "inventory.jsonl".to_owned(),
        "summary.json".to_owned(),
    ]);
    expected_checksums.extend(outputs.iter().cloned());
    if checksums.keys().cloned().collect::<BTreeSet<_>>() != expected_checksums {
        return Err("Carving checksum manifest does not match package contents.".into());
    }
    let mut expected_entries = expected_checksums;
    expected_entries.insert("checksums.sha256".into());
    expected_entries.insert("completion.json".into());
    if entries != expected_entries || !directories.is_empty() {
        return Err("Carving package has missing, nested, or unlisted entries.".into());
    }
    for (name, expected_hash) in &checksums {
        let (actual_hash, size) = hash_regular_file(&directory.join(name), locks)?;
        if &actual_hash != expected_hash {
            return Err(format!("Carving package checksum mismatch: {name}"));
        }
        if outputs.contains(name) {
            let record = inventory
                .iter()
                .find(|record| record.output_name.as_deref() == Some(name.as_str()))
                .ok_or("Carved output is absent from inventory.")?;
            if size != record.length
                || record.output_sha256.as_deref() != Some(actual_hash.as_str())
            {
                return Err(format!(
                    "Carved output does not match its inventory record: {name}"
                ));
            }
        }
    }

    let expected_state = if summary.cancelled || summary.failed > 0 {
        "partial"
    } else {
        "complete"
    };
    let source_after_matches =
        summary.source_sha256_after.as_deref() == completion.source_sha256_after.as_deref();
    if summary.exported != exported
        || summary.failed != failed
        || exported + failed != inventory.len()
        || inventory.len() > manifest.selected_candidates.len()
        || (!summary.cancelled && inventory.len() != manifest.selected_candidates.len())
        || completion.state != expected_state
        || completion.checksums_sha256 != format!("{:x}", Sha256::digest(&checksums_bytes))
        || completion.source_sha256_before != manifest.source.sha256_before_export
        || !source_after_matches
        || (summary.cancelled && summary.source_sha256_after.is_some())
        || (!summary.cancelled
            && summary.source_sha256_after.as_deref()
                != Some(manifest.source.sha256_before_export.as_str()))
    {
        return Err("Carving inventory, summary, and completion state do not agree.".into());
    }

    crate::safe_file::require_plain_directory(directory).map_err(err)?;
    if enumerate_entries(directory, locks)? != (entries, directories) {
        return Err("Carving package contents changed during verification.".into());
    }
    Ok(RecoveryExportVerification {
        package_type: "signature_carving".into(),
        case_id: Some(manifest.source.case_id),
        evidence_record_id: Some(manifest.source.evidence_record_id),
        scan_session_id: Some(manifest.source.scan_session_id),
        records: inventory.len(),
        exported,
        failed,
        cancelled: summary.cancelled,
        state: completion.state,
        checksums_sha256: format!("{:x}", Sha256::digest(&checksums_bytes)),
    })
}

fn verify_acquisition_package(
    directory: &Path,
    entries: BTreeSet<String>,
    directories: BTreeSet<String>,
    manifest_bytes: &[u8],
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<RecoveryExportVerification> {
    if !directories.is_empty() {
        return Err("Physical acquisition packages cannot contain subdirectories.".into());
    }
    let completion_bytes = read_bounded(directory, "completion.json", MAX_METADATA_BYTES, locks)?;
    let checksums_bytes = read_bounded(directory, "checksums.sha256", MAX_CHECKSUMS_BYTES, locks)?;
    let manifest: AcquisitionManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("Invalid acquisition manifest: {error}"))?;
    let completion: AcquisitionCompletion = serde_json::from_slice(&completion_bytes)
        .map_err(|error| format!("Invalid acquisition completion marker: {error}"))?;
    let created = manifest
        .created_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid acquisition timestamp.")?;
    if manifest.tool != "DaemonCore Data Recovery"
        || manifest.version.is_empty()
        || manifest.package_type != "physical_device_acquisition"
        || created == 0
        || manifest.case_id <= 0
        || manifest.device_number != manifest.device_identity.number
        || manifest.source_size_bytes == 0
        || manifest.device_identity.size_bytes != manifest.source_size_bytes
        || manifest.bytes_per_sector < 512
        || manifest.bytes_per_sector > 65_536
        || !manifest.bytes_per_sector.is_power_of_two()
        || manifest.device_identity.bytes_per_sector != manifest.bytes_per_sector
        || !manifest
            .source_size_bytes
            .is_multiple_of(u64::from(manifest.bytes_per_sector))
        || manifest.retries_per_range != 3
        || !manifest.hardware_write_blocker_attested
        || !matches!(
            manifest.acquisition_method.as_str(),
            "Windows raw physical-drive read through a handle opened without write access"
                | "Windows raw physical-drive read through a handle opened without write access; failed ranges are retried with binary subdivision through the reported sector size"
        )
        || manifest.image_name != "image.raw"
        || !validate_hex_digest(&manifest.image_sha256)
        || manifest.read_error_ranges > MAX_ACQUISITION_ERROR_RANGES
        || manifest.limitations.is_empty()
    {
        return Err("Unsupported or inconsistent acquisition manifest metadata.".into());
    }

    let completion_state = if manifest.read_error_ranges == 0 {
        "complete"
    } else {
        "partial"
    };
    if completion.state != completion_state
        || completion.image_sha256 != manifest.image_sha256
        || completion.read_error_ranges != manifest.read_error_ranges
        || completion.checksums_sha256 != format!("{:x}", Sha256::digest(&checksums_bytes))
    {
        return Err("Acquisition completion marker does not match the manifest.".into());
    }

    let checksums = parse_checksums(&checksums_bytes)?;
    let expected_names = BTreeSet::from([
        "image.raw".to_owned(),
        "manifest.json".to_owned(),
        "read-errors.jsonl".to_owned(),
    ]);
    if checksums.keys().cloned().collect::<BTreeSet<_>>() != expected_names {
        return Err("Acquisition checksum list does not match expected package files.".into());
    }
    let mut expected_entries = expected_names;
    expected_entries.insert("checksums.sha256".into());
    expected_entries.insert("completion.json".into());
    if entries != expected_entries {
        return Err("Acquisition package has missing or unlisted files.".into());
    }

    let (image_hash, image_length) = hash_regular_file(&directory.join("image.raw"), locks)?;
    if image_length != manifest.source_size_bytes || image_hash != manifest.image_sha256 {
        return Err("Acquisition image size or SHA-256 does not match its manifest.".into());
    }
    for name in ["manifest.json", "read-errors.jsonl"] {
        let (digest, _) = hash_regular_file(&directory.join(name), locks)?;
        if checksums.get(name) != Some(&digest) {
            return Err(format!("Acquisition checksum mismatch: {name}"));
        }
    }
    if checksums.get("image.raw") != Some(&image_hash) {
        return Err("Acquisition checksum mismatch: image.raw".into());
    }
    verify_acquisition_error_map(directory, &manifest, &checksums, locks)?;
    crate::safe_file::require_plain_directory(directory).map_err(err)?;
    if enumerate_entries(directory, locks)? != (expected_entries, BTreeSet::new()) {
        return Err("Acquisition package contents changed during verification.".into());
    }
    Ok(RecoveryExportVerification {
        package_type: "physical_device_acquisition".into(),
        case_id: Some(manifest.case_id),
        evidence_record_id: None,
        scan_session_id: None,
        records: 1,
        exported: 1,
        failed: manifest.read_error_ranges,
        cancelled: false,
        state: completion.state,
        checksums_sha256: format!("{:x}", Sha256::digest(&checksums_bytes)),
    })
}

fn verify_acquisition_error_map(
    directory: &Path,
    manifest: &AcquisitionManifest,
    checksums: &BTreeMap<String, String>,
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<()> {
    use std::io::{BufRead, BufReader};

    let path = directory.join("read-errors.jsonl");
    let metadata = fs::symlink_metadata(&path).map_err(err)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_ACQUISITION_ERROR_MAP_BYTES
    {
        return Err("Acquisition read-error map is not a bounded regular file.".into());
    }
    let file = crate::safe_file::open_regular_file(&path).map_err(err)?;
    let opened = file.metadata().map_err(err)?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("Acquisition read-error map changed while opening.".into());
    }
    let initial_length = opened.len();
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut count = 0usize;
    let mut previous_end = 0u64;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).map_err(err)?;
        if read == 0 {
            break;
        }
        if line.len() > 8192 || line.last() != Some(&b'\n') || line.len() < 2 {
            return Err("Acquisition read-error map contains an invalid line.".into());
        }
        let record: AcquisitionReadError = serde_json::from_slice(&line[..line.len() - 1])
            .map_err(|error| format!("Invalid acquisition read-error record: {error}"))?;
        let sector_bytes = u64::from(manifest.bytes_per_sector);
        let end = record.offset.checked_add(record.length);
        if record.offset < previous_end
            || record.offset >= manifest.source_size_bytes
            || !record.offset.is_multiple_of(sector_bytes)
            || record.length == 0
            || record.length > 1024 * 1024
            || !record.length.is_multiple_of(sector_bytes)
            || end.is_none_or(|end| {
                end > manifest.source_size_bytes
                    || record.offset / (1024 * 1024) != (end - 1) / (1024 * 1024)
            })
            || record.attempts != manifest.retries_per_range
            || record.error.is_empty()
            || record.error.len() > 4096
        {
            return Err("Acquisition read-error range is invalid or out of order.".into());
        }
        previous_end = end.ok_or("Acquisition read-error range overflowed.")?;
        count += 1;
        if count > MAX_ACQUISITION_ERROR_RANGES {
            return Err("Acquisition read-error map exceeds its range limit.".into());
        }
    }
    let file = reader.into_inner();
    if file.metadata().map_err(err)?.len() != initial_length || count != manifest.read_error_ranges
    {
        return Err("Acquisition read-error map count or size changed during verification.".into());
    }
    locks.retain_file(file);
    if count == 0 && initial_length != 0 {
        return Err("An acquisition with no read errors must have an empty error map.".into());
    }
    let (digest, _) = hash_regular_file(&path, locks)?;
    if checksums.get("read-errors.jsonl") != Some(&digest) {
        return Err("Acquisition checksum mismatch: read-errors.jsonl".into());
    }
    Ok(())
}

fn verify_raid_package(
    directory: &Path,
    entries: BTreeSet<String>,
    directories: BTreeSet<String>,
    manifest_bytes: &[u8],
    locks: &mut crate::safe_file::ReadLocks,
) -> Result<RecoveryExportVerification> {
    if !directories.is_empty() {
        return Err("RAID reconstruction packages cannot contain subdirectories.".into());
    }
    let completion_bytes = read_bounded(directory, "completion.json", MAX_METADATA_BYTES, locks)?;
    let checksums_bytes = read_bounded(directory, "checksums.sha256", MAX_CHECKSUMS_BYTES, locks)?;
    let manifest: RaidManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("Invalid RAID reconstruction manifest: {error}"))?;
    let completion: RaidCompletion = serde_json::from_slice(&completion_bytes)
        .map_err(|error| format!("Invalid RAID completion marker: {error}"))?;
    let created = manifest
        .created_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid RAID reconstruction timestamp.")?;
    if manifest.tool != "DaemonCore Data Recovery"
        || manifest.version.is_empty()
        || manifest.package_type != "raid_reconstruction"
        || manifest.case_id <= 0
        || created == 0
        || !manifest.member_order_is_operator_supplied
        || !(2..=32).contains(&manifest.members.len())
        || !matches!(manifest.bytes_per_sector, 512 | 4096)
        || manifest.image_name != "image.raw"
        || !validate_hex_digest(&manifest.image_sha256)
        || manifest.limitations.is_empty()
        || completion.state != "complete"
        || completion.image_sha256 != manifest.image_sha256
        || completion.checksums_sha256 != format!("{:x}", Sha256::digest(&checksums_bytes))
    {
        return Err("Unsupported or inconsistent RAID reconstruction metadata.".into());
    }

    let first_data_size = manifest.members[0].data_size_bytes;
    if first_data_size == 0 || !first_data_size.is_multiple_of(u64::from(manifest.bytes_per_sector))
    {
        return Err("RAID member data size is empty or not sector aligned.".into());
    }
    for (order, member) in manifest.members.iter().enumerate() {
        if member.order != order
            || member.path.is_empty()
            || member.path.encode_utf16().count() > 32767
            || member.path.chars().any(char::is_control)
            || member.image_size_bytes == 0
            || member.data_offset_bytes != manifest.data_offset_bytes
            || member
                .image_size_bytes
                .checked_sub(member.data_offset_bytes)
                != Some(member.data_size_bytes)
            || member.data_size_bytes != first_data_size
            || !validate_hex_digest(&member.image_sha256)
        {
            return Err("RAID member provenance is invalid or inconsistent.".into());
        }
    }
    let expected_size = match manifest.level.as_str() {
        "RAID 0" => {
            let stripe = manifest
                .stripe_size_bytes
                .ok_or("RAID 0 manifest has no stripe size.")?;
            if !(512..=16 * 1024 * 1024).contains(&stripe)
                || !stripe.is_power_of_two()
                || !stripe.is_multiple_of(u64::from(manifest.bytes_per_sector))
                || !first_data_size.is_multiple_of(stripe)
                || manifest.layout_method
                    != "RAID 0 left-symmetric striping in operator-supplied member order"
            {
                return Err("RAID 0 stripe geometry or layout method is invalid.".into());
            }
            first_data_size
                .checked_mul(manifest.members.len() as u64)
                .ok_or("Reconstructed RAID 0 size overflow")?
        }
        "RAID 1" => {
            if manifest.stripe_size_bytes.is_some()
                || manifest.layout_method
                    != "RAID 1 mirror copy after byte-for-byte agreement across all selected data regions"
            {
                return Err("RAID 1 mirror metadata or layout method is invalid.".into());
            }
            first_data_size
        }
        "RAID 5" => {
            let stripe = manifest
                .stripe_size_bytes
                .ok_or("RAID 5 manifest has no stripe size.")?;
            if manifest.members.len() < 3
                || !(512..=16 * 1024 * 1024).contains(&stripe)
                || !stripe.is_power_of_two()
                || !stripe.is_multiple_of(u64::from(manifest.bytes_per_sector))
                || !first_data_size.is_multiple_of(stripe)
                || manifest.layout_method
                    != "RAID 5 left-symmetric rotating parity; all member data and XOR parity verified"
            {
                return Err("RAID 5 stripe geometry or parity-validation method is invalid.".into());
            }
            first_data_size
                .checked_mul((manifest.members.len() - 1) as u64)
                .ok_or("Reconstructed RAID 5 size overflow")?
        }
        _ => return Err("Unsupported RAID reconstruction level.".into()),
    };
    if manifest.reconstructed_size_bytes != expected_size {
        return Err("RAID reconstruction size does not match the declared geometry.".into());
    }

    let checksums = parse_checksums(&checksums_bytes)?;
    let expected_checksums = BTreeSet::from(["image.raw".to_owned(), "manifest.json".to_owned()]);
    if checksums.keys().cloned().collect::<BTreeSet<_>>() != expected_checksums {
        return Err("RAID checksum list does not match package contents.".into());
    }
    let mut expected_entries = expected_checksums;
    expected_entries.insert("checksums.sha256".into());
    expected_entries.insert("completion.json".into());
    if entries != expected_entries {
        return Err("RAID package has missing or unlisted files.".into());
    }
    let (image_hash, image_size) = hash_regular_file(&directory.join("image.raw"), locks)?;
    if image_size != expected_size || image_hash != manifest.image_sha256 {
        return Err("Reconstructed RAID image size or SHA-256 does not match its manifest.".into());
    }
    let (manifest_hash, _) = hash_regular_file(&directory.join("manifest.json"), locks)?;
    if checksums.get("manifest.json") != Some(&manifest_hash) {
        return Err("RAID package checksum mismatch: manifest.json".into());
    }
    if checksums.get("image.raw") != Some(&image_hash) {
        return Err("RAID package checksum mismatch: image.raw".into());
    }
    crate::safe_file::require_plain_directory(directory).map_err(err)?;
    if enumerate_entries(directory, locks)? != (expected_entries, BTreeSet::new()) {
        return Err("RAID package contents changed during verification.".into());
    }
    Ok(RecoveryExportVerification {
        package_type: "raid_reconstruction".into(),
        case_id: Some(manifest.case_id),
        evidence_record_id: None,
        scan_session_id: None,
        records: manifest.members.len(),
        exported: 1,
        failed: 0,
        cancelled: false,
        state: completion.state,
        checksums_sha256: format!("{:x}", Sha256::digest(&checksums_bytes)),
    })
}

pub(crate) fn verify_package(directory: &Path) -> Result<RecoveryExportVerification> {
    let mut locks = crate::safe_file::ReadLocks::default();
    let (entries, directories) = enumerate_entries(directory, &mut locks)?;
    let manifest_bytes = read_bounded(directory, "manifest.json", MAX_METADATA_BYTES, &mut locks)?;
    let package_kind: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("Invalid recovery manifest: {error}"))?;
    match package_kind
        .get("package_type")
        .and_then(|value| value.as_str())
    {
        Some("signature_carving") => {
            return verify_carve_package(directory, entries, directories, &mut locks)
        }
        Some("physical_device_acquisition") => {
            return verify_acquisition_package(
                directory,
                entries,
                directories,
                &manifest_bytes,
                &mut locks,
            )
        }
        Some("raid_reconstruction") => {
            return verify_raid_package(
                directory,
                entries,
                directories,
                &manifest_bytes,
                &mut locks,
            )
        }
        _ => {}
    }

    let checksums_bytes = read_bounded(
        directory,
        "checksums.sha256",
        MAX_CHECKSUMS_BYTES,
        &mut locks,
    )?;
    let completion_bytes =
        read_bounded(directory, "completion.json", MAX_METADATA_BYTES, &mut locks)?;
    let summary_bytes = read_bounded(directory, "summary.json", MAX_METADATA_BYTES, &mut locks)?;
    let inventory_bytes = read_bounded(
        directory,
        "inventory.jsonl",
        MAX_INVENTORY_BYTES,
        &mut locks,
    )?;

    let completion: CompletionMarker = serde_json::from_slice(&completion_bytes)
        .map_err(|e| format!("Invalid recovery completion marker: {e}"))?;
    let summary: ExportSummary = serde_json::from_slice(&summary_bytes)
        .map_err(|e| format!("Invalid recovery summary: {e}"))?;
    let manifest: ExportManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("Invalid recovery manifest: {e}"))?;
    let start = manifest
        .export_started_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid recovery export timestamp.")?;

    if manifest.tool != "DaemonCore Data Recovery"
        || manifest.version.is_empty()
        || manifest.hash_algorithm != "SHA-256"
        || manifest.source.session_id == 0
        || manifest.source.case_id.is_some_and(|id| id <= 0)
        || manifest.source.evidence_record_id.is_some_and(|id| id <= 0)
        || manifest.source.scan_session_id.is_some_and(|id| id <= 0)
        || manifest.source.path.is_empty()
        || manifest.source.size == 0
        || manifest.source.sha256_before_export.len() != 64
        || !validate_hex_digest(&manifest.source.sha256_before_export)
        || manifest.state != "incomplete_until_completion_marker_exists"
        || manifest.content_validation
            != "Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established."
        || !manifest.volume.is_object()
        || start == 0
        || manifest.selected_records.is_empty()
        || manifest.selected_records.len() > 1000
    {
        return Err("Unsupported or inconsistent recovery manifest metadata.".into());
    }
    let (fat32_manifest, exfat_manifest) = match manifest
        .volume
        .get("filesystem")
        .and_then(|value| value.as_str())
    {
        Some("FAT32") => {
            let volume_offset = manifest.volume["volume_offset"].as_u64();
            let volume_size = manifest.volume["volume_size"].as_u64();
            let cluster_size = manifest.volume["cluster_size"].as_u64();
            let cluster_count = manifest.volume["cluster_count"].as_u64();
            if volume_offset.zip(volume_size).is_none_or(|(offset, size)| {
                size == 0
                    || offset
                        .checked_add(size)
                        .is_none_or(|end| end > manifest.source.size)
            }) || cluster_size
                .is_none_or(|size| !(512..=524_288).contains(&size) || !size.is_power_of_two())
                || cluster_count.is_none_or(|count| !(65_525..=0x0fff_fff5).contains(&count))
                || cluster_count.zip(cluster_size).zip(volume_size).is_none_or(
                    |((count, cluster), size)| {
                        count.checked_mul(cluster).is_none_or(|bytes| bytes > size)
                            || size % cluster != 0
                    },
                )
                || manifest.volume["deleted_file_layout"]
                    != "contiguous_assumed_only_when_candidate_clusters_are_free"
                || manifest.volume["selected_cluster_overlap_check"]
                    != "selected_entries_only_other_deleted_entries_may_reference_the_same_clusters"
            {
                return Err("FAT32 recovery manifest has invalid geometry or omits its recovery assumptions.".into());
            }
            (true, false)
        }
        Some("exFAT") => {
            let volume_offset = manifest.volume["volume_offset"].as_u64();
            let volume_size = manifest.volume["volume_size"].as_u64();
            let cluster_size = manifest.volume["cluster_size"].as_u64();
            let cluster_count = manifest.volume["cluster_count"].as_u64();
            let root_cluster = manifest.volume["root_cluster"].as_u64();
            if volume_offset.zip(volume_size).is_none_or(|(offset, size)| {
                size < 24 * 512
                    || offset
                        .checked_add(size)
                        .is_none_or(|end| end > manifest.source.size)
            }) || cluster_size.is_none_or(|size| {
                !(512..=32 * 1024 * 1024).contains(&size) || !size.is_power_of_two()
            }) || cluster_count.is_none_or(|count| count == 0 || count > 0xffff_fff5)
                || cluster_count.zip(cluster_size).zip(volume_size).is_none_or(
                    |((count, cluster), size)| {
                        count.checked_mul(cluster).is_none_or(|bytes| bytes > size)
                            || size % cluster != 0
                    },
                )
                || root_cluster
                    .zip(cluster_count)
                    .is_none_or(|(root, count)| !(2..=count.saturating_add(1)).contains(&root))
                || manifest.volume["deleted_file_layout"]
                    != "contiguous_declared_by_entry_set_and_free_in_allocation_bitmap"
                || manifest.volume["selected_cluster_overlap_check"]
                    != "overlapping_selected_ranges_are_not_exported"
            {
                return Err("exFAT recovery manifest has invalid geometry or omits its recovery assumptions.".into());
            }
            (false, true)
        }
        Some(_) => return Err("Recovery manifest names an unsupported filesystem.".into()),
        None => (false, false),
    };

    let canonical = directory.canonicalize().map_err(err)?;
    let summary_directory = PathBuf::from(&summary.directory)
        .canonicalize()
        .map_err(|e| format!("Recovery summary directory is invalid: {e}"))?;
    if canonical != summary_directory {
        return Err("Recovery summary refers to a different output directory.".into());
    }
    if summary.exported > manifest.selected_records.len()
        || summary.failed > manifest.selected_records.len()
        || summary
            .exported
            .checked_add(summary.failed)
            .is_none_or(|count| count > manifest.selected_records.len())
        || completion.checksums_sha256 != format!("{:x}", Sha256::digest(&checksums_bytes))
        || !matches!(completion.state.as_str(), "complete" | "partial")
    {
        return Err("Recovery summary or completion marker is inconsistent.".into());
    }

    let checksums = parse_checksums(&checksums_bytes)?;
    let mut inventory = Vec::new();
    if !inventory_bytes.is_empty() {
        for line in inventory_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: InventoryRecord = serde_json::from_slice(line)
                .map_err(|e| format!("Invalid recovery inventory record: {e}"))?;
            inventory.push(record);
            if inventory.len() > 1000 {
                return Err("Recovery inventory exceeds the selected-record limit.".into());
            }
        }
        if inventory_bytes.last() != Some(&b'\n')
            || inventory_bytes[..inventory_bytes.len() - 1]
                .split(|byte| *byte == b'\n')
                .any(|line| line.is_empty())
        {
            return Err("Recovery inventory has malformed line endings.".into());
        }
    }

    let selected: BTreeMap<u64, &SelectedRecord> = manifest
        .selected_records
        .iter()
        .map(|record| (record.record, record))
        .collect();
    if selected.len() != manifest.selected_records.len() {
        return Err("Recovery manifest contains duplicate record IDs.".into());
    }
    if manifest.selected_records.iter().any(|record| {
        record.record == 0
            || record.parent_record == 0
            || record.storage.is_empty()
            || record.allocation.is_empty()
            || !valid_parent_path(
                record.parent_record,
                record.parent_sequence,
                record.parent_path.as_deref(),
            )
            || !valid_filename_references(&record.filename_references)
            || !validate_hex_digest(&record.record_sha256)
    }) {
        return Err("Recovery manifest contains invalid selected-record metadata.".into());
    }
    if fat32_manifest
        && manifest.selected_records.iter().any(|record| {
            record.parent_record != 5
                || record.parent_sequence.is_some()
                || record.parent_path.is_some()
                || !record.filename_references.is_empty()
                || record.path_restored != Some(false)
                || record.storage != "contiguous_assumed"
                || record.allocation != "free_contiguous_clusters"
                || record.output_name.as_deref()
                    != Some(safe_name(record.record, &record.name).as_str())
        })
    {
        return Err(
            "FAT32 recovery manifest contains unsupported path or allocation claims.".into(),
        );
    }
    if exfat_manifest
        && manifest.selected_records.iter().any(|record| {
            record.parent_record != 5
                || record.parent_sequence.is_some()
                || record.parent_path.is_some()
                || !record.filename_references.is_empty()
                || record.path_restored != Some(false)
                || record.storage != "contiguous_declared"
                || record.allocation != "free_in_current_bitmap"
                || record.output_name.as_deref()
                    != Some(safe_name(record.record, &record.name).as_str())
        })
    {
        return Err(
            "exFAT recovery manifest contains unsupported path or allocation claims.".into(),
        );
    }
    let mut seen = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut exported = 0usize;
    let mut failed = 0usize;
    for record in &inventory {
        if !seen.insert(record.record) || record.content_validation != "not performed" {
            return Err("Recovery inventory contains duplicate or unsupported records.".into());
        }
        let selected_record = selected
            .get(&record.record)
            .ok_or("Recovery inventory contains a record absent from the manifest.")?;
        if selected_record.name != record.original_name
            || selected_record.filename_references != record.filename_references
            || selected_record.size != record.size
            || record
                .parent_record
                .is_some_and(|parent| parent != selected_record.parent_record)
            || selected_record.parent_sequence != record.parent_sequence
            || selected_record.path_restored != record.path_restored
        {
            return Err("Recovery inventory does not match the selected-record manifest.".into());
        }
        match record.status.as_str() {
            "destination_hash_verified" => {
                let name = record
                    .output_name
                    .as_deref()
                    .ok_or("Verified recovery record has no output name.")?;
                let digest = record
                    .sha256
                    .as_deref()
                    .ok_or("Verified recovery record has no output hash.")?;
                let legacy_flat_name = safe_name(record.record, &record.original_name);
                let restored_name = safe_relative_name(
                    record.record,
                    &record.original_name,
                    selected_record.parent_path.as_deref(),
                );
                let expected_name = match (
                    selected_record.output_name.as_deref(),
                    selected_record.path_restored,
                ) {
                    (Some(planned), Some(true))
                        if selected_record.parent_path.is_some()
                            && planned == restored_name
                            && planned.encode_utf16().count() <= MAX_EXPORT_RELATIVE_PATH_UTF16 =>
                    {
                        planned
                    }
                    (Some(planned), Some(false))
                        if planned == legacy_flat_name
                            && (selected_record.parent_path.is_none()
                                || restored_name.encode_utf16().count()
                                    > MAX_EXPORT_RELATIVE_PATH_UTF16) =>
                    {
                        planned
                    }
                    (None, None) => &legacy_flat_name,
                    _ => return Err("Recovery manifest contains an invalid output path.".into()),
                };
                if name != expected_name
                    || !validate_hex_digest(digest)
                    || record.error.is_some()
                    || record.all_zero.is_none()
                    || !outputs.insert(name.to_owned())
                {
                    return Err("Verified recovery inventory record is inconsistent.".into());
                }
                exported += 1;
            }
            "failed" => {
                if record.output_name.is_some()
                    || record.sha256.is_some()
                    || record.all_zero.is_some()
                    || record.error.is_none()
                {
                    return Err("Failed recovery inventory record is inconsistent.".into());
                }
                failed += 1;
            }
            _ => return Err("Recovery inventory contains an unsupported status.".into()),
        }
    }
    if exported != summary.exported
        || failed != summary.failed
        || (!summary.cancelled && inventory.len() != manifest.selected_records.len())
        || (summary.cancelled && inventory.len() > manifest.selected_records.len())
        || (!summary.cancelled && failed == 0 && completion.state != "complete")
        || ((summary.cancelled || failed > 0) && completion.state != "partial")
    {
        return Err("Recovery inventory, summary, and completion state do not agree.".into());
    }

    let mut expected_checksums = BTreeSet::from([
        "manifest.json".to_owned(),
        "inventory.jsonl".to_owned(),
        "summary.json".to_owned(),
    ]);
    expected_checksums.extend(outputs.iter().cloned());
    if checksums.keys().cloned().collect::<BTreeSet<_>>() != expected_checksums {
        return Err("Recovery checksum manifest does not match package contents.".into());
    }
    let mut expected_directories = BTreeSet::new();
    for output in &outputs {
        let components = output.split('/').collect::<Vec<_>>();
        let mut parent = String::new();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            expected_directories.insert(parent.clone());
        }
    }
    let mut expected_entries = expected_checksums;
    expected_entries.insert("checksums.sha256".into());
    expected_entries.insert("completion.json".into());
    if entries != expected_entries || directories != expected_directories {
        return Err("Recovery folder has missing or unlisted entries.".into());
    }

    for (name, expected_hash) in &checksums {
        let (actual_hash, size) = hash_regular_file(&directory.join(name), &mut locks)?;
        if &actual_hash != expected_hash {
            return Err(format!("Recovery file checksum mismatch: {name}"));
        }
        if outputs.contains(name) {
            let record = inventory
                .iter()
                .find(|record| record.output_name.as_deref() == Some(name.as_str()))
                .ok_or("Recovery output is absent from inventory.")?;
            if size != record.size || record.sha256.as_deref() != Some(actual_hash.as_str()) {
                return Err(format!(
                    "Recovery output does not match its inventory record: {name}"
                ));
            }
        }
    }

    crate::safe_file::require_plain_directory(directory).map_err(err)?;
    if enumerate_entries(directory, &mut locks)? != (entries, directories) {
        return Err("Recovery folder contents changed during verification.".into());
    }

    Ok(RecoveryExportVerification {
        package_type: "filesystem_recovery".into(),
        case_id: manifest.source.case_id,
        evidence_record_id: manifest.source.evidence_record_id,
        scan_session_id: manifest.source.scan_session_id,
        records: inventory.len(),
        exported,
        failed,
        cancelled: summary.cancelled,
        state: completion.state,
        checksums_sha256: format!("{:x}", Sha256::digest(&checksums_bytes)),
    })
}

#[tauri::command]
pub async fn verify_recovery_export(
    state: State<'_, AppState>,
) -> Result<Option<RecoveryExportVerification>> {
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Select a recovery export folder to verify")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(None);
    };
    let folder_path = folder.to_string_lossy().into_owned();
    let result = tauri::async_runtime::spawn_blocking(move || verify_package(&folder))
        .await
        .map_err(err)?;
    let (event, verification, failure) = match &result {
        Ok(verification) => (
            match verification.package_type.as_str() {
                "physical_device_acquisition" => "acquisition_package_verified",
                "signature_carving" => "carving_package_verified",
                "raid_reconstruction" => "raid_package_verified",
                _ => "recovery_export_verified",
            },
            Some(serde_json::to_value(verification).map_err(err)?),
            None,
        ),
        Err(failure) => (
            "recovery_export_verification_failed",
            None,
            Some(failure.clone()),
        ),
    };
    let payload = serde_json::json!({
        "case_id": result.as_ref().ok().map(|value| value.case_id),
        "evidence_record_id": result.as_ref().ok().and_then(|value| value.evidence_record_id),
        "scan_session_id": result.as_ref().ok().and_then(|value| value.scan_session_id),
        "package_type": result.as_ref().ok().map(|value| value.package_type.as_str()),
        "directory": folder_path,
        "verification": verification,
        "failure": failure
    })
    .to_string();
    let db = state.db.lock().map_err(err)?;
    audit(&db, event, &payload).map_err(|error| {
        format!(
            "Recovery export verification could not be recorded in the local audit log: {error}"
        )
    })?;
    result.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filename_reference_metadata_is_bounded_and_uses_known_namespaces() {
        let reference = FilenameReference {
            name: "evidence.txt".into(),
            attribute_record: 7,
            attribute_record_sequence: 1,
            parent_record: 5,
            parent_sequence: 2,
            namespace: 1,
            attribute_id: 4,
        };
        assert!(valid_filename_references(std::slice::from_ref(&reference)));

        let mut invalid = reference.clone();
        invalid.namespace = 4;
        assert!(!valid_filename_references(&[invalid]));
        let mut invalid = reference.clone();
        invalid.parent_record = 0x0001_0000_0000_0000;
        assert!(!valid_filename_references(&[invalid]));
        let mut invalid = reference;
        invalid.name = "x".repeat(256);
        assert!(!valid_filename_references(&[invalid]));
        assert!(!valid_filename_references(&vec![
            FilenameReference {
                name: "x".into(),
                attribute_record: 7,
                attribute_record_sequence: 1,
                parent_record: 5,
                parent_sequence: 1,
                namespace: 1,
                attribute_id: 0,
            };
            MAX_FILENAME_REFERENCES + 1
        ]));
    }

    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn acquisition_package(with_read_error: bool) -> (PathBuf, PathBuf) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("acquisition-verify-{unique}"));
        let directory = root.join("package");
        fs::create_dir_all(&directory).unwrap();
        let image = vec![if with_read_error { 0 } else { 0x5a }; 512];
        let image_hash = hash(&image);
        fs::write(directory.join("image.raw"), &image).unwrap();
        let error_map = if with_read_error {
            b"{\"offset\":0,\"length\":512,\"attempts\":3,\"error\":\"fixture failure\"}\n".to_vec()
        } else {
            Vec::new()
        };
        fs::write(directory.join("read-errors.jsonl"), &error_map).unwrap();
        let manifest = json!({
            "tool":"DaemonCore Data Recovery",
            "version":"0.1.0",
            "package_type":"physical_device_acquisition",
            "case_id":1,
            "created_unix_ns":"1",
            "device_number":0,
            "device_identity": {
                "number":0,
                "size_bytes":512,
                "bytes_per_sector":512,
                "vendor":"Fixture",
                "product":"Disk",
                "revision":null,
                "serial_number":"TEST-01",
                "bus_type":7,
                "identity_error":null
            },
            "source_size_bytes":512,
            "bytes_per_sector":512,
            "retries_per_range":3,
            "hardware_write_blocker_attested":true,
            "acquisition_method":"Windows raw physical-drive read through a handle opened without write access",
            "image_name":"image.raw",
            "image_sha256":image_hash,
            "read_error_ranges":if with_read_error { 1 } else { 0 },
            "limitations":"fixture"
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(directory.join("manifest.json"), &manifest_bytes).unwrap();
        let checksums = format!(
            "{}  manifest.json\n{}  read-errors.jsonl\n{}  image.raw\n",
            hash(&manifest_bytes),
            hash(&error_map),
            image_hash
        );
        fs::write(directory.join("checksums.sha256"), &checksums).unwrap();
        let completion = json!({
            "state":if with_read_error { "partial" } else { "complete" },
            "image_sha256":image_hash,
            "checksums_sha256":hash(checksums.as_bytes()),
            "read_error_ranges":if with_read_error { 1 } else { 0 }
        });
        fs::write(
            directory.join("completion.json"),
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();
        (root, directory)
    }

    #[test]
    fn verifies_complete_acquisition_package_and_image_digest() {
        let (root, directory) = acquisition_package(false);
        let verification = verify_package(&directory).unwrap();
        assert_eq!(verification.state, "complete");
        assert_eq!(verification.case_id, Some(1));
        assert_eq!(verification.exported, 1);
        fs::write(directory.join("unlisted.bin"), b"unexpected").unwrap();
        assert!(verify_package(&directory)
            .unwrap_err()
            .contains("missing or unlisted files"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verifies_partial_acquisition_ranges_and_rejects_modified_image() {
        let (root, directory) = acquisition_package(true);
        let verification = verify_package(&directory).unwrap();
        assert_eq!(verification.state, "partial");
        assert_eq!(verification.failed, 1);
        fs::write(directory.join("image.raw"), vec![0x7f; 512]).unwrap();
        assert!(verify_package(&directory)
            .unwrap_err()
            .contains("image size or SHA-256"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_out_of_bounds_acquisition_error_ranges_even_when_checksums_are_rebuilt() {
        let (root, directory) = acquisition_package(true);
        let error_map = b"{\"offset\":512,\"length\":0,\"attempts\":3,\"error\":\"forged\"}\n";
        fs::write(directory.join("read-errors.jsonl"), error_map).unwrap();
        let manifest = fs::read(directory.join("manifest.json")).unwrap();
        let image = fs::read(directory.join("image.raw")).unwrap();
        let checksums = format!(
            "{}  manifest.json\n{}  read-errors.jsonl\n{}  image.raw\n",
            hash(&manifest),
            hash(error_map),
            hash(&image)
        );
        fs::write(directory.join("checksums.sha256"), &checksums).unwrap();
        let mut completion: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("completion.json")).unwrap()).unwrap();
        completion["checksums_sha256"] = json!(hash(checksums.as_bytes()));
        fs::write(
            directory.join("completion.json"),
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();
        assert!(verify_package(&directory)
            .unwrap_err()
            .contains("read-error range is invalid"));
        fs::remove_dir_all(root).unwrap();
    }

    fn valid_package() -> (PathBuf, String) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("recovery-verify-{unique}"));
        let _ = fs::remove_dir_all(&root);
        let directory = root.join("export");
        fs::create_dir_all(&directory).unwrap();
        let data = b"verified recovery output";
        let output_name = safe_name(7, "deleted.txt");
        fs::write(directory.join(&output_name), data).unwrap();
        let output_hash = hash(data);
        let manifest = json!({
            "tool":"DaemonCore Data Recovery",
            "version":"0.1.0",
            "hash_algorithm":"SHA-256",
            "export_started_unix_ns":"1",
            "source":{"case_id":1,"evidence_record_id":2,"scan_session_id":3,"session_id":1,"path":"evidence.img","size":4096,"sha256_before_export":"a".repeat(64)},
            "volume":{"sector_size":512},
            "selected_records":[{"record":7,"name":"deleted.txt","parent_record":5,"parent_sequence":1,"filename_references":[{"name":"deleted.txt","attribute_record":7,"attribute_record_sequence":1,"parent_record":5,"parent_sequence":1,"namespace":1,"attribute_id":0}],"size":data.len(),"storage":"resident","allocation":"unallocated","record_sha256":"b".repeat(64)}],
            "state":"incomplete_until_completion_marker_exists",
            "content_validation":"Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established."
        });
        let inventory = json!({
            "record":7,
            "parent_record":5,
            "parent_sequence":1,
            "original_name":"deleted.txt",
            "filename_references":[{"name":"deleted.txt","attribute_record":7,"attribute_record_sequence":1,"parent_record":5,"parent_sequence":1,"namespace":1,"attribute_id":0}],
            "output_name":output_name,
            "size":data.len(),
            "sha256":output_hash,
            "all_zero":false,
            "status":"destination_hash_verified",
            "error":null,
            "content_validation":"not performed"
        });
        fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("inventory.jsonl"),
            format!("{}\n", serde_json::to_string(&inventory).unwrap()),
        )
        .unwrap();
        let summary = json!({"directory":directory,"exported":1,"failed":0,"cancelled":false});
        fs::write(
            directory.join("summary.json"),
            serde_json::to_vec_pretty(&summary).unwrap(),
        )
        .unwrap();
        let mut files = vec![
            "manifest.json",
            "inventory.jsonl",
            "summary.json",
            &output_name,
        ];
        files.sort();
        let checksums = files
            .iter()
            .map(|name| {
                format!(
                    "{}  {}\n",
                    hash(&fs::read(directory.join(name)).unwrap()),
                    name
                )
            })
            .collect::<String>();
        fs::write(directory.join("checksums.sha256"), &checksums).unwrap();
        let completion = json!({
            "state":"complete",
            "checksums_sha256":hash(checksums.as_bytes())
        });
        fs::write(
            directory.join("completion.json"),
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();
        (root, output_name)
    }

    #[test]
    fn verifies_recovery_export_hashes_inventory_and_completion() {
        let (root, _) = valid_package();
        let result = verify_package(&root.join("export")).unwrap();
        assert_eq!(result.records, 1);
        assert_eq!(result.exported, 1);
        assert_eq!(result.failed, 0);
        assert_eq!(result.state, "complete");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_filename_reference_mismatch_after_package_hashes_are_recomputed() {
        let (root, _) = valid_package();
        let directory = root.join("export");
        let inventory_path = directory.join("inventory.jsonl");
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&fs::read(&inventory_path).unwrap()).unwrap();
        inventory["filename_references"][0]["name"] = json!("forged-alias.txt");
        let inventory_bytes = [serde_json::to_vec(&inventory).unwrap(), b"\n".to_vec()].concat();
        fs::write(&inventory_path, &inventory_bytes).unwrap();

        let checksum_path = directory.join("checksums.sha256");
        let mut checksums = parse_checksums(&fs::read(&checksum_path).unwrap()).unwrap();
        checksums.insert("inventory.jsonl".into(), hash(&inventory_bytes));
        let checksums = checksums
            .iter()
            .map(|(name, digest)| format!("{digest}  {name}\n"))
            .collect::<String>();
        fs::write(&checksum_path, &checksums).unwrap();

        let completion_path = directory.join("completion.json");
        let mut completion: serde_json::Value =
            serde_json::from_slice(&fs::read(&completion_path).unwrap()).unwrap();
        completion["checksums_sha256"] = json!(hash(checksums.as_bytes()));
        fs::write(
            &completion_path,
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();

        let error = verify_package(&directory).unwrap_err();
        assert!(error.contains("selected-record manifest"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_parent_sequence_mismatch_even_when_package_hashes_are_recomputed() {
        let (root, _) = valid_package();
        let directory = root.join("export");
        let inventory_path = directory.join("inventory.jsonl");
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&fs::read(&inventory_path).unwrap()).unwrap();
        inventory["parent_sequence"] = json!(2);
        fs::write(
            &inventory_path,
            format!("{}\n", serde_json::to_string(&inventory).unwrap()),
        )
        .unwrap();

        let mut checksums =
            parse_checksums(&fs::read(directory.join("checksums.sha256")).unwrap()).unwrap();
        checksums.insert(
            "inventory.jsonl".into(),
            hash(&fs::read(&inventory_path).unwrap()),
        );
        let checksums_text = checksums
            .iter()
            .map(|(name, digest)| format!("{digest}  {name}\n"))
            .collect::<String>();
        fs::write(directory.join("checksums.sha256"), &checksums_text).unwrap();

        let completion_path = directory.join("completion.json");
        let mut completion: serde_json::Value =
            serde_json::from_slice(&fs::read(&completion_path).unwrap()).unwrap();
        completion["checksums_sha256"] = json!(hash(checksums_text.as_bytes()));
        fs::write(
            completion_path,
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();

        let error = verify_package(&directory).unwrap_err();
        assert!(error.contains("inventory does not match"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_legacy_recovery_manifests_without_case_linkage() {
        let (root, _) = valid_package();
        let directory = root.join("export");
        let manifest_path = directory.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let source = manifest["source"].as_object_mut().unwrap();
        source.remove("case_id");
        source.remove("evidence_record_id");
        source.remove("scan_session_id");
        manifest["selected_records"][0]
            .as_object_mut()
            .unwrap()
            .remove("parent_sequence");
        let inventory_path = directory.join("inventory.jsonl");
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&fs::read(&inventory_path).unwrap()).unwrap();
        inventory.as_object_mut().unwrap().remove("parent_record");
        inventory.as_object_mut().unwrap().remove("parent_sequence");
        fs::write(
            &inventory_path,
            [serde_json::to_vec(&inventory).unwrap(), b"\n".to_vec()].concat(),
        )
        .unwrap();
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &manifest_bytes).unwrap();

        let checksum_path = directory.join("checksums.sha256");
        let current = parse_checksums(&fs::read(&checksum_path).unwrap()).unwrap();
        let mut updated = current;
        updated.insert("manifest.json".into(), hash(&manifest_bytes));
        updated.insert(
            "inventory.jsonl".into(),
            hash(&fs::read(&inventory_path).unwrap()),
        );
        let checksums = updated
            .iter()
            .map(|(name, digest)| format!("{digest}  {name}\n"))
            .collect::<String>();
        fs::write(&checksum_path, &checksums).unwrap();

        let completion_path = directory.join("completion.json");
        let mut completion: serde_json::Value =
            serde_json::from_slice(&fs::read(&completion_path).unwrap()).unwrap();
        completion["checksums_sha256"] = json!(hash(checksums.as_bytes()));
        fs::write(
            completion_path,
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();

        let verified = verify_package(&directory).unwrap();
        assert_eq!(verified.case_id, None);
        assert_eq!(verified.evidence_record_id, None);
        assert_eq!(verified.scan_session_id, None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_modified_recovery_output() {
        let (root, name) = valid_package();
        fs::write(root.join("export").join(name), b"tampered").unwrap();
        let error = verify_package(&root.join("export")).unwrap_err();
        assert!(error.contains("checksum mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unlisted_recovery_output_entries() {
        let (root, _) = valid_package();
        fs::write(root.join("export").join("extra.txt"), b"unlisted").unwrap();
        let error = verify_package(&root.join("export")).unwrap_err();
        assert!(error.contains("unlisted entries"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unlisted_empty_recovery_directories() {
        let (root, _) = valid_package();
        let directory = root.join("export");
        fs::create_dir(directory.join("unlisted")).unwrap();
        let error = verify_package(&directory).unwrap_err();
        assert!(error.contains("missing or unlisted entries"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_partial_status_for_cancelled_exports() {
        let (root, _) = valid_package();
        let directory = root.join("export");
        let summary_path = directory.join("summary.json");
        let mut summary: serde_json::Value =
            serde_json::from_slice(&fs::read(&summary_path).unwrap()).unwrap();
        summary["cancelled"] = serde_json::Value::Bool(true);
        fs::write(&summary_path, serde_json::to_vec_pretty(&summary).unwrap()).unwrap();

        let mut files = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name != "checksums.sha256" && name != "completion.json")
            })
            .collect::<Vec<_>>();
        files.sort();
        let checksums = files
            .iter()
            .map(|path| {
                format!(
                    "{}  {}\n",
                    hash(&fs::read(path).unwrap()),
                    path.file_name().unwrap().to_string_lossy()
                )
            })
            .collect::<String>();
        fs::write(directory.join("checksums.sha256"), &checksums).unwrap();
        let completion = json!({
            "state":"partial",
            "checksums_sha256":hash(checksums.as_bytes())
        });
        fs::write(
            directory.join("completion.json"),
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();

        let result = verify_package(&directory).unwrap();
        assert_eq!(result.state, "partial");
        assert!(result.cancelled);
        fs::remove_dir_all(root).unwrap();
    }
}
