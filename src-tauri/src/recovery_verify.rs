use crate::{
    audit, err,
    ntfs::DirectoryComponent,
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

#[derive(Debug, Serialize)]
pub struct RecoveryExportVerification {
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

fn read_bounded(directory: &Path, name: &str, maximum: u64) -> Result<Vec<u8>> {
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
    Ok(bytes)
}

fn hash_regular_file(path: &Path) -> Result<(String, u64)> {
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
    Ok((format!("{:x}", digest.finalize()), count))
}

fn validate_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn enumerate_entries(directory: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((folder, relative)) = pending.pop() {
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

pub(crate) fn verify_package(directory: &Path) -> Result<RecoveryExportVerification> {
    crate::safe_file::require_plain_directory(directory).map_err(err)?;
    let (entries, directories) = enumerate_entries(directory)?;
    let checksums_bytes = read_bounded(directory, "checksums.sha256", MAX_CHECKSUMS_BYTES)?;
    let completion_bytes = read_bounded(directory, "completion.json", MAX_METADATA_BYTES)?;
    let summary_bytes = read_bounded(directory, "summary.json", MAX_METADATA_BYTES)?;
    let manifest_bytes = read_bounded(directory, "manifest.json", MAX_METADATA_BYTES)?;
    let inventory_bytes = read_bounded(directory, "inventory.jsonl", MAX_INVENTORY_BYTES)?;

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
            || !validate_hex_digest(&record.record_sha256)
    }) {
        return Err("Recovery manifest contains invalid selected-record metadata.".into());
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
        let (actual_hash, size) = hash_regular_file(&directory.join(name))?;
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

    Ok(RecoveryExportVerification {
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
            "recovery_export_verified",
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

    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
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
            "selected_records":[{"record":7,"name":"deleted.txt","parent_record":5,"parent_sequence":1,"size":data.len(),"storage":"resident","allocation":"unallocated","record_sha256":"b".repeat(64)}],
            "state":"incomplete_until_completion_marker_exists",
            "content_validation":"Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established."
        });
        let inventory = json!({
            "record":7,
            "parent_record":5,
            "parent_sequence":1,
            "original_name":"deleted.txt",
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
