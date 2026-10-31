use crate::ntfs::DirectoryComponent;
use crate::{
    destination,
    ntfs::{self, Candidate, ScanResult, Stream},
    storage::BlockSource,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize, Clone)]
pub struct ExportSummary {
    pub directory: String,
    pub exported: usize,
    pub failed: usize,
    pub cancelled: bool,
}
pub struct SourceIdentity<'a> {
    pub case_id: i64,
    pub evidence_record_id: i64,
    pub scan_session_id: i64,
    pub id: u64,
    pub path: &'a str,
    pub sha256: &'a str,
}
fn hash_source(
    source: &dyn BlockSource,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<Option<String>, String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut position = 0;
    while position < source.len() {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let count = (source.len() - position).min(buffer.len() as u64) as usize;
        source
            .read_exact_at(position, &mut buffer[..count])
            .map_err(|e| e.to_string())?;
        digest.update(&buffer[..count]);
        position += count as u64;
        progress(count as u64);
    }
    Ok(Some(format!("{:x}", digest.finalize())))
}
#[derive(Serialize)]
struct InventoryEntry<'a> {
    record: u64,
    parent_record: Option<u64>,
    parent_sequence: Option<u16>,
    original_name: &'a str,
    output_name: Option<&'a str>,
    path_restored: bool,
    size: u64,
    sha256: Option<String>,
    all_zero: Option<bool>,
    status: &'a str,
    error: Option<String>,
    content_validation: &'a str,
}
pub fn safe_relative_name(
    record: u64,
    name: &str,
    parent_path: Option<&[DirectoryComponent]>,
) -> String {
    let mut parts = parent_path
        .unwrap_or_default()
        .iter()
        .filter(|component| component.record != 5)
        .map(|component| safe_name(component.record, &component.name))
        .collect::<Vec<_>>();
    parts.push(safe_name(record, name));
    parts.join("/")
}

const MAX_EXPORT_RELATIVE_PATH_UTF16: usize = 1024;

fn planned_output_name(candidate: &Candidate) -> (String, bool) {
    if candidate.parent_path.is_some() {
        let restored = safe_relative_name(
            candidate.id,
            &candidate.name,
            candidate.parent_path.as_deref(),
        );
        if restored.encode_utf16().count() <= MAX_EXPORT_RELATIVE_PATH_UTF16 {
            return (restored, true);
        }
    }
    (safe_name(candidate.id, &candidate.name), false)
}

fn safe_package_components(name: &str) -> Result<Vec<&str>, String> {
    let components = name.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > 257
        || components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.encode_utf16().count() > 255
                || component
                    .chars()
                    .any(|c| c.is_control() || "<>:\"\\|?*".contains(c))
                || component.ends_with([' ', '.'])
        })
    {
        return Err("Recovered path is not a safe relative package path.".into());
    }
    Ok(components)
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

fn ensure_output_parent(
    directory: &Path,
    relative_name: &str,
) -> Result<(PathBuf, String), String> {
    let components = safe_package_components(relative_name)?;
    let filename = components.last().ok_or("Recovered path has no filename")?;
    let mut parent = directory.to_path_buf();
    for component in &components[..components.len() - 1] {
        parent.push(component);
        match fs::create_dir(&parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("Could not create recovered directory: {error}")),
        }
        let metadata = fs::symlink_metadata(&parent).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err("Recovered path contains a non-directory or link entry.".into());
        }
    }
    Ok((parent, (*filename).to_owned()))
}

fn remove_empty_parent_dirs(directory: &Path, relative_name: &str) {
    let Ok(components) = safe_package_components(relative_name) else {
        return;
    };
    let mut parent = directory.to_path_buf();
    let mut parents = Vec::new();
    for component in &components[..components.len().saturating_sub(1)] {
        parent.push(component);
        parents.push(parent.clone());
    }
    for parent in parents.into_iter().rev() {
        if fs::remove_dir(parent).is_err() {
            break;
        }
    }
}
struct PartialOutput(PathBuf);
impl Drop for PartialOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn write_checksums(directory: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    let mut directory_count = 0usize;
    while let Some((folder, relative)) = pending.pop() {
        for entry in fs::read_dir(folder).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let file_type = entry.file_type().map_err(|e| e.to_string())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "Recovery output contains a non-UTF-8 name.")?;
            let rel = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            safe_package_components(&rel)?;
            if file_type.is_symlink() || is_reparse_point(&metadata) {
                return Err("Recovery output contains a link entry.".into());
            }
            if file_type.is_dir() {
                directory_count += 1;
                if directory_count > 100_000 {
                    return Err("Recovery output contains too many directories.".into());
                }
                pending.push((entry.path(), rel));
            } else if file_type.is_file() {
                if rel != "checksums.sha256" {
                    files.push((entry.path(), rel));
                    if files.len() > 1005 {
                        return Err("Recovery output contains too many files.".into());
                    }
                }
            } else {
                return Err("Recovery output contains an unsupported entry type.".into());
            }
        }
    }
    files.sort_by(|a, b| a.1.cmp(&b.1));
    let mut checksums = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("checksums.sha256"))
        .map_err(|e| e.to_string())?;
    let mut buffer = vec![0; 1024 * 1024];
    for (path, relative_name) in files {
        let mut file = File::open(&path).map_err(|e| e.to_string())?;
        let mut digest = Sha256::new();
        loop {
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        writeln!(checksums, "{:x}  {}", digest.finalize(), relative_name)
            .map_err(|e| e.to_string())?;
    }
    checksums.sync_all().map_err(|e| e.to_string())
}
fn write_completion_marker(directory: &Path, summary: &ExportSummary) -> Result<(), String> {
    let checksums = fs::read(directory.join("checksums.sha256")).map_err(|e| e.to_string())?;
    let marker = serde_json::json!({
        "state": if summary.cancelled || summary.failed > 0 { "partial" } else { "complete" },
        "checksums_sha256": format!("{:x}", Sha256::digest(checksums)),
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("completion.json"))
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut file, &marker).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

pub fn safe_name(record: u64, name: &str) -> String {
    let tail = name
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .take(100)
        .collect::<String>();
    format!("{record:012}_{}", tail.trim_matches([' ', '.']))
}
fn stream_for_candidate(
    source: &dyn BlockSource,
    scan: &ScanResult,
    candidate: &Candidate,
) -> Result<Stream, String> {
    if !candidate.exportable {
        return Err("This candidate is blocked by its allocation or stream checks.".into());
    }
    let record = ntfs::read_record(source, &scan.boot, &scan.mft, candidate.id)?;
    if record.fingerprint != candidate.fingerprint || !record.deleted {
        return Err("The source record changed after scanning. Rescan before extraction.".into());
    }
    let stream = record
        .stream
        .ok_or("The source record has no unnamed data stream")?;
    if stream.blocked.is_some() || stream.size != candidate.size {
        return Err("The candidate stream is no longer consistent with the scan".into());
    }
    Ok(stream)
}

fn extract_one(
    source: &dyn BlockSource,
    scan: &ScanResult,
    candidate: &Candidate,
    directory: &Path,
    relative_name: &str,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<(String, bool), String> {
    let stream = stream_for_candidate(source, scan, candidate)?;
    let (parent, filename) = ensure_output_parent(directory, relative_name)?;
    let final_path = parent.join(&filename);
    let partial = PartialOutput(parent.join(format!(".{filename}.partial")));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial.0)
        .map_err(|e| {
            format!(
                "Could not create staged output {}: {e}",
                partial.0.display()
            )
        })?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut position = 0;
    let mut digest = Sha256::new();
    let mut all_zero = true;
    while position < stream.size {
        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = (stream.size - position).min(buffer.len() as u64) as usize;
        stream.read_at(source, &scan.boot, position, &mut buffer[..count])?;
        file.write_all(&buffer[..count])
            .map_err(|e| format!("Could not write staged output {}: {e}", partial.0.display()))?;
        digest.update(&buffer[..count]);
        all_zero &= buffer[..count].iter().all(|b| *b == 0);
        position += count as u64;
        progress(count as u64);
    }
    file.sync_all()
        .map_err(|e| format!("Could not flush staged output {}: {e}", partial.0.display()))?;
    drop(file);
    let expected = format!("{:x}", digest.finalize());
    let mut verify = File::open(&partial.0).map_err(|e| e.to_string())?;
    let mut actual = Sha256::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = verify.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        actual.update(&buffer[..count]);
        progress(count as u64);
    }
    if format!("{:x}", actual.finalize()) != expected {
        return Err("Destination verification failed; partial output was discarded".into());
    }
    drop(verify);
    destination::publish_new(&partial.0, &final_path).map_err(|e| {
        format!(
            "Could not publish verified output {}: {e}",
            final_path.display()
        )
    })?;
    Ok((expected, all_zero))
}

pub fn export_to(
    source: &dyn BlockSource,
    scan: &ScanResult,
    selected: &[Candidate],
    destination: &Path,
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<ExportSummary, String> {
    let total = selected
        .iter()
        .try_fold(0u64, |n, c| n.checked_add(c.size.checked_mul(2)?))
        .ok_or("Export size overflow")?
        .checked_add(source.len().checked_mul(2).ok_or("Export size overflow")?)
        .ok_or("Export size overflow")?;
    let mut processed = 0;
    progress(processed, total);
    let before = hash_source(source, cancel, |count| {
        processed += count;
        progress(processed, total);
    })?
    .ok_or("Export cancelled before source verification; no recovery folder was created.")?;
    if before != identity.sha256 {
        return Err("Source SHA-256 changed before export. No recovery folder was created; reopen and investigate the image.".into());
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let directory = destination.join(format!("DaemonCore-Recovery-{stamp}"));
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("manifest.json"))
        .map_err(|e| e.to_string())?;
    let planned_outputs = selected.iter().map(planned_output_name).collect::<Vec<_>>();
    let initial = serde_json::json!({
        "tool": "DaemonCore Data Recovery",
        "version": env!("CARGO_PKG_VERSION"),
        "hash_algorithm": "SHA-256",
        "export_started_unix_ns": stamp.to_string(),
        "source": {
            "case_id": identity.case_id,
            "evidence_record_id": identity.evidence_record_id,
            "scan_session_id": identity.scan_session_id,
            "session_id": identity.id,
            "path": identity.path,
            "size": source.len(),
            "sha256_before_export": identity.sha256,
        },
        "volume": scan.boot,
        "selected_records": selected.iter().zip(&planned_outputs).map(|(c, (output_name, path_restored))| serde_json::json!({
            "record": c.id,
            "name": c.name,
            "parent_record": c.parent_record,
            "parent_sequence": c.parent_sequence,
            "parent_path": c.parent_path,
            "output_name": output_name,
            "path_restored": path_restored,
            "size": c.size,
            "storage": c.storage,
            "allocation": c.allocation,
            "record_sha256": c.fingerprint,
        })).collect::<Vec<_>>(),
        "state": "incomplete_until_completion_marker_exists",
        "content_validation": "Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established.",
    });
    serde_json::to_writer_pretty(&mut manifest, &initial).map_err(|e| e.to_string())?;
    manifest.sync_all().map_err(|e| e.to_string())?;
    let mut inventory = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("inventory.jsonl"))
        .map_err(|e| e.to_string())?;
    let mut summary = ExportSummary {
        directory: directory.to_string_lossy().into(),
        exported: 0,
        failed: 0,
        cancelled: false,
    };
    for (candidate, (name, path_restored)) in selected.iter().zip(&planned_outputs) {
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
        let result = extract_one(source, scan, candidate, &directory, name, cancel, |n| {
            processed += n;
            progress(processed, total);
        });
        let entry = match result {
            Ok((hash, all_zero)) => {
                summary.exported += 1;
                InventoryEntry {
                    record: candidate.id,
                    parent_record: Some(candidate.parent_record),
                    parent_sequence: Some(candidate.parent_sequence),
                    original_name: &candidate.name,
                    output_name: Some(name),
                    path_restored: *path_restored,
                    size: candidate.size,
                    sha256: Some(hash),
                    all_zero: Some(all_zero),
                    status: "destination_hash_verified",
                    error: None,
                    content_validation: "not performed",
                }
            }
            Err(e) => {
                remove_empty_parent_dirs(&directory, name);
                summary.failed += 1;
                InventoryEntry {
                    record: candidate.id,
                    parent_record: Some(candidate.parent_record),
                    parent_sequence: Some(candidate.parent_sequence),
                    original_name: &candidate.name,
                    output_name: None,
                    path_restored: *path_restored,
                    size: candidate.size,
                    sha256: None,
                    all_zero: None,
                    status: "failed",
                    error: Some(e),
                    content_validation: "not performed",
                }
            }
        };
        serde_json::to_writer(&mut inventory, &entry).map_err(|e| e.to_string())?;
        inventory.write_all(b"\n").map_err(|e| e.to_string())?;
        inventory.sync_all().map_err(|e| e.to_string())?;
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
    }
    if cancel.load(Ordering::Relaxed) {
        summary.cancelled = true;
        let mut final_manifest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("summary.json"))
            .map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(&mut final_manifest, &summary).map_err(|e| e.to_string())?;
        final_manifest.sync_all().map_err(|e| e.to_string())?;
        drop(final_manifest);
        write_checksums(&directory)?;
        write_completion_marker(&directory, &summary)?;
        return Ok(summary);
    }
    let after = hash_source(source, cancel, |count| {
        processed += count;
        progress(processed, total);
    })?
    .ok_or(
        "Source integrity recheck was cancelled; the recovery folder has no completion marker.",
    )?;
    if after != identity.sha256 {
        return Err("Source SHA-256 changed during export. The recovery folder has no completion summary; quarantine this working copy and investigate the change.".into());
    }
    let mut final_manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("summary.json"))
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut final_manifest, &summary).map_err(|e| e.to_string())?;
    final_manifest.sync_all().map_err(|e| e.to_string())?;
    drop(final_manifest);
    write_checksums(&directory)?;
    write_completion_marker(&directory, &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_names_cannot_escape_or_be_windows_devices() {
        assert_eq!(safe_name(16, "../CON:stream"), "000000000016__CON_stream");
        assert!(!safe_name(17, "a/b\\c").contains(['/', '\\', ':']));
        assert!(safe_name(1, "NUL").starts_with("000000000001_"));
    }

    #[test]
    fn verified_paths_over_the_package_bound_fall_back_to_flat_names() {
        let mut parent_path = (30..50)
            .map(|record| ntfs::DirectoryComponent {
                record,
                name: "evidence-folder".repeat(8),
                sequence: 1,
                parent_record: record + 1,
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
        let candidate = Candidate {
            id: 90,
            name: "evidence.bin".into(),
            parent_record: 30,
            parent_sequence: 1,
            parent_ambiguous: false,
            parent_path: Some(parent_path),
            size: 1,
            deleted: true,
            storage: "resident".into(),
            allocation: "resident".into(),
            exportable: true,
            notes: Vec::new(),
            fingerprint: "a".repeat(64),
            created_filetime: None,
            modified_filetime: None,
        };
        let (name, restored) = planned_output_name(&candidate);
        assert_eq!(name, safe_name(candidate.id, &candidate.name));
        assert!(!restored);
    }
}
