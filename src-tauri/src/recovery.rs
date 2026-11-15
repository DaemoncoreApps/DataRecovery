use crate::ntfs::DirectoryComponent;
use crate::{
    destination, err,
    ntfs::{self, Candidate, ScanResult, Stream},
    storage::BlockSource,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
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

struct ExportFolder<'a> {
    created_unix_ns: u128,
    directory: &'a Path,
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
    filename_references: &'a [ntfs::FilenameReference],
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

static PARTIAL_OUTPUT_ID: AtomicU64 = AtomicU64::new(0);

fn create_partial_output(parent: &Path, filename: &str) -> Result<(PartialOutput, File), String> {
    // A process crash can leave an older partial behind. Give each attempt its own
    // create-new path so recovery can be retried without touching that evidence.
    for _ in 0..16 {
        let id = PARTIAL_OUTPUT_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{filename}.partial-{}-{id}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((PartialOutput(path), file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "Could not create staged output {}: {error}",
                    path.display()
                ))
            }
        }
    }
    Err("Could not allocate a unique staged recovery output after repeated collisions.".into())
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
    let (partial, mut file) = create_partial_output(&parent, &filename)?;
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
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let directory = destination.join(format!("DaemonCore-Recovery-{stamp}"));
    let result = export_to_directory(
        source,
        scan,
        selected,
        identity,
        cancel,
        &mut progress,
        ExportFolder {
            created_unix_ns: stamp,
            directory: &directory,
        },
    );
    report_incomplete_export_path(result, &directory)
}

fn report_incomplete_export_path<T>(
    result: Result<T, String>,
    directory: &Path,
) -> Result<T, String> {
    match result {
        Err(error) if directory.exists() => Err(format!(
            "{error} A partial recovery folder may remain at {}. Treat it as unverified until the package verifier accepts it.",
            directory.display()
        )),
        result => result,
    }
}

fn export_to_directory(
    source: &dyn BlockSource,
    scan: &ScanResult,
    selected: &[Candidate],
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    folder: ExportFolder<'_>,
) -> Result<ExportSummary, String> {
    let stamp = folder.created_unix_ns;
    let directory = folder.directory;
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
    fs::create_dir(directory).map_err(|e| e.to_string())?;
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
            "filename_references": c.filename_references,
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
        let result = extract_one(source, scan, candidate, directory, name, cancel, |n| {
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
                    filename_references: &candidate.filename_references,
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
                remove_empty_parent_dirs(directory, name);
                summary.failed += 1;
                InventoryEntry {
                    record: candidate.id,
                    parent_record: Some(candidate.parent_record),
                    parent_sequence: Some(candidate.parent_sequence),
                    original_name: &candidate.name,
                    filename_references: &candidate.filename_references,
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
        write_checksums(directory)?;
        write_completion_marker(directory, &summary)?;
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
    write_checksums(directory)?;
    write_completion_marker(directory, &summary)?;
    Ok(summary)
}

struct Fat32ExportContext<'a> {
    source: &'a dyn BlockSource,
    volume: &'a daemoncore_ntfs_core::fat32::Volume,
    directory: &'a Path,
    cancel: &'a AtomicBool,
}

fn extract_fat32_one(
    context: &Fat32ExportContext<'_>,
    deleted: &daemoncore_ntfs_core::fat32::DeletedFileMapping,
    entry: &daemoncore_ntfs_core::fat32::DirectoryEntry,
    relative_name: &str,
    mut progress: impl FnMut(u64),
) -> Result<(String, bool), String> {
    if !entry.deleted || entry.is_directory() || entry.is_volume_label() || entry.size == 0 {
        return Err("Only nonempty deleted FAT32 file entries can be exported.".into());
    }
    let (parent, filename) = ensure_output_parent(context.directory, relative_name)?;
    let final_path = parent.join(&filename);
    let (partial, mut file) = create_partial_output(&parent, &filename)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut position = 0_u64;
    let mut digest = Sha256::new();
    let mut all_zero = true;
    while position < u64::from(entry.size) {
        if context.cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = (u64::from(entry.size) - position).min(buffer.len() as u64) as usize;
        context.volume.read_file_at(
            context.source,
            deleted.mapping(),
            position,
            &mut buffer[..count],
        )?;
        file.write_all(&buffer[..count]).map_err(|error| {
            format!(
                "Could not write staged output {}: {error}",
                partial.0.display()
            )
        })?;
        digest.update(&buffer[..count]);
        all_zero &= buffer[..count].iter().all(|byte| *byte == 0);
        position += count as u64;
        progress(count as u64);
    }
    file.sync_all().map_err(|error| {
        format!(
            "Could not flush staged output {}: {error}",
            partial.0.display()
        )
    })?;
    drop(file);

    let expected = format!("{:x}", digest.finalize());
    let mut verify = File::open(&partial.0).map_err(err)?;
    let mut actual = Sha256::new();
    loop {
        if context.cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = verify.read(&mut buffer).map_err(err)?;
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
    destination::publish_new(&partial.0, &final_path).map_err(|error| {
        format!(
            "Could not publish verified output {}: {error}",
            final_path.display()
        )
    })?;
    Ok((expected, all_zero))
}

pub fn export_fat32_to(
    source: &dyn BlockSource,
    volume_offset: u64,
    selected: &[daemoncore_ntfs_core::fat32::TreeEntry],
    destination: &Path,
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<ExportSummary, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let directory = destination.join(format!("DaemonCore-Recovery-{stamp}"));
    let result = export_fat32_to_directory(
        source,
        volume_offset,
        selected,
        identity,
        cancel,
        &mut progress,
        ExportFolder {
            created_unix_ns: stamp,
            directory: &directory,
        },
    );
    report_incomplete_export_path(result, &directory)
}

fn export_fat32_to_directory(
    source: &dyn BlockSource,
    volume_offset: u64,
    selected: &[daemoncore_ntfs_core::fat32::TreeEntry],
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    folder: ExportFolder<'_>,
) -> Result<ExportSummary, String> {
    let stamp = folder.created_unix_ns;
    let directory = folder.directory;
    let volume = daemoncore_ntfs_core::fat32::Volume::open(
        source,
        volume_offset,
        source.len().saturating_sub(volume_offset),
    )?;
    let current_entries = volume
        .read_tree_including_deleted(source)?
        .into_iter()
        .map(|tree_entry| (tree_entry.entry.source_offset, tree_entry))
        .collect::<BTreeMap<_, _>>();
    let mut selected_offsets = BTreeSet::new();
    let entries: Vec<daemoncore_ntfs_core::fat32::TreeEntry> = selected
        .iter()
        .map(|tree_entry| {
            let entry = &tree_entry.entry;
            let source_offset = entry.source_offset;
            if !selected_offsets.insert(source_offset)
                || !entry.deleted
                || entry.is_directory()
                || entry.is_volume_label()
                || entry.size == 0
            {
                return Err(
                    "A selected FAT32 entry is duplicated or is not a recoverable file record."
                        .into(),
                );
            }
            let current = current_entries
                .get(&source_offset)
                .ok_or("A selected FAT32 record is no longer present in the source image.")?;
            if current.entry.raw_record != entry.raw_record
                || !current.entry.deleted
                || current.entry.size != entry.size
                || current.entry.first_cluster != entry.first_cluster
                || current.entry.is_directory()
                || current.entry.is_volume_label()
            {
                return Err(
                    "A selected FAT32 record changed or is no longer a deleted file entry.".into(),
                );
            }
            Ok(current.clone())
        })
        .collect::<Result<_, String>>()?;
    if entries.is_empty() || entries.len() > 1000 {
        return Err("Select between 1 and 1,000 deleted FAT32 files.".into());
    }
    let selected_clusters = entries
        .iter()
        .try_fold(0_u64, |total, item| {
            total.checked_add(u64::from(item.entry.size).div_ceil(volume.cluster_size()))
        })
        .ok_or("FAT32 recovery cluster count overflow")?;
    if selected_clusters > 1_000_000 {
        return Err("Selected FAT32 files exceed the 1,000,000-cluster recovery limit.".into());
    }
    let mappings = entries
        .iter()
        .map(|item| {
            volume.map_deleted_file_contiguous(
                source,
                item.entry.first_cluster,
                u64::from(item.entry.size),
            )
        })
        .collect::<Vec<_>>();
    let mut cluster_owners: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (index, mapping) in mappings.iter().enumerate() {
        if let Ok(mapping) = mapping {
            for cluster in mapping.mapping().clusters() {
                cluster_owners.entry(*cluster).or_default().push(index);
            }
        }
    }
    let mut overlaps = vec![false; mappings.len()];
    for owners in cluster_owners.values().filter(|owners| owners.len() > 1) {
        for owner in owners {
            overlaps[*owner] = true;
        }
    }
    let expected_total = selected
        .iter()
        .try_fold(0_u64, |total, item| {
            total.checked_add(u64::from(item.entry.size).checked_mul(2)?)
        })
        .ok_or("Export size overflow")?;
    let total = expected_total
        .checked_add(source.len().checked_mul(2).ok_or("Export size overflow")?)
        .ok_or("Export size overflow")?;
    let mut processed = 0_u64;
    progress(processed, total);
    let before = hash_source(source, cancel, |count| {
        processed = processed.saturating_add(count);
        progress(processed, total);
    })?
    .ok_or("Export cancelled before source verification; no recovery folder was created.")?;
    if before != identity.sha256 {
        return Err("Source SHA-256 changed before FAT32 export. No recovery folder was created; reopen and investigate the image.".into());
    }
    fs::create_dir(directory).map_err(err)?;
    let extract_context = Fat32ExportContext {
        source,
        volume: &volume,
        directory,
        cancel,
    };
    let selected_records = entries
        .iter()
        .map(|tree_entry| {
            let entry = &tree_entry.entry;
            let record = entry.source_offset;
            serde_json::json!({
                "record": record,
                "name": entry.display_name(),
                "parent_record": 5,
                "parent_sequence": null,
                "parent_path": null,
                "filename_references": [],
                "output_name": safe_name(record, &entry.display_name()),
                "path_restored": false,
                "size": entry.size,
                "storage": "contiguous_assumed",
                "allocation": "free_contiguous_clusters",
                "record_sha256": format!("{:x}", Sha256::digest(entry.raw_record)),
            })
        })
        .collect::<Vec<_>>();
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("manifest.json"))
        .map_err(err)?;
    serde_json::to_writer_pretty(
        &mut manifest,
        &serde_json::json!({
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
            "volume": {
                "filesystem": "FAT32",
                "volume_offset": volume_offset,
                "volume_size": volume.volume_size(),
                "cluster_size": volume.cluster_size(),
                "cluster_count": volume.cluster_count(),
                "root_cluster": volume.root_cluster(),
                "deleted_file_layout": "contiguous_assumed_only_when_candidate_clusters_are_free",
                "selected_cluster_overlap_check": "selected_entries_only_other_deleted_entries_may_reference_the_same_clusters",
            },
            "selected_records": selected_records,
            "state": "incomplete_until_completion_marker_exists",
            "content_validation": "Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established."
        }),
    )
    .map_err(err)?;
    manifest.sync_all().map_err(err)?;
    let mut inventory = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("inventory.jsonl"))
        .map_err(err)?;
    let mut summary = ExportSummary {
        directory: directory.to_string_lossy().into_owned(),
        exported: 0,
        failed: 0,
        cancelled: false,
    };
    for (index, tree_entry) in entries.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
        let entry = &tree_entry.entry;
        let name = entry.display_name();
        let output_name = safe_name(entry.source_offset, &name);
        let result = if overlaps[index] {
            Err("Selected deleted entries overlap the same assumed cluster range; neither was exported.".into())
        } else {
            match &mappings[index] {
                Ok(mapping) => {
                    extract_fat32_one(&extract_context, mapping, entry, &output_name, |count| {
                        processed = processed.saturating_add(count);
                        progress(processed, total);
                    })
                }
                Err(error) => Err(error.clone()),
            }
        };
        let item = match result {
            Ok((sha256, all_zero)) => {
                summary.exported += 1;
                serde_json::json!({
                    "record": entry.source_offset,
                    "parent_record": 5,
                    "parent_sequence": null,
                    "original_name": name,
                    "filename_references": [],
                    "output_name": output_name,
                    "path_restored": false,
                    "size": entry.size,
                    "sha256": sha256,
                    "all_zero": all_zero,
                    "status": "destination_hash_verified",
                    "error": null,
                    "content_validation": "not performed",
                })
            }
            Err(error) => {
                summary.failed += 1;
                serde_json::json!({
                    "record": entry.source_offset,
                    "parent_record": 5,
                    "parent_sequence": null,
                    "original_name": name,
                    "filename_references": [],
                    "output_name": null,
                    "path_restored": false,
                    "size": entry.size,
                    "sha256": null,
                    "all_zero": null,
                    "status": "failed",
                    "error": error,
                    "content_validation": "not performed",
                })
            }
        };
        serde_json::to_writer(&mut inventory, &item).map_err(err)?;
        inventory.write_all(b"\n").map_err(err)?;
        inventory.sync_all().map_err(err)?;
    }
    drop(inventory);
    if cancel.load(Ordering::Relaxed) {
        summary.cancelled = true;
        let mut final_summary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("summary.json"))
            .map_err(err)?;
        serde_json::to_writer_pretty(&mut final_summary, &summary).map_err(err)?;
        final_summary.sync_all().map_err(err)?;
        drop(final_summary);
        write_checksums(directory)?;
        write_completion_marker(directory, &summary)?;
        return Ok(summary);
    }
    let after = hash_source(source, cancel, |count| {
        processed = processed.saturating_add(count);
        progress(processed, total);
    })?
    .ok_or(
        "Source integrity recheck was cancelled; the recovery folder has no completion marker.",
    )?;
    if after != identity.sha256 {
        return Err("Source SHA-256 changed during FAT32 export. The recovery folder has no completion marker; quarantine this working copy and investigate the change.".into());
    }
    let mut final_summary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("summary.json"))
        .map_err(err)?;
    serde_json::to_writer_pretty(&mut final_summary, &summary).map_err(err)?;
    final_summary.sync_all().map_err(err)?;
    drop(final_summary);
    write_checksums(directory)?;
    write_completion_marker(directory, &summary)?;
    Ok(summary)
}

pub fn export_exfat_to(
    source: &dyn BlockSource,
    volume_offset: u64,
    selected: &[daemoncore_ntfs_core::exfat::TreeEntry],
    destination: &Path,
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<ExportSummary, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let directory = destination.join(format!("DaemonCore-Recovery-{stamp}"));
    let result = export_exfat_to_directory(
        source,
        volume_offset,
        selected,
        identity,
        cancel,
        &mut progress,
        ExportFolder {
            created_unix_ns: stamp,
            directory: &directory,
        },
    );
    report_incomplete_export_path(result, &directory)
}

fn export_exfat_to_directory(
    source: &dyn BlockSource,
    volume_offset: u64,
    selected: &[daemoncore_ntfs_core::exfat::TreeEntry],
    identity: SourceIdentity<'_>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    folder: ExportFolder<'_>,
) -> Result<ExportSummary, String> {
    use daemoncore_ntfs_core::exfat;

    if selected.is_empty() || selected.len() > 1000 {
        return Err("Select between 1 and 1,000 deleted exFAT files.".into());
    }
    let stamp = folder.created_unix_ns;
    let directory = folder.directory;
    let volume = exfat::Volume::open(
        source,
        volume_offset,
        source.len().saturating_sub(volume_offset),
    )?;
    let entries = selected.iter().map(|item| &item.entry).collect::<Vec<_>>();
    let mappings = volume.prepare_deleted_files(source, &entries)?;
    let mut offsets = BTreeSet::new();
    let mut cluster_owners: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut overlaps = vec![false; selected.len()];
    let mut file_bytes = 0_u64;
    let mut selected_clusters = 0_u64;
    for (index, item) in selected.iter().enumerate() {
        if !offsets.insert(item.entry.source_offset) {
            return Err("An exFAT directory entry was selected more than once.".into());
        }
        file_bytes = file_bytes
            .checked_add(item.entry.data_length)
            .ok_or("exFAT recovery size overflow.")?;
        selected_clusters = selected_clusters
            .checked_add(item.entry.data_length.div_ceil(volume.cluster_size()))
            .ok_or("exFAT recovery cluster count overflow.")?;
        if selected_clusters > 1_000_000 {
            return Err("Selected exFAT files exceed the 1,000,000-cluster recovery limit.".into());
        }
        if let Ok(mapping) = &mappings[index] {
            for cluster in u64::from(mapping.first_cluster())
                ..u64::from(mapping.first_cluster())
                    + mapping.data_length().div_ceil(volume.cluster_size())
            {
                cluster_owners.entry(cluster).or_default().push(index);
            }
        }
    }
    for owners in cluster_owners.values().filter(|owners| owners.len() > 1) {
        for owner in owners {
            overlaps[*owner] = true;
        }
    }
    let total = file_bytes
        .checked_mul(2)
        .and_then(|bytes| {
            source
                .len()
                .checked_mul(2)
                .and_then(|image| bytes.checked_add(image))
        })
        .ok_or("exFAT recovery progress total overflow.")?;
    let mut processed = 0_u64;
    progress(processed, total);
    let before = hash_source(source, cancel, |count| {
        processed = processed.saturating_add(count);
        progress(processed, total);
    })?
    .ok_or("Export cancelled before source verification; no recovery folder was created.")?;
    if before != identity.sha256 {
        return Err("Source SHA-256 changed before exFAT export. No recovery folder was created; reopen and investigate the image.".into());
    }
    fs::create_dir(directory).map_err(err)?;
    let selected_records = selected
        .iter()
        .map(|item| {
            let entry = &item.entry;
            let raw = entry
                .raw_entries
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            serde_json::json!({
                "record": entry.source_offset,
                "name": entry.name,
                "parent_record": 5,
                "parent_sequence": null,
                "parent_path": null,
                "filename_references": [],
                "output_name": safe_name(entry.source_offset, &entry.name),
                "path_restored": false,
                "size": entry.data_length,
                "storage": "contiguous_declared",
                "allocation": "free_in_current_bitmap",
                "record_sha256": format!("{:x}", Sha256::digest(raw)),
            })
        })
        .collect::<Vec<_>>();
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("manifest.json"))
        .map_err(err)?;
    serde_json::to_writer_pretty(&mut manifest, &serde_json::json!({
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
        "volume": {
            "filesystem": "exFAT",
            "volume_offset": volume_offset,
            "volume_size": volume.volume_size(),
            "cluster_size": volume.cluster_size(),
            "cluster_count": volume.cluster_count(),
            "root_cluster": volume.root_cluster(),
            "deleted_file_layout": "contiguous_declared_by_entry_set_and_free_in_allocation_bitmap",
            "selected_cluster_overlap_check": "overlapping_selected_ranges_are_not_exported",
        },
        "selected_records": selected_records,
        "state": "incomplete_until_completion_marker_exists",
        "content_validation": "Export verification compares the reconstructed stream with destination bytes. Original file content integrity is not established."
    })).map_err(err)?;
    manifest.sync_all().map_err(err)?;
    let mut inventory = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("inventory.jsonl"))
        .map_err(err)?;
    let mut summary = ExportSummary {
        directory: directory.to_string_lossy().into_owned(),
        exported: 0,
        failed: 0,
        cancelled: false,
    };
    for (index, item) in selected.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
        let entry = &item.entry;
        let name = &entry.name;
        let output_name = safe_name(entry.source_offset, name);
        let result = if overlaps[index] {
            Err("Selected deleted exFAT entries overlap the same assumed cluster range; neither was exported.".into())
        } else {
            match &mappings[index] {
                Ok(mapping) => {
                    extract_exfat_one(source, &volume, mapping, directory, cancel, item, |count| {
                        processed = processed.saturating_add(count);
                        progress(processed, total);
                    })
                }
                Err(error) => Err(error.clone()),
            }
        };
        let record = match result {
            Ok((sha256, all_zero)) => {
                summary.exported += 1;
                serde_json::json!({"record":entry.source_offset,"parent_record":5,"parent_sequence":null,"original_name":name,"filename_references":[],"output_name":output_name,"path_restored":false,"size":entry.data_length,"sha256":sha256,"all_zero":all_zero,"status":"destination_hash_verified","error":null,"content_validation":"not performed"})
            }
            Err(error) => {
                summary.failed += 1;
                serde_json::json!({"record":entry.source_offset,"parent_record":5,"parent_sequence":null,"original_name":name,"filename_references":[],"output_name":null,"path_restored":false,"size":entry.data_length,"sha256":null,"all_zero":null,"status":"failed","error":error,"content_validation":"not performed"})
            }
        };
        serde_json::to_writer(&mut inventory, &record).map_err(err)?;
        inventory.write_all(b"\n").map_err(err)?;
        inventory.sync_all().map_err(err)?;
    }
    drop(inventory);
    if cancel.load(Ordering::Relaxed) {
        summary.cancelled = true;
    }
    if !summary.cancelled {
        let after = hash_source(source, cancel, |count| {
            processed = processed.saturating_add(count);
            progress(processed, total);
        })?
        .ok_or(
            "Source integrity recheck was cancelled; the recovery folder has no completion marker.",
        )?;
        if after != identity.sha256 {
            return Err("Source SHA-256 changed during exFAT export. The recovery folder has no completion marker; quarantine this working copy and investigate the change.".into());
        }
    } else {
        summary.cancelled = true;
    }
    let mut summary_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("summary.json"))
        .map_err(err)?;
    serde_json::to_writer_pretty(&mut summary_file, &summary).map_err(err)?;
    summary_file.sync_all().map_err(err)?;
    drop(summary_file);
    write_checksums(directory)?;
    write_completion_marker(directory, &summary)?;
    Ok(summary)
}

fn extract_exfat_one(
    source: &dyn BlockSource,
    volume: &daemoncore_ntfs_core::exfat::Volume,
    stream: &daemoncore_ntfs_core::exfat::DeletedFileStream,
    directory: &Path,
    cancel: &AtomicBool,
    entry: &daemoncore_ntfs_core::exfat::TreeEntry,
    mut progress: impl FnMut(u64),
) -> Result<(String, bool), String> {
    let output_name = safe_name(entry.entry.source_offset, &entry.entry.name);
    let (parent, filename) = ensure_output_parent(directory, &output_name)?;
    let final_path = parent.join(&filename);
    let (partial, mut file) = create_partial_output(&parent, &filename)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut position = 0_u64;
    let mut digest = Sha256::new();
    let mut all_zero = true;
    while position < stream.data_length() {
        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = (stream.data_length() - position).min(buffer.len() as u64) as usize;
        volume.read_deleted_file_range(source, stream, position, &mut buffer[..count])?;
        file.write_all(&buffer[..count]).map_err(|error| {
            format!(
                "Could not write staged exFAT output {}: {error}",
                partial.0.display()
            )
        })?;
        digest.update(&buffer[..count]);
        all_zero &= buffer[..count].iter().all(|byte| *byte == 0);
        position += count as u64;
        progress(count as u64);
    }
    file.sync_all().map_err(|error| {
        format!(
            "Could not flush staged exFAT output {}: {error}",
            partial.0.display()
        )
    })?;
    drop(file);
    let expected = format!("{:x}", digest.finalize());
    let mut verify = File::open(&partial.0).map_err(err)?;
    let mut actual = Sha256::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Export cancelled".into());
        }
        let count = verify.read(&mut buffer).map_err(err)?;
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
    destination::publish_new(&partial.0, &final_path).map_err(|error| {
        format!(
            "Could not publish verified exFAT output for record {}: {error}",
            entry.entry.source_offset
        )
    })?;
    Ok((expected, all_zero))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemorySource;

    fn exfat_deleted_fixture() -> (MemorySource, Vec<u8>) {
        const SECTOR: usize = 512;
        let mut image = vec![0; 2048 * SECTOR];
        for boot_start in [0, 12 * SECTOR] {
            let region = &mut image[boot_start..boot_start + 12 * SECTOR];
            region[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
            region[3..11].copy_from_slice(b"EXFAT   ");
            region[72..80].copy_from_slice(&2048_u64.to_le_bytes());
            region[80..84].copy_from_slice(&24_u32.to_le_bytes());
            region[84..88].copy_from_slice(&16_u32.to_le_bytes());
            region[88..92].copy_from_slice(&40_u32.to_le_bytes());
            region[92..96].copy_from_slice(&2008_u32.to_le_bytes());
            region[96..100].copy_from_slice(&2_u32.to_le_bytes());
            region[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
            region[108] = 9;
            region[110] = 1;
            region[112] = 0xff;
            region[510..512].copy_from_slice(&[0x55, 0xaa]);
            for index in 1..=8 {
                let end = (index + 1) * SECTOR;
                region[end - 4..end].copy_from_slice(&[0, 0, 0x55, 0xaa]);
            }
            let mut checksum = 0_u32;
            for (index, byte) in region[..11 * SECTOR].iter().enumerate() {
                if !matches!(index, 106 | 107 | 112) {
                    checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
                }
            }
            for word in region[11 * SECTOR..12 * SECTOR].chunks_mut(4) {
                word.copy_from_slice(&checksum.to_le_bytes());
            }
        }
        for cluster in 2..=4 {
            let at = 24 * SECTOR + cluster * 4;
            image[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let heap = 40 * SECTOR;
        let mut root = [0_u8; SECTOR];
        root[0] = 0x81;
        root[20..24].copy_from_slice(&4_u32.to_le_bytes());
        root[24..32].copy_from_slice(&251_u64.to_le_bytes());
        root[32] = 0x82;
        root[52..56].copy_from_slice(&3_u32.to_le_bytes());
        let mut upcase = Vec::new();
        for unit in 0..97_u16 {
            upcase.extend_from_slice(&unit.to_le_bytes());
        }
        for unit in b'A' as u16..=b'Z' as u16 {
            upcase.extend_from_slice(&unit.to_le_bytes());
        }
        upcase.extend_from_slice(&0xffff_u16.to_le_bytes());
        upcase.extend_from_slice(&65_413_u16.to_le_bytes());
        let mut upcase_checksum = 0_u32;
        for byte in &upcase {
            upcase_checksum = upcase_checksum
                .rotate_right(1)
                .wrapping_add(u32::from(*byte));
        }
        root[36..40].copy_from_slice(&upcase_checksum.to_le_bytes());
        root[56..64].copy_from_slice(&(upcase.len() as u64).to_le_bytes());
        root[64] = 0x85;
        root[65] = 2;
        root[68..70].copy_from_slice(&0x20_u16.to_le_bytes());
        root[96] = 0xc0;
        root[97] = 3;
        root[99] = 11;
        root[104..112].copy_from_slice(&512_u64.to_le_bytes());
        root[116..120].copy_from_slice(&5_u32.to_le_bytes());
        root[120..128].copy_from_slice(&512_u64.to_le_bytes());
        root[128] = 0xc1;
        let name: Vec<u16> = "RECOVER.BIN".encode_utf16().collect();
        let mut name_hash = 0_u16;
        for (index, unit) in name.iter().enumerate() {
            root[130 + index * 2..132 + index * 2].copy_from_slice(&unit.to_le_bytes());
            for byte in unit.to_le_bytes() {
                name_hash = name_hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        root[100..102].copy_from_slice(&name_hash.to_le_bytes());
        let set = root[64..160]
            .chunks_exact(32)
            .map(|record| record.try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();
        let mut entry_checksum = 0_u16;
        for (record_index, record) in set.iter().enumerate() {
            for (byte_index, byte) in record.iter().enumerate() {
                if record_index != 0 || !matches!(byte_index, 2 | 3) {
                    entry_checksum = entry_checksum
                        .rotate_right(1)
                        .wrapping_add(u16::from(*byte));
                }
            }
        }
        root[66..68].copy_from_slice(&entry_checksum.to_le_bytes());
        for record in root[64..160].chunks_exact_mut(32) {
            record[0] &= 0x7f;
        }
        image[heap..heap + SECTOR].copy_from_slice(&root);
        image[heap + SECTOR..heap + SECTOR + upcase.len()].copy_from_slice(&upcase);
        image[heap + 2 * SECTOR] = 0b0000_0111;
        let expected = vec![0x5a; SECTOR];
        image[heap + 3 * SECTOR..heap + 4 * SECTOR].copy_from_slice(&expected);
        (MemorySource(image), expected)
    }

    fn fat32_deleted_fixture() -> (MemorySource, Vec<u8>) {
        const SECTOR: usize = 512;
        const TOTAL_SECTORS: usize = 66_581;
        const DATA_SECTOR: usize = 1056;
        let mut image = vec![0; TOTAL_SECTORS * SECTOR];
        let mut boot = [0; SECTOR];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&(TOTAL_SECTORS as u32).to_le_bytes());
        boot[36..40].copy_from_slice(&512_u32.to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[67..71].copy_from_slice(&0xdcdc_0201_u32.to_le_bytes());
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        image[..SECTOR].copy_from_slice(&boot);
        image[6 * SECTOR..7 * SECTOR].copy_from_slice(&boot);

        for fat_sector in [32, 544] {
            let root_entry = fat_sector * SECTOR + 2 * 4;
            image[root_entry..root_entry + 4].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
        }

        let record_offset = DATA_SECTOR * SECTOR;
        image[record_offset] = 0xe5;
        image[record_offset + 1..record_offset + 8].copy_from_slice(b"ECOVER ");
        image[record_offset + 8..record_offset + 11].copy_from_slice(b"BIN");
        image[record_offset + 11] = 0x20;
        image[record_offset + 26..record_offset + 28].copy_from_slice(&3_u16.to_le_bytes());
        let expected = (0..65_536).map(|byte| byte as u8).collect::<Vec<_>>();
        image[DATA_SECTOR * SECTOR + SECTOR..DATA_SECTOR * SECTOR + SECTOR + expected.len()]
            .copy_from_slice(&expected);
        image[record_offset + 28..record_offset + 32]
            .copy_from_slice(&(expected.len() as u32).to_le_bytes());
        (MemorySource(image), expected)
    }

    fn recovery_test_directory(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("{label}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn interrupted_partial_does_not_block_a_new_recovery_attempt() {
        let directory = recovery_test_directory("stale-partial");
        let stale = directory.join(".recovered.bin.partial");
        fs::write(&stale, b"preserve interrupted output").unwrap();

        let (partial, mut file) = create_partial_output(&directory, "recovered.bin").unwrap();
        assert_ne!(partial.0, stale);
        file.write_all(b"new verified output").unwrap();
        drop(file);
        let staged_path = partial.0.clone();
        drop(partial);

        assert_eq!(fs::read(&stale).unwrap(), b"preserve interrupted output");
        assert!(!staged_path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_recovery_export_reports_the_unverified_folder_path() {
        let root = recovery_test_directory("failed-export-path");
        let partial = root.join("DaemonCore-Recovery-incomplete");
        fs::create_dir(&partial).unwrap();

        let error = report_incomplete_export_path::<()>(Err("source changed".into()), &partial)
            .unwrap_err();

        assert!(error.contains("source changed"));
        assert!(error.contains(&partial.to_string_lossy().to_string()));
        assert!(error.contains("Treat it as unverified"));
        assert!(crate::recovery_verify::verify_package(&partial).is_err());
        let no_folder_error = report_incomplete_export_path::<()>(
            Err("source changed before output".into()),
            &root.join("not-created"),
        )
        .unwrap_err();
        assert!(no_folder_error.contains("source changed before output"));
        assert!(!no_folder_error.contains("not-created"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fat32_export_builds_a_verifiable_package_with_contiguous_assumption() {
        let (source, expected) = fat32_deleted_fixture();
        let volume = daemoncore_ntfs_core::fat32::Volume::open(&source, 0, source.len()).unwrap();
        let entry = volume
            .read_tree_including_deleted(&source)
            .unwrap()
            .into_iter()
            .find(|tree_entry| tree_entry.entry.deleted)
            .unwrap();
        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap();
        let root = recovery_test_directory("fat32-export");
        let summary = export_fat32_to(
            &source,
            0,
            &[entry.clone()],
            &root,
            SourceIdentity {
                case_id: 1,
                evidence_record_id: 1,
                scan_session_id: 1,
                id: 1,
                path: "controlled-fat32.img",
                sha256: &digest,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.exported, 1);
        assert_eq!(summary.failed, 0);
        let package = PathBuf::from(&summary.directory);
        let verification = crate::recovery_verify::verify_package(&package).unwrap();
        assert_eq!(verification.state, "complete");
        assert_eq!(verification.exported, 1);
        assert_eq!(
            fs::read(package.join(safe_name(
                entry.entry.source_offset,
                &entry.entry.display_name(),
            )))
            .unwrap(),
            expected
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["volume"]["deleted_file_layout"],
            "contiguous_assumed_only_when_candidate_clusters_are_free"
        );
        assert_eq!(
            manifest["selected_records"][0]["storage"],
            "contiguous_assumed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exfat_export_builds_a_verifiable_package_and_labels_its_assumption() {
        let (source, expected) = exfat_deleted_fixture();
        let volume = daemoncore_ntfs_core::exfat::Volume::open(&source, 0, source.len()).unwrap();
        let entry = volume
            .read_tree_with_deleted(&source)
            .unwrap()
            .into_iter()
            .find(|tree_entry| tree_entry.entry.deleted)
            .unwrap();
        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap();
        let root = recovery_test_directory("exfat-export");
        let summary = export_exfat_to(
            &source,
            0,
            &[entry.clone()],
            &root,
            SourceIdentity {
                case_id: 1,
                evidence_record_id: 1,
                scan_session_id: 1,
                id: 1,
                path: "controlled-exfat.img",
                sha256: &digest,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.exported, 1);
        assert_eq!(summary.failed, 0);
        let package = PathBuf::from(&summary.directory);
        let verification = crate::recovery_verify::verify_package(&package).unwrap();
        assert_eq!(verification.state, "complete");
        assert_eq!(verification.exported, 1);
        assert_eq!(
            fs::read(package.join(safe_name(entry.entry.source_offset, &entry.entry.name,)))
                .unwrap(),
            expected
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["volume"]["filesystem"], "exFAT");
        assert_eq!(
            manifest["volume"]["deleted_file_layout"],
            "contiguous_declared_by_entry_set_and_free_in_allocation_bitmap"
        );
        assert_eq!(
            manifest["selected_records"][0]["allocation"],
            "free_in_current_bitmap"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exfat_export_records_a_candidate_that_became_allocated_as_failed() {
        let (mut source, _) = exfat_deleted_fixture();
        let volume = daemoncore_ntfs_core::exfat::Volume::open(&source, 0, source.len()).unwrap();
        let entry = volume
            .read_tree_with_deleted(&source)
            .unwrap()
            .into_iter()
            .find(|tree_entry| tree_entry.entry.deleted)
            .unwrap();
        source.0[40 * 512 + 2 * 512] |= 1 << 3;
        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap();
        let root = recovery_test_directory("exfat-allocated-export");
        let summary = export_exfat_to(
            &source,
            0,
            &[entry],
            &root,
            SourceIdentity {
                case_id: 1,
                evidence_record_id: 1,
                scan_session_id: 1,
                id: 1,
                path: "changed-exfat.img",
                sha256: &digest,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.exported, 0);
        assert_eq!(summary.failed, 1);
        let verification =
            crate::recovery_verify::verify_package(&PathBuf::from(&summary.directory)).unwrap();
        assert_eq!(verification.state, "partial");
        assert_eq!(verification.failed, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires an independently formatted and deleted FAT32 image cross-checked with Sleuth Kit"]
    fn exports_deleted_file_from_independent_fat32_image_against_sleuthkit_bytes() {
        let image_path = std::env::var_os("DAEMONCORE_FAT32_DELETED_IMAGE")
            .expect("set DAEMONCORE_FAT32_DELETED_IMAGE to the independent FAT32 image");
        let expected_path = std::env::var_os("DAEMONCORE_FAT32_DELETED_EXPECTED")
            .expect("set DAEMONCORE_FAT32_DELETED_EXPECTED to the original file bytes");
        let image_path = PathBuf::from(image_path);
        let expected = fs::read(expected_path).expect("read independently retained original bytes");
        assert_eq!(expected.len(), 65_536);
        assert_eq!(
            format!("{:x}", Sha256::digest(&expected)),
            "7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2"
        );

        let source = crate::storage::Image::open(&image_path).expect("open independent image");
        let volume = daemoncore_ntfs_core::fat32::Volume::open(&source, 0, source.len()).unwrap();
        let entry = volume
            .read_tree_including_deleted(&source)
            .unwrap()
            .into_iter()
            .find(|tree_entry| {
                tree_entry.entry.deleted
                    && tree_entry
                        .entry
                        .display_name()
                        .eq_ignore_ascii_case("?ECOVER.BIN")
            })
            .expect("deleted FAT32 entry found in independent fixture");
        assert_eq!(entry.entry.size as usize, expected.len());

        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .expect("hash complete independent image");
        let source_path = image_path.to_string_lossy().into_owned();
        let root = recovery_test_directory("fat32-independent-export");
        let summary = export_fat32_to(
            &source,
            0,
            &[entry.clone()],
            &root,
            SourceIdentity {
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
        .expect("export the independently validated deleted entry");

        assert_eq!(summary.exported, 1);
        assert_eq!(summary.failed, 0);
        let package = PathBuf::from(&summary.directory);
        let verified = crate::recovery_verify::verify_package(&package)
            .expect("native recovery package verifier accepts the export");
        assert_eq!(verified.state, "complete");
        assert_eq!(verified.exported, 1);
        let recovered = fs::read(package.join(safe_name(
            entry.entry.source_offset,
            &entry.entry.display_name(),
        )))
        .expect("read packaged recovered bytes");
        assert_eq!(recovered, expected);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fat32_export_refuses_clusters_that_are_no_longer_free() {
        let (mut source, _) = fat32_deleted_fixture();
        for fat_sector in [32, 544] {
            let entry = fat_sector * 512 + 3 * 4;
            source.0[entry..entry + 4].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
        }
        let volume = daemoncore_ntfs_core::fat32::Volume::open(&source, 0, source.len()).unwrap();
        let entry = volume
            .read_tree_including_deleted(&source)
            .unwrap()
            .into_iter()
            .find(|tree_entry| tree_entry.entry.deleted)
            .unwrap();
        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap();
        let root = recovery_test_directory("fat32-overwritten-export");
        let summary = export_fat32_to(
            &source,
            0,
            &[entry],
            &root,
            SourceIdentity {
                case_id: 1,
                evidence_record_id: 1,
                scan_session_id: 1,
                id: 1,
                path: "controlled-fat32.img",
                sha256: &digest,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.exported, 0);
        assert_eq!(summary.failed, 1);
        let package = PathBuf::from(&summary.directory);
        let verification = crate::recovery_verify::verify_package(&package).unwrap();
        assert_eq!(verification.state, "partial");
        assert_eq!(verification.exported, 0);
        assert_eq!(verification.failed, 1);
        assert_eq!(fs::read_dir(&package).unwrap().count(), 5);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fat32_export_rejects_overlapping_selected_deleted_entries() {
        let (mut source, _) = fat32_deleted_fixture();
        let record_offset = 1056 * 512 + 32;
        source.0[record_offset] = 0xe5;
        source.0[record_offset + 1..record_offset + 8].copy_from_slice(b"OTHER  ");
        source.0[record_offset + 8..record_offset + 11].copy_from_slice(b"BIN");
        source.0[record_offset + 11] = 0x20;
        source.0[record_offset + 26..record_offset + 28].copy_from_slice(&3_u16.to_le_bytes());
        source.0[record_offset + 28..record_offset + 32].copy_from_slice(&65_536_u32.to_le_bytes());
        let volume = daemoncore_ntfs_core::fat32::Volume::open(&source, 0, source.len()).unwrap();
        let entries = volume
            .read_tree_including_deleted(&source)
            .unwrap()
            .into_iter()
            .filter(|tree_entry| tree_entry.entry.deleted)
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        let digest = hash_source(&source, &AtomicBool::new(false), |_| {})
            .unwrap()
            .unwrap();
        let root = recovery_test_directory("fat32-overlap-export");
        let summary = export_fat32_to(
            &source,
            0,
            &entries,
            &root,
            SourceIdentity {
                case_id: 1,
                evidence_record_id: 1,
                scan_session_id: 1,
                id: 1,
                path: "controlled-fat32.img",
                sha256: &digest,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.exported, 0);
        assert_eq!(summary.failed, 2);
        let package = PathBuf::from(&summary.directory);
        let verification = crate::recovery_verify::verify_package(&package).unwrap();
        assert_eq!(verification.state, "partial");
        assert_eq!(verification.failed, 2);
        let inventory = fs::read_to_string(package.join("inventory.jsonl")).unwrap();
        assert_eq!(
            inventory
                .matches("overlap the same assumed cluster range")
                .count(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }

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
            filename_references: Vec::new(),
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
