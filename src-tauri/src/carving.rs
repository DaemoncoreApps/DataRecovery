use daemoncore_ntfs_core::storage::BlockSource;
use image::{AnimationDecoder, ImageDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const BMP_SIGNATURE: &[u8; 2] = b"BM";
const JPEG_SIGNATURE: &[u8; 2] = b"\xff\xd8";
const GIF_SIGNATURE: &[u8; 3] = b"GIF";
pub const SUPPORTED_FORMATS: &[&str] = &["PNG", "BMP", "JPEG", "GIF"];
const MAX_SIGNATURE_LEN: usize = 8;
const READ_CHUNK: usize = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PNG_CHUNK_BYTES: u32 = 64 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIF_DECODED_BYTES: usize = 512 * 1024 * 1024;
const MAX_GIF_FRAMES: usize = 1_000;
const MAX_CANDIDATES: usize = 10_000;

fn try_zeroed_buffer(length: usize, purpose: &str) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|error| format!("Could not allocate {length} bytes for {purpose}: {error}"))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CarvedCandidate {
    pub id: u64,
    pub offset: u64,
    pub length: u64,
    pub format: String,
    pub sha256: String,
    pub validation: String,
}

#[derive(Debug)]
pub struct CarvingResult {
    pub source_sha256: String,
    pub scanned_bytes: u64,
    pub candidates: Vec<CarvedCandidate>,
    pub candidates_limited: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CarveScanRecord {
    pub id: i64,
    pub evidence_id: i64,
    pub source_sha256: String,
    pub completed_at: String,
    pub scanned_bytes: u64,
    pub candidates_limited: bool,
    pub snapshot_sha256: String,
    pub candidates: Vec<CarvedCandidate>,
}

pub fn snapshot_digest(
    source_sha256: &str,
    scanned_bytes: u64,
    candidates_limited: bool,
    candidates_json: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"DaemonCore PNG carve snapshot v1\0");
    digest.update(source_sha256.as_bytes());
    digest.update(scanned_bytes.to_le_bytes());
    digest.update([u8::from(candidates_limited)]);
    digest.update((candidates_json.len() as u64).to_le_bytes());
    digest.update(candidates_json.as_bytes());
    format!("{:x}", digest.finalize())
}

pub fn list_case_scan_sessions_from(
    db: &rusqlite::Connection,
    case_id: i64,
) -> crate::Result<Vec<CarveScanRecord>> {
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='carve_scan_persisted'")
        .map_err(crate::err)?;
    let mut audit_rows = audit_statement.query([]).map_err(crate::err)?;
    let mut audit_payloads = std::collections::BTreeMap::new();
    while let Some(row) = audit_rows.next().map_err(crate::err)? {
        let encoded: String = row.get(0).map_err(crate::err)?;
        let payload: serde_json::Value = serde_json::from_str(&encoded).map_err(crate::err)?;
        if payload["case_id"].as_i64() == Some(case_id) {
            let scan_id = payload["scan_session_id"].as_i64().unwrap_or_default();
            if audit_payloads.insert(scan_id, payload).is_some() {
                return Err(format!(
                    "Carving scan {scan_id} has duplicate audit references."
                ));
            }
        }
    }
    let mut statement = db
        .prepare("SELECT id,evidence_id,source_sha256,completed_at,scanned_bytes,candidates_json,snapshot_sha256,candidates_limited FROM carve_scan_sessions WHERE case_id=?1 ORDER BY id")
        .map_err(crate::err)?;
    let mut rows = statement.query([case_id]).map_err(crate::err)?;
    let mut sessions = Vec::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    while let Some(row) = rows.next().map_err(crate::err)? {
        let id: i64 = row.get(0).map_err(crate::err)?;
        let evidence_id: i64 = row.get(1).map_err(crate::err)?;
        let source_sha256: String = row.get(2).map_err(crate::err)?;
        let completed_at: String = row.get(3).map_err(crate::err)?;
        let scanned_bytes: i64 = row.get(4).map_err(crate::err)?;
        let candidates_json: String = row.get(5).map_err(crate::err)?;
        let snapshot_sha256: String = row.get(6).map_err(crate::err)?;
        let candidates_limited: i64 = row.get(7).map_err(crate::err)?;
        if id <= 0
            || evidence_id <= 0
            || scanned_bytes <= 0
            || !seen_ids.insert(id)
            || !valid_sha256(&source_sha256)
            || !valid_sha256(&snapshot_sha256)
            || !matches!(candidates_limited, 0 | 1)
        {
            return Err(format!("Carving scan {id} has invalid persisted metadata."));
        }
        let payload = audit_payloads
            .get(&id)
            .ok_or_else(|| format!("Carving scan {id} has no matching audit reference."))?;
        let candidates: Vec<CarvedCandidate> = serde_json::from_str(&candidates_json)
            .map_err(|error| format!("Carving scan {id} candidate snapshot is invalid: {error}"))?;
        let limited = candidates_limited == 1;
        let observed_digest = snapshot_digest(
            &source_sha256,
            scanned_bytes as u64,
            limited,
            &candidates_json,
        );
        if observed_digest != snapshot_sha256
            || payload["evidence_record_id"].as_i64() != Some(evidence_id)
            || payload["source_sha256"].as_str() != Some(source_sha256.as_str())
            || payload["scanned_bytes"].as_u64() != Some(scanned_bytes as u64)
            || payload["candidates"].as_u64() != Some(candidates.len() as u64)
            || payload["candidates_limited"].as_bool() != Some(limited)
            || payload["snapshot_sha256"].as_str() != Some(snapshot_sha256.as_str())
        {
            return Err(format!(
                "Carving scan {id} does not match its audited candidate snapshot."
            ));
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(format!(
                "Carving scan {id} exceeds the candidate count limit."
            ));
        }
        let mut candidate_offsets = std::collections::BTreeSet::new();
        for candidate in &candidates {
            if candidate.id != candidate.offset
                || candidate.length == 0
                || candidate
                    .offset
                    .checked_add(candidate.length)
                    .is_none_or(|end| end > scanned_bytes as u64)
                || !candidate_format_metadata_valid(candidate)
                || !valid_sha256(&candidate.sha256)
                || !candidate_offsets.insert(candidate.offset)
            {
                return Err(format!(
                    "Carving scan {id} contains invalid candidate metadata."
                ));
            }
        }
        sessions.push(CarveScanRecord {
            id,
            evidence_id,
            source_sha256,
            completed_at,
            scanned_bytes: scanned_bytes as u64,
            candidates_limited: limited,
            snapshot_sha256,
            candidates,
        });
    }
    for id in audit_payloads.keys() {
        if !seen_ids.contains(id) {
            return Err(format!("Carving audit record refers to missing scan {id}."));
        }
    }
    Ok(sessions)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn candidate_format_metadata_valid(candidate: &CarvedCandidate) -> bool {
    match candidate.format.as_str() {
        "PNG" => candidate.validation == "PNG chunks and CRCs valid; image decoded",
        "BMP" => matches!(
            candidate.validation.as_str(),
            "BMP pixels decoded; bounded dimensions and allocation valid"
                | "BMP header, geometry, and pixel bounds valid"
        ),
        "JPEG" => candidate.validation == "JPEG decoded; dimensions and allocation bounds valid",
        "GIF" => candidate.validation == "GIF structure valid; all frames decoded within limits",
        _ => false,
    }
}

fn extension(format: &str) -> Option<&'static str> {
    match format {
        "PNG" => Some("png"),
        "BMP" => Some("bmp"),
        "JPEG" => Some("jpg"),
        "GIF" => Some("gif"),
        _ => None,
    }
}

fn output_name(candidate: &CarvedCandidate) -> Result<String, String> {
    let extension = extension(&candidate.format).ok_or("Unsupported carved file format.")?;
    Ok(format!("carved-{:016x}.{extension}", candidate.offset))
}

#[derive(Clone, Debug, Serialize)]
pub struct CarveExportSummary {
    pub directory: String,
    pub exported: usize,
    pub failed: usize,
    pub cancelled: bool,
    pub source_sha256_after: Option<String>,
}

pub struct ExportIdentity<'a> {
    pub case_id: i64,
    pub evidence_record_id: i64,
    pub scan_session_id: i64,
    pub source_id: u64,
    pub source_path: &'a str,
    pub source_sha256: &'a str,
}

#[derive(Serialize)]
struct ExportInventory<'a> {
    scan_session_id: i64,
    offset: u64,
    length: u64,
    format: &'a str,
    output_name: Option<String>,
    source_sha256: &'a str,
    output_sha256: Option<String>,
    validation: &'a str,
    status: &'a str,
    error: Option<String>,
}

struct PartialFile(PathBuf);
impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn report_incomplete_package_path<T>(
    result: Result<T, String>,
    directory: &Path,
) -> Result<T, String> {
    match result {
        Err(error) if directory.exists() => Err(format!(
            "{error} An incomplete carving package may remain at {}. Treat it as unverified until the package verifier accepts it.",
            directory.display()
        )),
        result => result,
    }
}

pub fn export_selected(
    source: &dyn BlockSource,
    selected: &[CarvedCandidate],
    destination: &Path,
    identity: ExportIdentity<'_>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<CarveExportSummary, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let directory = destination.join(format!("DaemonCore-Carved-Recovery-{stamp}"));
    let result = export_selected_into(
        source,
        selected,
        identity,
        cancel,
        &mut progress,
        stamp,
        &directory,
    );
    report_incomplete_package_path(result, &directory)
}

fn export_selected_into(
    source: &dyn BlockSource,
    selected: &[CarvedCandidate],
    identity: ExportIdentity<'_>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    stamp: u128,
    directory: &Path,
) -> Result<CarveExportSummary, String> {
    if selected.is_empty() || selected.len() > 1_000 {
        return Err("Select between 1 and 1,000 validated carved candidates.".into());
    }
    let unique = selected
        .iter()
        .map(|candidate| candidate.id)
        .collect::<std::collections::BTreeSet<_>>();
    if unique.len() != selected.len() {
        return Err("Duplicate carved candidates cannot be exported.".into());
    }
    if selected.iter().any(|candidate| {
        candidate.id != candidate.offset
            || candidate.length == 0
            || candidate.length > MAX_FILE_BYTES
            || candidate
                .offset
                .checked_add(candidate.length)
                .is_none_or(|end| end > source.len())
            || !valid_sha256(&candidate.sha256)
            || !candidate_format_metadata_valid(candidate)
    }) {
        return Err("A selected candidate has unsupported or invalid metadata.".into());
    }
    let outputs_size = selected
        .iter()
        .try_fold(0u64, |total, candidate| {
            total.checked_add(candidate.length.checked_mul(2)?)
        })
        .ok_or("Carving export size overflow.")?;
    let total = source
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(outputs_size))
        .ok_or("Carving export progress size overflow.")?;
    let mut processed = 0u64;
    progress(processed, total);
    let before = hash_source(source, cancel, |count| {
        processed += count;
        progress(processed, total);
    })?
    .ok_or("Carving export cancelled before the source check completed; no package was created.")?;
    if before != identity.source_sha256 {
        return Err(
            "The source SHA-256 changed before export. No carving package was created.".into(),
        );
    }
    fs::create_dir(directory).map_err(|error| error.to_string())?;
    let selected_metadata = selected
        .iter()
        .map(|candidate| {
            Ok(serde_json::json!({
                "offset": candidate.offset,
                "length": candidate.length,
                "format": candidate.format,
                "sha256": candidate.sha256,
                "validation": candidate.validation,
                "output_name": output_name(candidate)?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let manifest = serde_json::json!({
        "tool": "DaemonCore Data Recovery",
        "version": env!("CARGO_PKG_VERSION"),
        "package_type": "signature_carving",
        "hash_algorithm": "SHA-256",
        "created_unix_ns": stamp.to_string(),
        "source": {
            "case_id": identity.case_id,
            "evidence_record_id": identity.evidence_record_id,
            "scan_session_id": identity.scan_session_id,
            "source_id": identity.source_id,
            "path": identity.source_path,
            "size": source.len(),
            "sha256_before_export": identity.source_sha256,
        },
        "selected_candidates": selected_metadata,
        "recovery_scope": "Supported file bytes were carved from a raw image and validated using their format-specific checks. Original filename, directory, timestamps, allocation state, and deletion status are unknown.",
        "completion": "Treat this package as incomplete unless completion.json exists and verifies.",
    });
    write_new_json(&directory.join("manifest.json"), &manifest)?;
    let inventory_path = directory.join("inventory.jsonl");
    let mut inventory_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&inventory_path)
        .map_err(|error| error.to_string())?;
    let mut summary = CarveExportSummary {
        directory: directory.to_string_lossy().into_owned(),
        exported: 0,
        failed: 0,
        cancelled: false,
        source_sha256_after: None,
    };
    let mut buffer = vec![0; READ_CHUNK];
    for candidate in selected {
        if cancel.load(Ordering::Relaxed) {
            summary.cancelled = true;
            break;
        }
        let name = output_name(candidate)?;
        let validation = validate_candidate(source, candidate);
        let error = match validation {
            Ok(Some((length, digest)))
                if length == candidate.length && digest == candidate.sha256 =>
            {
                None
            }
            Ok(_) => Some("The carved candidate changed after scanning.".to_owned()),
            Err(error) => Some(error),
        };
        let output_digest = if error.is_some() {
            summary.failed += 1;
            None
        } else {
            let final_path = directory.join(&name);
            let partial = PartialFile(directory.join(format!(".{name}.partial")));
            let mut output = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial.0)
            {
                Ok(file) => file,
                Err(error) => {
                    summary.failed += 1;
                    write_inventory(
                        &mut inventory_file,
                        candidate,
                        identity.scan_session_id,
                        None,
                        None,
                        "failed",
                        Some(error.to_string()),
                    )?;
                    continue;
                }
            };
            let mut digest = Sha256::new();
            let mut position = 0u64;
            let mut failed = None;
            while position < candidate.length {
                if cancel.load(Ordering::Relaxed) {
                    failed = Some("Export cancelled".to_owned());
                    summary.cancelled = true;
                    break;
                }
                let count = (candidate.length - position).min(buffer.len() as u64) as usize;
                if let Err(error) =
                    source.read_exact_at(candidate.offset + position, &mut buffer[..count])
                {
                    failed = Some(error.to_string());
                    break;
                }
                if let Err(error) = output.write_all(&buffer[..count]) {
                    failed = Some(error.to_string());
                    break;
                }
                digest.update(&buffer[..count]);
                position += count as u64;
                processed += count as u64;
                progress(processed, total);
            }
            if failed.is_none() {
                if let Err(error) = output.sync_all() {
                    failed = Some(error.to_string());
                }
            }
            drop(output);
            if let Some(error) = failed {
                summary.failed += 1;
                if error == "Export cancelled" {
                    summary.cancelled = true;
                }
                write_inventory(
                    &mut inventory_file,
                    candidate,
                    identity.scan_session_id,
                    Some(name),
                    None,
                    "failed",
                    Some(error),
                )?;
                if summary.cancelled {
                    break;
                }
                continue;
            }
            let source_digest = format!("{:x}", digest.finalize());
            if source_digest != candidate.sha256 {
                summary.failed += 1;
                write_inventory(
                    &mut inventory_file,
                    candidate,
                    identity.scan_session_id,
                    Some(name),
                    None,
                    "failed",
                    Some("Carved output bytes do not match the scan digest".into()),
                )?;
                continue;
            }
            let mut output_file = File::open(&partial.0).map_err(|error| error.to_string())?;
            let mut output_check = Sha256::new();
            loop {
                let count = output_file
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if count == 0 {
                    break;
                }
                output_check.update(&buffer[..count]);
                processed += count as u64;
                progress(processed, total);
            }
            let verified_digest = format!("{:x}", output_check.finalize());
            if verified_digest != candidate.sha256 {
                summary.failed += 1;
                write_inventory(
                    &mut inventory_file,
                    candidate,
                    identity.scan_session_id,
                    Some(name),
                    None,
                    "failed",
                    Some("Destination SHA-256 verification failed".into()),
                )?;
                continue;
            }
            crate::destination::publish_new(&partial.0, &final_path)
                .map_err(|error| error.to_string())?;
            summary.exported += 1;
            Some(verified_digest)
        };
        if let Some(error) = error {
            write_inventory(
                &mut inventory_file,
                candidate,
                identity.scan_session_id,
                None,
                None,
                "failed",
                Some(error),
            )?;
        } else {
            write_inventory(
                &mut inventory_file,
                candidate,
                identity.scan_session_id,
                Some(name),
                output_digest,
                "exported",
                None,
            )?;
        }
    }
    inventory_file
        .sync_all()
        .map_err(|error| error.to_string())?;
    if !summary.cancelled {
        let after = hash_source(source, cancel, |count| {
            processed += count;
            progress(processed.min(total), total);
        })?
        .ok_or(
            "Export cancelled during the final source check. The package has no completion marker.",
        )?;
        if after != identity.source_sha256 {
            return Err("Source SHA-256 changed during carving export. Quarantine the incomplete package and investigate the evidence.".into());
        }
        summary.source_sha256_after = Some(after);
    } else {
        summary.source_sha256_after = None;
    }
    write_new_json(&directory.join("summary.json"), &summary)?;
    let checksums = write_package_checksums(directory)?;
    let completion = serde_json::json!({
        "state": if summary.cancelled || summary.failed > 0 { "partial" } else { "complete" },
        "checksums_sha256": format!("{:x}", Sha256::digest(&checksums)),
        "source_sha256_before": identity.source_sha256,
        "source_sha256_after": summary.source_sha256_after,
    });
    write_new_json(&directory.join("completion.json"), &completion)?;
    Ok(summary)
}

fn hash_source(
    source: &dyn BlockSource,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<Option<String>, String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    let mut position = 0u64;
    while position < source.len() {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let count = (source.len() - position).min(buffer.len() as u64) as usize;
        source
            .read_exact_at(position, &mut buffer[..count])
            .map_err(|error| error.to_string())?;
        digest.update(&buffer[..count]);
        position += count as u64;
        progress(count as u64);
    }
    Ok(Some(format!("{:x}", digest.finalize())))
}

fn write_inventory(
    file: &mut File,
    candidate: &CarvedCandidate,
    scan_session_id: i64,
    output_name: Option<String>,
    output_sha256: Option<String>,
    status: &str,
    error: Option<String>,
) -> Result<(), String> {
    let entry = ExportInventory {
        scan_session_id,
        offset: candidate.offset,
        length: candidate.length,
        format: &candidate.format,
        output_name,
        source_sha256: &candidate.sha256,
        output_sha256,
        validation: &candidate.validation,
        status,
        error,
    };
    serde_json::to_writer(&mut *file, &entry).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn write_package_checksums(directory: &Path) -> Result<Vec<u8>, String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_file() {
            return Err("Carving package contains an unexpected directory or link.".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Carving package contains a non-UTF-8 filename.")?;
        if name != "checksums.sha256" && name != "completion.json" {
            entries.push((entry.path(), name));
        }
    }
    entries.sort_by(|left, right| left.1.cmp(&right.1));
    let path = directory.join("checksums.sha256");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let mut buffer = vec![0; READ_CHUNK];
    for (path, name) in entries {
        let mut input = File::open(path).map_err(|error| error.to_string())?;
        let mut digest = Sha256::new();
        loop {
            let count = input.read(&mut buffer).map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        writeln!(file, "{:x}  {name}", digest.finalize()).map_err(|error| error.to_string())?;
    }
    file.sync_all().map_err(|error| error.to_string())?;
    fs::read(directory.join("checksums.sha256")).map_err(|error| error.to_string())
}

pub fn scan_supported_files(
    source: &dyn BlockSource,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, usize),
) -> Result<Option<CarvingResult>, String> {
    let mut source_digest = Sha256::new();
    let mut cursor = 0u64;
    let mut carry = Vec::new();
    let mut next_candidate_offset = 0u64;
    let mut skip_until = 0u64;
    let mut candidates = Vec::new();
    let mut candidates_limited = false;
    let mut chunk = vec![0; READ_CHUNK];
    let mut window = Vec::with_capacity(READ_CHUNK + MAX_SIGNATURE_LEN - 1);
    while cursor < source.len() {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let count = (source.len() - cursor).min(READ_CHUNK as u64) as usize;
        source
            .read_exact_at(cursor, &mut chunk[..count])
            .map_err(|error| error.to_string())?;
        source_digest.update(&chunk[..count]);
        window.clear();
        window.extend_from_slice(&carry);
        window.extend_from_slice(&chunk[..count]);
        let window_start = cursor - carry.len() as u64;
        for (index, bytes) in window.windows(2).enumerate() {
            let offset = window_start + index as u64;
            if offset < next_candidate_offset
                || offset >= cursor + count as u64
                || offset < skip_until
            {
                continue;
            }
            let (format, candidate) = if bytes == BMP_SIGNATURE {
                ("BMP", validate_bmp(source, offset)?)
            } else if bytes == JPEG_SIGNATURE {
                ("JPEG", validate_jpeg(source, offset)?)
            } else if bytes == &PNG_SIGNATURE[..2] {
                ("PNG", validate_png(source, offset)?)
            } else if bytes == &GIF_SIGNATURE[..2] {
                ("GIF", validate_gif(source, offset)?)
            } else {
                continue;
            };
            if let Some((length, digest)) = candidate {
                skip_until = offset.saturating_add(length);
                if candidates.len() < MAX_CANDIDATES {
                    candidates.push(CarvedCandidate {
                        id: offset,
                        offset,
                        length,
                        format: format.into(),
                        sha256: digest,
                        validation: match format {
                            "PNG" => "PNG chunks and CRCs valid; image decoded",
                            "BMP" => "BMP pixels decoded; bounded dimensions and allocation valid",
                            "JPEG" => "JPEG decoded; dimensions and allocation bounds valid",
                            "GIF" => "GIF structure valid; all frames decoded within limits",
                            _ => unreachable!(),
                        }
                        .into(),
                    });
                } else {
                    candidates_limited = true;
                }
            }
        }
        cursor += count as u64;
        next_candidate_offset = cursor.saturating_sub((MAX_SIGNATURE_LEN - 1) as u64);
        let keep = (MAX_SIGNATURE_LEN - 1).min(window.len());
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
        progress(cursor, candidates.len());
    }
    Ok(Some(CarvingResult {
        source_sha256: format!("{:x}", source_digest.finalize()),
        scanned_bytes: cursor,
        candidates,
        candidates_limited,
    }))
}

fn validate_candidate(
    source: &dyn BlockSource,
    candidate: &CarvedCandidate,
) -> Result<Option<(u64, String)>, String> {
    match candidate.format.as_str() {
        "PNG" => validate_png(source, candidate.offset),
        "BMP" => validate_bmp(source, candidate.offset),
        "JPEG" => validate_jpeg(source, candidate.offset),
        "GIF" => validate_gif(source, candidate.offset),
        _ => Err("Unsupported carved file format.".into()),
    }
}

struct SourceRangeReader<'a> {
    source: &'a dyn BlockSource,
    start: u64,
    length: u64,
    position: u64,
}

impl Read for SourceRangeReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer
            .len()
            .min(usize::try_from(self.length.saturating_sub(self.position)).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let offset = self
            .start
            .checked_add(self.position)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source offset overflow"))?;
        self.source
            .read_exact_at(offset, &mut buffer[..count])
            .map_err(io::Error::other)?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for SourceRangeReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => seek_relative(self.position, delta),
            SeekFrom::End(delta) => seek_relative(self.length, delta),
        }
        .filter(|position| *position <= self.length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside candidate"))?;
        self.position = next;
        Ok(next)
    }
}

fn seek_relative(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
}

fn validate_bmp(source: &dyn BlockSource, offset: u64) -> Result<Option<(u64, String)>, String> {
    if offset.checked_add(54).is_none_or(|end| end > source.len()) {
        return Ok(None);
    }
    let mut header = [0u8; 54];
    source
        .read_exact_at(offset, &mut header)
        .map_err(|error| error.to_string())?;
    if &header[..2] != BMP_SIGNATURE {
        return Ok(None);
    }
    let file_size = u32::from_le_bytes(header[2..6].try_into().expect("fixed-size slice")) as u64;
    let pixel_offset =
        u32::from_le_bytes(header[10..14].try_into().expect("fixed-size slice")) as u64;
    let dib_size = u32::from_le_bytes(header[14..18].try_into().expect("fixed-size slice"));
    if !matches!(dib_size, 40 | 52 | 56 | 108 | 124)
        || !(54..=MAX_FILE_BYTES).contains(&file_size)
        || u64::from(dib_size) > file_size.saturating_sub(14)
        || offset
            .checked_add(file_size)
            .is_none_or(|end| end > source.len())
    {
        return Ok(None);
    }
    let mut dib = vec![0; dib_size as usize];
    source
        .read_exact_at(offset + 14, &mut dib)
        .map_err(|error| error.to_string())?;
    let width = i32::from_le_bytes(dib[4..8].try_into().expect("fixed-size slice"));
    let height = i32::from_le_bytes(dib[8..12].try_into().expect("fixed-size slice"));
    let planes = u16::from_le_bytes(dib[12..14].try_into().expect("fixed-size slice"));
    let bits_per_pixel = u16::from_le_bytes(dib[14..16].try_into().expect("fixed-size slice"));
    let compression = u32::from_le_bytes(dib[16..20].try_into().expect("fixed-size slice"));
    let image_size = u32::from_le_bytes(dib[20..24].try_into().expect("fixed-size slice")) as u64;
    let colors_used = u32::from_le_bytes(dib[32..36].try_into().expect("fixed-size slice")) as u64;
    if width <= 0
        || height == 0
        || height == i32::MIN
        || planes != 1
        || !matches!(bits_per_pixel, 1 | 4 | 8 | 16 | 24 | 32)
        || !matches!(compression, 0 | 3 | 6)
        || (compression != 0 && !matches!(bits_per_pixel, 16 | 32))
    {
        return Ok(None);
    }

    let width = width as u64;
    let height = u64::from(height.unsigned_abs());
    if width
        .checked_mul(height)
        .is_none_or(|pixels| pixels > 100_000_000)
    {
        return Ok(None);
    }
    let row_bits = match width.checked_mul(u64::from(bits_per_pixel)) {
        Some(value) => value,
        None => return Ok(None),
    };
    let row_stride = match row_bits.checked_add(31).map(|value| (value / 32) * 4) {
        Some(value) => value,
        None => return Ok(None),
    };
    let pixel_bytes = match row_stride.checked_mul(height) {
        Some(value) => value,
        None => return Ok(None),
    };
    let palette_entries = if bits_per_pixel <= 8 {
        if colors_used == 0 {
            1u64 << bits_per_pixel
        } else if colors_used <= (1u64 << bits_per_pixel) {
            colors_used
        } else {
            return Ok(None);
        }
    } else {
        colors_used
    };
    let palette_bytes = match palette_entries.checked_mul(4) {
        Some(value) => value,
        None => return Ok(None),
    };
    let external_masks = match (compression, dib_size) {
        (3, 40) => 12u64,
        (6, 40) => 16u64,
        (3, 52 | 56 | 108 | 124) | (6, 56 | 108 | 124) | (0, _) => 0,
        _ => return Ok(None),
    };
    let metadata_end = 14u64
        .checked_add(u64::from(dib_size))
        .and_then(|value| value.checked_add(external_masks))
        .and_then(|value| value.checked_add(palette_bytes));
    let data_bytes = file_size.saturating_sub(pixel_offset);
    if metadata_end.is_none_or(|end| end > pixel_offset)
        || pixel_offset < 14 + u64::from(dib_size)
        || pixel_offset > file_size
        || pixel_bytes > data_bytes
        || (image_size != 0 && (image_size < pixel_bytes || image_size > data_bytes))
    {
        return Ok(None);
    }

    let range = SourceRangeReader {
        source,
        start: offset,
        length: file_size,
        position: 0,
    };
    let mut decoder =
        match image::codecs::bmp::BmpDecoder::new(BufReader::with_capacity(READ_CHUNK, range)) {
            Ok(decoder) => decoder,
            Err(image::ImageError::IoError(error)) => return Err(error.to_string()),
            Err(_) => return Ok(None),
        };
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(32_768);
    limits.max_image_height = Some(32_768);
    let decoded_bytes = decoder.total_bytes();
    if decoder.set_limits(limits).is_err()
        || decoded_bytes > MAX_DECODED_BYTES as u64
        || usize::try_from(decoded_bytes).is_err()
    {
        return Ok(None);
    }
    let mut decoded = try_zeroed_buffer(decoded_bytes as usize, "BMP image decoding")?;
    if let Err(error) = decoder.read_image(&mut decoded) {
        return match error {
            image::ImageError::IoError(error) => Err(error.to_string()),
            _ => Ok(None),
        };
    }

    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    let mut position = 0u64;
    while position < file_size {
        let count = (file_size - position).min(buffer.len() as u64) as usize;
        source
            .read_exact_at(offset + position, &mut buffer[..count])
            .map_err(|error| error.to_string())?;
        digest.update(&buffer[..count]);
        position += count as u64;
    }
    Ok(Some((file_size, format!("{:x}", digest.finalize()))))
}

fn validate_png(source: &dyn BlockSource, offset: u64) -> Result<Option<(u64, String)>, String> {
    if offset
        .checked_add(PNG_SIGNATURE.len() as u64)
        .is_none_or(|end| end > source.len())
    {
        return Ok(None);
    }
    let mut signature = [0; 8];
    source
        .read_exact_at(offset, &mut signature)
        .map_err(|error| error.to_string())?;
    if &signature != PNG_SIGNATURE {
        return Ok(None);
    }
    let mut candidate = signature.to_vec();
    let mut position = offset + PNG_SIGNATURE.len() as u64;
    let mut chunk_count = 0u32;
    let mut saw_ihdr = false;
    let mut saw_idat = false;
    let mut finished_idat = false;
    loop {
        if position.saturating_sub(offset) > MAX_FILE_BYTES || chunk_count >= 100_000 {
            return Ok(None);
        }
        let mut header = [0; 8];
        if position.checked_add(8).is_none_or(|end| end > source.len()) {
            return Ok(None);
        }
        source
            .read_exact_at(position, &mut header)
            .map_err(|error| error.to_string())?;
        let length = u32::from_be_bytes(header[..4].try_into().expect("fixed-size slice"));
        let kind = &header[4..8];
        if length > MAX_PNG_CHUNK_BYTES {
            return Ok(None);
        }
        let chunk_end = match position
            .checked_add(12)
            .and_then(|value| value.checked_add(u64::from(length)))
        {
            Some(end) if end <= source.len() && end - offset <= MAX_FILE_BYTES => end,
            _ => return Ok(None),
        };
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return Ok(None);
        }
        if !saw_ihdr {
            if kind != b"IHDR" || length != 13 {
                return Ok(None);
            }
            saw_ihdr = true;
        } else if kind == b"IHDR" {
            return Ok(None);
        }
        if kind == b"IDAT" {
            if finished_idat {
                return Ok(None);
            }
            saw_idat = true;
        } else if saw_idat {
            finished_idat = true;
        }
        if kind[0].is_ascii_uppercase() && !matches!(kind, b"IHDR" | b"PLTE" | b"IDAT" | b"IEND") {
            return Ok(None);
        }
        let data_start = position + 8;
        let data_length = usize::try_from(length).map_err(|_| "PNG chunk is too large")?;
        let candidate_growth = header
            .len()
            .checked_add(data_length)
            .and_then(|size| size.checked_add(4))
            .ok_or("PNG candidate size overflow")?;
        candidate
            .try_reserve(candidate_growth)
            .map_err(|error| format!("Could not grow the bounded PNG candidate buffer: {error}"))?;
        candidate.extend_from_slice(&header);
        let candidate_data_start = candidate.len();
        candidate.resize(candidate_data_start + data_length, 0);
        let mut crc = crc32fast::Hasher::new();
        crc.update(kind);
        let mut copied = 0usize;
        while copied < data_length {
            let count = (data_length - copied).min(READ_CHUNK);
            let candidate_start = candidate_data_start + copied;
            let candidate_end = candidate_start + count;
            source
                .read_exact_at(
                    data_start + copied as u64,
                    &mut candidate[candidate_start..candidate_end],
                )
                .map_err(|error| error.to_string())?;
            crc.update(&candidate[candidate_start..candidate_end]);
            copied += count;
        }
        let mut stored_crc = [0; 4];
        source
            .read_exact_at(data_start + u64::from(length), &mut stored_crc)
            .map_err(|error| error.to_string())?;
        if crc.finalize() != u32::from_be_bytes(stored_crc) {
            return Ok(None);
        }
        candidate.extend_from_slice(&stored_crc);
        chunk_count += 1;
        position = chunk_end;
        if kind == b"IEND" {
            if length != 0 || !saw_idat {
                return Ok(None);
            }
            let mut decoder = png::Decoder::new(std::io::Cursor::new(candidate.as_slice()));
            decoder.set_limits(png::Limits {
                bytes: MAX_DECODED_BYTES,
            });
            let mut reader = match decoder.read_info() {
                Ok(reader) => reader,
                Err(_) => return Ok(None),
            };
            if reader.output_buffer_size() > MAX_DECODED_BYTES {
                return Ok(None);
            }
            let mut decoded = try_zeroed_buffer(reader.output_buffer_size(), "PNG image decoding")?;
            if reader.next_frame(&mut decoded).is_err() {
                return Ok(None);
            }
            return Ok(Some((
                position - offset,
                format!("{:x}", Sha256::digest(&candidate)),
            )));
        }
    }
}

fn gif_read_exact(reader: &mut impl Read, buffer: &mut [u8]) -> Result<bool, String> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn gif_skip_sub_blocks(reader: &mut SourceRangeReader<'_>) -> Result<Option<bool>, String> {
    let mut saw_payload = false;
    loop {
        let mut length = [0];
        if !gif_read_exact(reader, &mut length)? {
            return Ok(None);
        }
        if length[0] == 0 {
            return Ok(Some(saw_payload));
        }
        saw_payload = true;
        if reader
            .seek(SeekFrom::Current(i64::from(length[0])))
            .is_err()
        {
            return Ok(None);
        }
    }
}

fn gif_decoder_source_error(error: &image::ImageError) -> Option<String> {
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        if let Some(source_error) = current.downcast_ref::<io::Error>() {
            return Some(source_error.to_string());
        }
        cause = current.source();
    }
    None
}

fn validate_gif(source: &dyn BlockSource, offset: u64) -> Result<Option<(u64, String)>, String> {
    let Some(available) = source.len().checked_sub(offset) else {
        return Ok(None);
    };
    if available < 13 {
        return Ok(None);
    }
    let mut reader = SourceRangeReader {
        source,
        start: offset,
        length: available.min(MAX_FILE_BYTES),
        position: 0,
    };
    let mut header = [0; 6];
    if !gif_read_exact(&mut reader, &mut header)? || !matches!(&header, b"GIF87a" | b"GIF89a") {
        return Ok(None);
    }
    let mut screen = [0; 7];
    if !gif_read_exact(&mut reader, &mut screen)? {
        return Ok(None);
    }
    let canvas_width = u16::from_le_bytes([screen[0], screen[1]]) as u32;
    let canvas_height = u16::from_le_bytes([screen[2], screen[3]]) as u32;
    let screen_flags = screen[4];
    if canvas_width == 0
        || canvas_height == 0
        || canvas_width > 32_768
        || canvas_height > 32_768
        || canvas_width
            .checked_mul(canvas_height)
            .and_then(|pixels| pixels.checked_mul(4))
            .is_none_or(|bytes| bytes > MAX_DECODED_BYTES as u32)
    {
        return Ok(None);
    }
    if screen_flags & 0x80 != 0 {
        let table_bytes = 3usize << (usize::from(screen_flags & 0x07) + 1);
        if reader.seek(SeekFrom::Current(table_bytes as i64)).is_err() {
            return Ok(None);
        }
    }

    let mut frame_count = 0usize;
    let mut block_count = 0usize;
    let length = loop {
        block_count += 1;
        if block_count > 100_000 {
            return Ok(None);
        }
        let mut introducer = [0];
        if !gif_read_exact(&mut reader, &mut introducer)? {
            return Ok(None);
        }
        match introducer[0] {
            0x3b if frame_count > 0 => {
                break reader
                    .stream_position()
                    .map_err(|error| error.to_string())?
            }
            0x21 => {
                let mut label = [0];
                if !gif_read_exact(&mut reader, &mut label)?
                    || gif_skip_sub_blocks(&mut reader)?.is_none()
                {
                    return Ok(None);
                }
            }
            0x2c => {
                let mut descriptor = [0; 9];
                if !gif_read_exact(&mut reader, &mut descriptor)? {
                    return Ok(None);
                }
                let left = u16::from_le_bytes([descriptor[0], descriptor[1]]) as u32;
                let top = u16::from_le_bytes([descriptor[2], descriptor[3]]) as u32;
                let width = u16::from_le_bytes([descriptor[4], descriptor[5]]) as u32;
                let height = u16::from_le_bytes([descriptor[6], descriptor[7]]) as u32;
                let flags = descriptor[8];
                if width == 0
                    || height == 0
                    || left.checked_add(width).is_none_or(|end| end > canvas_width)
                    || top
                        .checked_add(height)
                        .is_none_or(|end| end > canvas_height)
                {
                    return Ok(None);
                }
                if flags & 0x80 != 0 {
                    let table_bytes = 3usize << (usize::from(flags & 0x07) + 1);
                    if reader.seek(SeekFrom::Current(table_bytes as i64)).is_err() {
                        return Ok(None);
                    }
                }
                let mut lzw_minimum_code_size = [0];
                if !gif_read_exact(&mut reader, &mut lzw_minimum_code_size)?
                    || !(2..=8).contains(&lzw_minimum_code_size[0])
                    || gif_skip_sub_blocks(&mut reader)? != Some(true)
                {
                    return Ok(None);
                }
                frame_count += 1;
                if frame_count > MAX_GIF_FRAMES {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        }
    };
    if length == 0 || length > MAX_FILE_BYTES {
        return Ok(None);
    }

    let decoder_reader = BufReader::with_capacity(
        READ_CHUNK,
        SourceRangeReader {
            source,
            start: offset,
            length,
            position: 0,
        },
    );
    let mut decoder = match image::codecs::gif::GifDecoder::new(decoder_reader) {
        Ok(decoder) => decoder,
        Err(image::ImageError::IoError(error)) if error.kind() != io::ErrorKind::UnexpectedEof => {
            return Err(error.to_string());
        }
        Err(error) => {
            return match gif_decoder_source_error(&error) {
                Some(error) => Err(error),
                None => Ok(None),
            }
        }
    };
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(32_768);
    limits.max_image_height = Some(32_768);
    limits.max_alloc = Some(MAX_DECODED_BYTES as u64);
    if decoder.set_limits(limits).is_err() {
        return Ok(None);
    }
    let mut decoded_bytes = 0usize;
    let mut decoded_frames = 0usize;
    for frame in decoder.into_frames() {
        let frame = match frame {
            Ok(frame) => frame,
            Err(image::ImageError::IoError(error))
                if error.kind() != io::ErrorKind::UnexpectedEof =>
            {
                return Err(error.to_string());
            }
            Err(error) => {
                return match gif_decoder_source_error(&error) {
                    Some(error) => Err(error),
                    None => Ok(None),
                }
            }
        };
        decoded_bytes = decoded_bytes
            .checked_add(frame.buffer().as_raw().len())
            .ok_or("GIF decoded output size overflow")?;
        decoded_frames += 1;
        if decoded_bytes > MAX_GIF_DECODED_BYTES || decoded_frames > MAX_GIF_FRAMES {
            return Ok(None);
        }
    }
    if decoded_frames != frame_count {
        return Ok(None);
    }

    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    let mut position = 0u64;
    while position < length {
        let count = (length - position).min(buffer.len() as u64) as usize;
        source
            .read_exact_at(offset + position, &mut buffer[..count])
            .map_err(|error| error.to_string())?;
        digest.update(&buffer[..count]);
        position += count as u64;
    }
    Ok(Some((length, format!("{:x}", digest.finalize()))))
}

struct CandidateReader<'a> {
    source: &'a dyn BlockSource,
    offset: u64,
    bytes: Vec<u8>,
}

impl CandidateReader<'_> {
    fn ensure(&mut self, required: usize) -> Result<bool, String> {
        if required as u64 > MAX_FILE_BYTES {
            return Ok(false);
        }
        while self.bytes.len() < required {
            let available = self.source.len().saturating_sub(self.offset);
            if self.bytes.len() as u64 >= available {
                return Ok(false);
            }
            let count = (required - self.bytes.len())
                .max(64 * 1024)
                .min((available - self.bytes.len() as u64) as usize)
                .min((MAX_FILE_BYTES - self.bytes.len() as u64) as usize);
            if count == 0 {
                return Ok(false);
            }
            let start = self.bytes.len();
            let end = start
                .checked_add(count)
                .ok_or("JPEG candidate buffer size overflow")?;
            self.bytes.try_reserve(count).map_err(|error| {
                format!("Could not grow the bounded JPEG candidate buffer: {error}")
            })?;
            self.bytes.resize(end, 0);
            self.source
                .read_exact_at(self.offset + start as u64, &mut self.bytes[start..])
                .map_err(|error| error.to_string())?;
        }
        Ok(true)
    }
}

fn is_jpeg_frame_marker(marker: u8) -> bool {
    matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf)
}

fn scan_jpeg_entropy(reader: &mut CandidateReader<'_>, cursor: &mut usize) -> Result<bool, String> {
    loop {
        if !reader.ensure(*cursor + 1)? {
            return Ok(false);
        }
        let Some(relative) = reader.bytes[*cursor..]
            .iter()
            .position(|byte| *byte == 0xff)
        else {
            *cursor = reader.bytes.len();
            continue;
        };
        let marker_start = *cursor + relative;
        if !reader.ensure(marker_start + 2)? {
            return Ok(false);
        }
        let mut marker_end = marker_start + 1;
        while reader.bytes[marker_end] == 0xff {
            marker_end += 1;
            if !reader.ensure(marker_end + 1)? {
                return Ok(false);
            }
        }
        let marker = reader.bytes[marker_end];
        if marker == 0x00 || (0xd0..=0xd7).contains(&marker) {
            *cursor = marker_end + 1;
            continue;
        }
        *cursor = marker_start;
        return Ok(true);
    }
}

fn validate_jpeg(source: &dyn BlockSource, offset: u64) -> Result<Option<(u64, String)>, String> {
    if offset >= source.len() {
        return Ok(None);
    }
    let mut reader = CandidateReader {
        source,
        offset,
        bytes: {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(64 * 1024).map_err(|error| {
                format!("Could not allocate the JPEG candidate buffer: {error}")
            })?;
            bytes
        },
    };
    if !reader.ensure(2)? || &reader.bytes[..2] != JPEG_SIGNATURE {
        return Ok(None);
    }
    let mut cursor = 2usize;
    let mut saw_frame = false;
    let mut saw_scan = false;
    let mut scan_count = 0u32;
    loop {
        if cursor as u64 >= MAX_FILE_BYTES || !reader.ensure(cursor.saturating_add(2))? {
            return Ok(None);
        }
        if reader.bytes[cursor] != 0xff {
            return Ok(None);
        }
        let mut marker_end = cursor + 1;
        while reader.bytes[marker_end] == 0xff {
            marker_end += 1;
            if marker_end as u64 >= MAX_FILE_BYTES || !reader.ensure(marker_end + 1)? {
                return Ok(None);
            }
        }
        let marker = reader.bytes[marker_end];
        if marker == 0x00 || marker == 0xd8 {
            return Ok(None);
        }
        if marker == 0xd9 {
            let length = marker_end + 1;
            if !saw_frame || !saw_scan || length as u64 > MAX_FILE_BYTES {
                return Ok(None);
            }
            reader.bytes.truncate(length);
            let mut decoder = match image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(
                reader.bytes.as_slice(),
            )) {
                Ok(decoder) => decoder,
                Err(_) => return Ok(None),
            };
            let mut limits = image::Limits::default();
            limits.max_image_width = Some(32_768);
            limits.max_image_height = Some(32_768);
            limits.max_alloc = Some(MAX_DECODED_BYTES as u64);
            if decoder.set_limits(limits).is_err()
                || decoder.total_bytes() > MAX_DECODED_BYTES as u64
            {
                return Ok(None);
            }
            let mut decoded =
                try_zeroed_buffer(decoder.total_bytes() as usize, "JPEG image decoding")?;
            if decoder.read_image(&mut decoded).is_err() {
                return Ok(None);
            }
            let digest = format!("{:x}", Sha256::digest(&reader.bytes));
            return Ok(Some((length as u64, digest)));
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            cursor = marker_end + 1;
            continue;
        }
        let length_index = marker_end + 1;
        if !reader.ensure(length_index.saturating_add(2))? {
            return Ok(None);
        }
        let segment_length =
            u16::from_be_bytes([reader.bytes[length_index], reader.bytes[length_index + 1]])
                as usize;
        if segment_length < 2 {
            return Ok(None);
        }
        let segment_end = length_index.saturating_add(segment_length);
        if segment_end as u64 > MAX_FILE_BYTES || !reader.ensure(segment_end)? {
            return Ok(None);
        }
        if is_jpeg_frame_marker(marker) {
            let payload = length_index + 2;
            if segment_length < 8 {
                return Ok(None);
            }
            let height = u16::from_be_bytes([reader.bytes[payload + 1], reader.bytes[payload + 2]]);
            let width = u16::from_be_bytes([reader.bytes[payload + 3], reader.bytes[payload + 4]]);
            let components = reader.bytes[payload + 5] as usize;
            if width == 0
                || height == 0
                || !(1..=4).contains(&components)
                || segment_length != 8 + 3 * components
                || saw_frame
            {
                return Ok(None);
            }
            saw_frame = true;
        }
        cursor = segment_end;
        if marker == 0xda {
            if !saw_frame || segment_length < 6 {
                return Ok(None);
            }
            saw_scan = true;
            scan_count += 1;
            if scan_count > 1_000 || !scan_jpeg_entropy(&mut reader, &mut cursor)? {
                return Ok(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn oversized_buffer_request_fails_without_panicking() {
        let error = try_zeroed_buffer(usize::MAX, "test candidate").unwrap_err();
        assert!(error.contains("test candidate"));

        assert_eq!(try_zeroed_buffer(4, "test candidate").unwrap(), [0; 4]);
    }

    struct TestSource(Vec<u8>);

    impl BlockSource for TestSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            let start =
                usize::try_from(offset).map_err(|_| std::io::Error::other("offset overflow"))?;
            let end = start
                .checked_add(buffer.len())
                .filter(|end| *end <= self.0.len())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            buffer.copy_from_slice(&self.0[start..end]);
            Ok(())
        }
    }

    struct ReadLimitedSource<'a> {
        source: &'a dyn BlockSource,
        maximum_read: usize,
    }

    impl BlockSource for ReadLimitedSource<'_> {
        fn len(&self) -> u64 {
            self.source.len()
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            if buffer.len() > self.maximum_read {
                return Err(std::io::Error::other("read exceeded the configured bound"));
            }
            self.source.read_exact_at(offset, buffer)
        }
    }

    #[test]
    fn archived_carve_scan_lookup_scopes_audit_memory_to_the_selected_case() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE audit(event TEXT NOT NULL,payload TEXT NOT NULL);
             CREATE TABLE carve_scan_sessions(
                id INTEGER PRIMARY KEY,
                evidence_id INTEGER NOT NULL,
                case_id INTEGER NOT NULL,
                source_sha256 TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                scanned_bytes INTEGER NOT NULL,
                candidates_json TEXT NOT NULL,
                snapshot_sha256 TEXT NOT NULL,
                candidates_limited INTEGER NOT NULL
             );",
        )
        .unwrap();

        for id in 1..=5_000 {
            db.execute(
                "INSERT INTO audit(event,payload) VALUES ('carve_scan_persisted',?1)",
                [format!("{{\"case_id\":99,\"scan_session_id\":{id}}}")],
            )
            .unwrap();
        }

        let source_sha256 = "a".repeat(64);
        let candidates_json = "[]";
        let snapshot_sha256 = snapshot_digest(&source_sha256, 4096, false, candidates_json);
        db.execute(
            "INSERT INTO carve_scan_sessions(id,evidence_id,case_id,source_sha256,completed_at,scanned_bytes,candidates_json,snapshot_sha256,candidates_limited) VALUES (1,2,7,?1,'1',4096,?2,?3,0)",
            rusqlite::params![source_sha256, candidates_json, snapshot_sha256],
        )
        .unwrap();
        let payload = serde_json::json!({
            "case_id": 7,
            "scan_session_id": 1,
            "evidence_record_id": 2,
            "source_sha256": source_sha256,
            "scanned_bytes": 4096,
            "candidates": 0,
            "candidates_limited": false,
            "snapshot_sha256": snapshot_sha256,
        });
        db.execute(
            "INSERT INTO audit(event,payload) VALUES ('carve_scan_persisted',?1)",
            [payload.to_string()],
        )
        .unwrap();

        let sessions = list_case_scan_sessions_from(&db, 7).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, 1);
        assert!(sessions[0].candidates.is_empty());
    }

    struct FailAfterFirstFullRead {
        bytes: Vec<u8>,
        full_reads: std::sync::atomic::AtomicUsize,
    }

    impl BlockSource for FailAfterFirstFullRead {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            if offset == 0 && buffer.len() == self.bytes.len() {
                let prior = self.full_reads.fetch_add(1, Ordering::SeqCst);
                if prior > 0 {
                    return Err(std::io::Error::other(
                        "injected final source recheck failure",
                    ));
                }
            }
            let start =
                usize::try_from(offset).map_err(|_| std::io::Error::other("offset overflow"))?;
            let end = start
                .checked_add(buffer.len())
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            buffer.copy_from_slice(&self.bytes[start..end]);
            Ok(())
        }
    }

    struct DecoderReadFailure {
        bytes: Vec<u8>,
        failing_offset: u64,
        failing_length: usize,
    }

    #[test]
    fn failed_carving_export_reports_the_unverified_package_path() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("daemoncore-carving-path-{stamp}"));
        let package = root.join("DaemonCore-Carved-Recovery-incomplete");
        fs::create_dir_all(&package).unwrap();

        let error = report_incomplete_package_path::<()>(Err("source changed".into()), &package)
            .unwrap_err();

        assert!(error.contains("source changed"));
        assert!(error.contains(&package.to_string_lossy().to_string()));
        assert!(error.contains("Treat it as unverified"));
        assert!(crate::recovery_verify::verify_package(&package).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn final_source_recheck_failure_reports_real_incomplete_export() {
        let mut bytes = vec![0x5a; 17];
        bytes.extend_from_slice(&valid_png());
        let scan = scan_supported_files(
            &TestSource(bytes.clone()),
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(scan.candidates.len(), 1);
        let source = FailAfterFirstFullRead {
            bytes: bytes.clone(),
            full_reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("daemoncore-carving-failure-{stamp}"));
        fs::create_dir_all(&root).unwrap();

        let error = export_selected(
            &source,
            &scan.candidates,
            &root,
            ExportIdentity {
                case_id: 4,
                evidence_record_id: 9,
                scan_session_id: 12,
                source_id: 7,
                source_path: "synthetic.raw",
                source_sha256: &source_sha256,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap_err();

        let package = fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert!(error.contains("injected final source recheck failure"));
        assert!(error.contains(&package.to_string_lossy().to_string()));
        assert!(error.contains("Treat it as unverified"));
        assert!(package.join("carved-0000000000000011.png").is_file());
        assert!(crate::recovery_verify::verify_package(&package).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    impl BlockSource for DecoderReadFailure {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            if offset == self.failing_offset && buffer.len() == self.failing_length {
                return Err(std::io::Error::other("injected image read failure"));
            }
            let start =
                usize::try_from(offset).map_err(|_| std::io::Error::other("offset overflow"))?;
            let end = start
                .checked_add(buffer.len())
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            buffer.copy_from_slice(&self.bytes[start..end]);
            Ok(())
        }
    }

    fn valid_png() -> Vec<u8> {
        let mut output = Vec::new();
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&[0xff, 0x20, 0x30, 0xff]).unwrap();
        drop(writer);
        output
    }

    fn valid_bmp() -> Vec<u8> {
        let mut output = vec![0; 58];
        output[..2].copy_from_slice(BMP_SIGNATURE);
        output[2..6].copy_from_slice(&58u32.to_le_bytes());
        output[10..14].copy_from_slice(&54u32.to_le_bytes());
        output[14..18].copy_from_slice(&40u32.to_le_bytes());
        output[18..22].copy_from_slice(&1i32.to_le_bytes());
        output[22..26].copy_from_slice(&1i32.to_le_bytes());
        output[26..28].copy_from_slice(&1u16.to_le_bytes());
        output[28..30].copy_from_slice(&24u16.to_le_bytes());
        output[34..38].copy_from_slice(&4u32.to_le_bytes());
        output
    }

    fn valid_jpeg() -> Vec<u8> {
        include_bytes!("../tests/fixtures/forensic-jpeg-16x12.jpg").to_vec()
    }

    fn valid_gif() -> Vec<u8> {
        let frames = [
            image::Rgba([0xff, 0x20, 0x30, 0xff]),
            image::Rgba([0x10, 0x80, 0xe0, 0xff]),
        ]
        .into_iter()
        .map(|pixel| image::Frame::new(image::RgbaImage::from_pixel(2, 2, pixel)))
        .collect::<Vec<_>>();
        let mut output = Vec::new();
        image::codecs::gif::GifEncoder::new(Cursor::new(&mut output))
            .encode_frames(frames)
            .unwrap();
        output
    }

    #[test]
    fn supported_format_inventory_matches_scanner_output() {
        let mut image = valid_png();
        image.extend_from_slice(&valid_bmp());
        image.extend_from_slice(&valid_jpeg());
        image.extend_from_slice(&valid_gif());
        let scan = scan_supported_files(&TestSource(image), &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        let mut scanned_formats = scan
            .candidates
            .iter()
            .map(|candidate| candidate.format.as_str())
            .collect::<Vec<_>>();
        scanned_formats.sort_unstable();
        scanned_formats.dedup();

        let mut declared_formats = SUPPORTED_FORMATS.to_vec();
        declared_formats.sort_unstable();
        assert_eq!(scanned_formats, declared_formats);
    }

    #[test]
    fn decodes_independently_generated_gif_against_known_bytes() {
        let gif = include_bytes!("../tests/fixtures/forensic-gif-16x12.gif");
        let offset = 23;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(gif);
        let scan = scan_supported_files(&TestSource(image), &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        let candidate = scan
            .candidates
            .iter()
            .find(|candidate| candidate.format == "GIF")
            .expect("GDI+-encoded GIF should decode");

        assert_eq!(candidate.offset, offset as u64);
        assert_eq!(candidate.length, 854);
        assert_eq!(
            candidate.sha256,
            "4d1be0dda7762d6527f6aac405befa4ecabed5746dd04c9eb1f11ef1b057d170"
        );
        assert_eq!(
            candidate.validation,
            "GIF structure valid; all frames decoded within limits"
        );

        let frames = image::codecs::gif::GifDecoder::new(Cursor::new(gif.as_slice()))
            .unwrap()
            .into_frames()
            .collect_frames()
            .unwrap();
        assert_eq!(frames.len(), 1);
        let expected = [
            [
                image::Rgba([0, 0, 0, 255]),
                image::Rgba([255, 255, 255, 255]),
            ],
            [image::Rgba([255, 0, 0, 255]), image::Rgba([0, 255, 0, 255])],
        ];
        for y in 0..12 {
            for x in 0..16 {
                assert_eq!(
                    *frames[0].buffer().get_pixel(x, y),
                    expected[(y % 2) as usize][(x % 2) as usize]
                );
            }
        }
    }

    #[test]
    #[ignore = "requires the hash-pinned independent exFAT reference image"]
    fn carves_independent_exfat_image_files_against_upstream_hashes() {
        let image_path = std::env::var_os("DAEMONCORE_CARVING_REFERENCE_IMAGE")
            .expect("set DAEMONCORE_CARVING_REFERENCE_IMAGE to fs.exfat.raw");
        let image = std::fs::read(image_path).expect("read independent exFAT reference image");
        let source = TestSource(image);
        let result = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        for (format, length, expected_sha256) in [
            (
                "JPEG",
                689_275_u64,
                "76204f90870d97c2d462c58e113f8a90f2edf4b6fbd95ac2f0f876bb4e61b311",
            ),
            (
                "PNG",
                83_972_u64,
                "a331c17e8e1c28e734937353b633708b8e0c0816ee5ff1926e89cff957a68f08",
            ),
        ] {
            assert!(
                result.candidates.iter().any(|candidate| {
                    candidate.format == format
                        && candidate.length == length
                        && candidate.sha256 == expected_sha256
                }),
                "carver did not recover upstream {format} fixture bytes",
            );
        }
    }

    #[test]
    fn finds_decodable_png_across_scan_chunk_boundary_and_hashes_source() {
        let png = valid_png();
        let offset = READ_CHUNK - 3;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(&png);
        image.extend_from_slice(&[0; 20]);
        let expected = format!("{:x}", Sha256::digest(&image));
        let source = TestSource(image);
        let result = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        assert_eq!(result.scanned_bytes, source.len());
        assert_eq!(result.source_sha256, expected);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].offset, offset as u64);
        assert_eq!(result.candidates[0].length, png.len() as u64);
    }

    #[test]
    fn validates_large_png_chunks_with_bounded_source_reads() {
        let mut png = valid_png();
        let payload = vec![0x5a; READ_CHUNK + 17];
        let kind = *b"npAD";
        let mut crc = crc32fast::Hasher::new();
        crc.update(&kind);
        crc.update(&payload);
        let mut chunk = Vec::with_capacity(payload.len() + 12);
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(&kind);
        chunk.extend_from_slice(&payload);
        chunk.extend_from_slice(&crc.finalize().to_be_bytes());
        // Insert an ancillary chunk after IHDR to exercise multi-read handling.
        png.splice(8 + 25..8 + 25, chunk);

        let source = TestSource(png);
        let limited = ReadLimitedSource {
            source: &source,
            maximum_read: READ_CHUNK,
        };
        let result = scan_supported_files(&limited, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].format, "PNG");
        assert_eq!(result.candidates[0].length, source.len());
    }

    #[test]
    fn finds_and_verifies_animated_gif_across_scan_boundary() {
        let gif = valid_gif();
        let offset = READ_CHUNK - 1;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(&gif);
        image.extend_from_slice(&[0; 20]);
        let expected_source_sha256 = format!("{:x}", Sha256::digest(&image));
        let source = TestSource(image);
        let scan = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        assert_eq!(scan.candidates.len(), 1);
        let candidate = &scan.candidates[0];
        assert_eq!(candidate.format, "GIF");
        assert_eq!(candidate.offset, offset as u64);
        assert_eq!(candidate.length, gif.len() as u64);
        assert_eq!(candidate.sha256, format!("{:x}", Sha256::digest(&gif)));
        assert_eq!(
            candidate.validation,
            "GIF structure valid; all frames decoded within limits"
        );

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/t")
            .join(format!(
                "gif-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&root).unwrap();
        let package = export_selected(
            &source,
            &scan.candidates,
            &root,
            ExportIdentity {
                case_id: 4,
                evidence_record_id: 9,
                scan_session_id: 12,
                source_id: 7,
                source_path: "synthetic.raw",
                source_sha256: &expected_source_sha256,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let output = Path::new(&package.directory).join(format!("carved-{offset:016x}.gif"));
        assert_eq!(fs::read(output).unwrap(), gif);
        let verified = crate::recovery_verify::verify_package(Path::new(&package.directory))
            .expect("GIF carving package should pass native verification");
        assert_eq!(verified.exported, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_truncated_and_incomplete_gif_candidates() {
        let gif = valid_gif();
        let mut truncated = gif.clone();
        truncated.truncate(truncated.len() - 1);
        assert!(
            scan_supported_files(&TestSource(truncated), &AtomicBool::new(false), |_, _| {},)
                .unwrap()
                .unwrap()
                .candidates
                .is_empty()
        );

        let mut invalid = gif;
        let trailer = invalid.len() - 1;
        invalid[trailer] = 0;
        assert!(
            scan_supported_files(&TestSource(invalid), &AtomicBool::new(false), |_, _| {})
                .unwrap()
                .unwrap()
                .candidates
                .is_empty()
        );
    }

    #[test]
    fn surfaces_gif_source_read_errors_instead_of_skipping_the_candidate() {
        let gif = valid_gif();
        let offset = 17;
        let mut bytes = vec![0x5a; offset];
        bytes.extend_from_slice(&gif);
        let source = DecoderReadFailure {
            bytes,
            failing_offset: offset as u64,
            failing_length: gif.len(),
        };
        let error = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .expect_err("a GIF source read error must stop the scan");
        assert!(error.contains("injected image read failure"));
    }

    #[test]
    fn candidate_limit_is_reported_without_stopping_source_coverage() {
        let bmp = valid_bmp();
        let source_bytes = bmp.repeat(MAX_CANDIDATES + 1);
        let source = TestSource(source_bytes);
        let result = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        assert_eq!(result.candidates.len(), MAX_CANDIDATES);
        assert!(result.candidates_limited);
        assert_eq!(result.scanned_bytes, source.len());
        assert_eq!(
            result.candidates.last().unwrap().offset,
            (MAX_CANDIDATES - 1) as u64 * bmp.len() as u64
        );
    }

    #[test]
    fn rejects_png_with_corrupt_chunk_crc() {
        let mut png = valid_png();
        let crc = png.len() - 5;
        png[crc] ^= 1;
        let source = TestSource(png);
        let result = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn finds_and_verifies_bmp_across_scan_boundary() {
        let bmp = valid_bmp();
        let offset = READ_CHUNK - 1;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(&bmp);
        let expected_source_sha256 = format!("{:x}", Sha256::digest(&image));
        let source = TestSource(image);
        let scan = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(scan.candidates[0].format, "BMP");
        assert_eq!(scan.candidates[0].length, bmp.len() as u64);
        assert_eq!(scan.candidates[0].offset, offset as u64);

        let mut invalid_geometry = valid_bmp();
        invalid_geometry[18..22].copy_from_slice(&0i32.to_le_bytes());
        assert!(scan_supported_files(
            &TestSource(invalid_geometry),
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap()
        .unwrap()
        .candidates
        .is_empty());
        let mut truncated = valid_bmp();
        truncated.pop();
        assert!(
            scan_supported_files(&TestSource(truncated), &AtomicBool::new(false), |_, _| {},)
                .unwrap()
                .unwrap()
                .candidates
                .is_empty()
        );

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/t")
            .join(format!(
                "bmp-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&root).unwrap();
        let package = export_selected(
            &source,
            &scan.candidates,
            &root,
            ExportIdentity {
                case_id: 4,
                evidence_record_id: 9,
                scan_session_id: 12,
                source_id: 7,
                source_path: "synthetic.raw",
                source_sha256: &expected_source_sha256,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let output = Path::new(&package.directory).join(format!("carved-{offset:016x}.bmp"));
        assert_eq!(fs::read(output).unwrap(), bmp);
        let verified = crate::recovery_verify::verify_package(Path::new(&package.directory))
            .expect("BMP carving package should pass native verification");
        assert_eq!(verified.exported, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn decodes_independently_generated_bmp_against_known_bytes() {
        let bmp = include_bytes!("../tests/fixtures/forensic-bmp-16x12.bmp");
        let offset = 19;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(bmp);
        let scan = scan_supported_files(&TestSource(image), &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();

        let candidate = scan
            .candidates
            .iter()
            .find(|candidate| candidate.format == "BMP")
            .expect("Pillow-generated BMP should decode");
        assert_eq!(candidate.offset, offset as u64);
        assert_eq!(candidate.length, 630);
        assert_eq!(
            candidate.sha256,
            "f55ff8aa849bbde392a5e6e4816ca7a609b0289deab22eb1408c0592d231ce13"
        );
        assert_eq!(
            candidate.validation,
            "BMP pixels decoded; bounded dimensions and allocation valid"
        );
    }

    #[test]
    fn rejects_bmp_with_missing_bitfield_masks_after_valid_geometry() {
        let mut bmp = vec![0; 74];
        bmp[..2].copy_from_slice(BMP_SIGNATURE);
        bmp[2..6].copy_from_slice(&74u32.to_le_bytes());
        bmp[10..14].copy_from_slice(&70u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&56u32.to_le_bytes());
        bmp[18..22].copy_from_slice(&1i32.to_le_bytes());
        bmp[22..26].copy_from_slice(&1i32.to_le_bytes());
        bmp[26..28].copy_from_slice(&1u16.to_le_bytes());
        bmp[28..30].copy_from_slice(&16u16.to_le_bytes());
        bmp[30..34].copy_from_slice(&3u32.to_le_bytes());
        bmp[34..38].copy_from_slice(&4u32.to_le_bytes());

        let result = scan_supported_files(&TestSource(bmp), &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn surfaces_bmp_pixel_read_errors_instead_of_skipping_the_candidate() {
        let bmp = valid_bmp();
        let offset = (READ_CHUNK - 1) as u64;
        let mut bytes = vec![0x5a; offset as usize];
        bytes.extend_from_slice(&bmp);
        let source = DecoderReadFailure {
            bytes,
            failing_offset: offset,
            failing_length: bmp.len(),
        };

        let error = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .expect_err("a source read failure during BMP decode must stop the scan");
        assert!(error.contains("injected image read failure"));
    }

    #[test]
    fn decodes_jpeg_and_verifies_export_across_scan_boundary() {
        let jpeg = valid_jpeg();
        let offset = READ_CHUNK - 1;
        let mut image = vec![0x5a; offset];
        image.extend_from_slice(&jpeg);
        let expected_source_sha256 = format!("{:x}", Sha256::digest(&image));
        let source = TestSource(image);
        let scan = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(scan.candidates[0].format, "JPEG");
        assert_eq!(scan.candidates[0].length, jpeg.len() as u64);
        assert_eq!(scan.candidates[0].offset, offset as u64);
        assert_eq!(
            scan.candidates[0].validation,
            "JPEG decoded; dimensions and allocation bounds valid"
        );

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/t")
            .join(format!(
                "jpeg-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&root).unwrap();
        let package = export_selected(
            &source,
            &scan.candidates,
            &root,
            ExportIdentity {
                case_id: 4,
                evidence_record_id: 9,
                scan_session_id: 12,
                source_id: 7,
                source_path: "synthetic.raw",
                source_sha256: &expected_source_sha256,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let output = Path::new(&package.directory).join(format!("carved-{offset:016x}.jpg"));
        assert_eq!(fs::read(output).unwrap(), jpeg);
        let verified = crate::recovery_verify::verify_package(Path::new(&package.directory))
            .expect("JPEG carving package should pass native verification");
        assert_eq!(verified.exported, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_truncated_and_oversized_jpeg_candidates() {
        let jpeg = valid_jpeg();
        let mut truncated = jpeg.clone();
        truncated.truncate(truncated.len() - 2);
        assert!(
            scan_supported_files(&TestSource(truncated), &AtomicBool::new(false), |_, _| {},)
                .unwrap()
                .unwrap()
                .candidates
                .is_empty()
        );

        let mut oversized = jpeg;
        let frame = oversized
            .windows(2)
            .position(|pair| pair[0] == 0xff && is_jpeg_frame_marker(pair[1]))
            .unwrap();
        let width_start = frame + 7;
        let height_start = frame + 5;
        oversized[width_start..width_start + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        oversized[height_start..height_start + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(
            scan_supported_files(&TestSource(oversized), &AtomicBool::new(false), |_, _| {},)
                .unwrap()
                .unwrap()
                .candidates
                .is_empty()
        );
    }

    #[test]
    fn cancellation_returns_no_partial_candidate_set() {
        let source = TestSource(vec![0; READ_CHUNK * 2]);
        let cancel = AtomicBool::new(true);
        assert!(scan_supported_files(&source, &cancel, |_, _| {})
            .unwrap()
            .is_none());
    }

    #[test]
    fn carved_png_export_writes_a_hashed_no_replace_package() {
        let png = valid_png();
        let mut image = vec![0x11; 23];
        image.extend_from_slice(&png);
        let expected_source_sha256 = format!("{:x}", Sha256::digest(&image));
        let source = TestSource(image);
        let scan = scan_supported_files(&source, &AtomicBool::new(false), |_, _| {})
            .unwrap()
            .unwrap();
        let test_parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/t");
        fs::create_dir_all(&test_parent).unwrap();
        let root = test_parent.join(format!(
            "c-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let package = export_selected(
            &source,
            &scan.candidates,
            &root,
            ExportIdentity {
                case_id: 4,
                evidence_record_id: 9,
                scan_session_id: 12,
                source_id: 7,
                source_path: "synthetic.raw",
                source_sha256: &expected_source_sha256,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();

        assert_eq!(package.exported, 1);
        assert_eq!(package.failed, 0);
        assert_eq!(
            package.source_sha256_after.as_deref(),
            Some(expected_source_sha256.as_str())
        );
        let output = Path::new(&package.directory).join(format!("carved-{:016x}.png", 23));
        assert_eq!(fs::read(output).unwrap(), png);
        let marker: serde_json::Value = serde_json::from_slice(
            &fs::read(Path::new(&package.directory).join("completion.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(marker["state"], "complete");
        let checksums =
            fs::read_to_string(Path::new(&package.directory).join("checksums.sha256")).unwrap();
        assert!(checksums.contains("manifest.json"));
        assert!(checksums.contains("inventory.jsonl"));
        assert!(checksums.contains("summary.json"));
        let verified = crate::recovery_verify::verify_package(Path::new(&package.directory))
            .expect("carved recovery package should pass the native verifier");
        assert_eq!(verified.state, "complete");
        assert_eq!(verified.records, 1);
        assert_eq!(verified.exported, 1);
        assert_eq!(verified.case_id, Some(4));
        fs::write(
            Path::new(&package.directory).join(format!("carved-{:016x}.png", 23)),
            b"modified output",
        )
        .unwrap();
        assert!(crate::recovery_verify::verify_package(Path::new(&package.directory)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
