use crate::{audit, err, ntfs, recovery, storage::BlockSource, AppState, Job, Result, ScanSession};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};
use tauri::{Manager, State};

#[derive(Serialize)]
pub struct ScanSummary {
    scan_session_id: i64,
    source_id: u64,
    boot: ntfs::Boot,
    records: u64,
    skipped: u64,
    found: usize,
    limited: bool,
    cancelled: bool,
    source_sha256: String,
}
#[derive(Serialize)]
pub struct CaseScanSession {
    id: i64,
    evidence_id: i64,
    case_id: i64,
    volume_offset: String,
    source_sha256: String,
    completed_at: String,
    records: u64,
    skipped: u64,
    found: usize,
    limited: bool,
}
#[derive(Serialize)]
pub struct Page {
    total: usize,
    rows: Vec<ntfs::Candidate>,
}

struct ScanSnapshot<'a> {
    evidence_id: i64,
    case_id: i64,
    source_id: u64,
    volume_offset: u64,
    source_sha256: &'a str,
    boot: &'a ntfs::Boot,
    records: u64,
    skipped: u64,
    limited: bool,
    candidates: &'a [ntfs::Candidate],
}

fn persist_scan_snapshot(
    db: &mut rusqlite::Connection,
    snapshot: &ScanSnapshot<'_>,
) -> Result<i64> {
    let candidates_json = serde_json::to_string(snapshot.candidates).map_err(err)?;
    let boot_json = serde_json::to_string(snapshot.boot).map_err(err)?;
    let snapshot_sha256 = scan_snapshot_digest(&boot_json, &candidates_json);
    let completed_at = crate::audit_timestamp(std::time::SystemTime::now())?;
    let tx = db.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO scan_sessions(evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,records,skipped,found,limited,candidates_json,snapshot_sha256) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        rusqlite::params![snapshot.evidence_id, snapshot.case_id, snapshot.volume_offset.to_string(), snapshot.source_sha256, completed_at, boot_json, snapshot.records, snapshot.skipped, snapshot.candidates.len() as i64, snapshot.limited as i64, candidates_json, snapshot_sha256],
    ).map_err(err)?;
    let scan_session_id = tx.last_insert_rowid();
    audit(
        &tx,
        "ntfs_scan_persisted",
        &serde_json::json!({"case_id":snapshot.case_id,"evidence_id":snapshot.evidence_id,"scan_session_id":scan_session_id,"source_id":snapshot.source_id,"volume_offset":snapshot.volume_offset,"source_sha256":snapshot.source_sha256,"records":snapshot.records,"skipped":snapshot.skipped,"found":snapshot.candidates.len(),"limited":snapshot.limited,"snapshot_sha256":snapshot_sha256}).to_string(),
    )?;
    tx.commit().map_err(err)?;
    Ok(scan_session_id)
}

fn scan_snapshot_digest(boot_json: &str, candidates_json: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"DaemonCore NTFS scan snapshot v1\0");
    digest.update((boot_json.len() as u64).to_le_bytes());
    digest.update(boot_json.as_bytes());
    digest.update((candidates_json.len() as u64).to_le_bytes());
    digest.update(candidates_json.as_bytes());
    format!("{:x}", digest.finalize())
}

#[tauri::command]
pub fn list_case_scan_sessions(
    case_id: i64,
    state: State<AppState>,
) -> Result<Vec<CaseScanSession>> {
    let db = state.db.lock().map_err(err)?;
    list_case_scan_sessions_from(&db, case_id)
}

#[tauri::command]
pub fn archived_scan_results(
    case_id: i64,
    scan_session_id: i64,
    offset: usize,
    limit: usize,
    state: State<AppState>,
) -> Result<Page> {
    if limit == 0 || limit > 200 {
        return Err("Invalid archived-results page size.".into());
    }
    let db = state.db.lock().map_err(err)?;
    archived_scan_results_from(&db, case_id, scan_session_id, offset, limit)
}

fn archived_scan_results_from(
    db: &rusqlite::Connection,
    case_id: i64,
    scan_session_id: i64,
    offset: usize,
    limit: usize,
) -> Result<Page> {
    let sessions = list_case_scan_sessions_from(db, case_id)?;
    let session = sessions
        .iter()
        .find(|session| session.id == scan_session_id)
        .ok_or("The archived scan does not belong to the selected case.")?;
    let candidates_json: String = db
        .query_row(
            "SELECT candidates_json FROM scan_sessions WHERE id=?1 AND case_id=?2",
            rusqlite::params![scan_session_id, case_id],
            |row| row.get(0),
        )
        .map_err(err)?;
    let candidates: Vec<ntfs::Candidate> =
        serde_json::from_str(&candidates_json).map_err(|error| {
            format!("Archived scan candidates do not match the supported schema: {error}")
        })?;
    if candidates.len() != session.found {
        return Err("Archived scan candidate count does not match the audited record.".into());
    }
    Ok(Page {
        total: candidates.len(),
        rows: candidates.into_iter().skip(offset).take(limit).collect(),
    })
}

fn list_case_scan_sessions_from(
    db: &rusqlite::Connection,
    case_id: i64,
) -> Result<Vec<CaseScanSession>> {
    let chain = crate::verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='ntfs_scan_persisted'")
        .map_err(err)?;
    let audit_rows = audit_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(err)?;
    let mut audit_snapshots = std::collections::HashMap::new();
    for row in audit_rows {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        if let (Some(id), Some(case), Some(snapshot_hash)) = (
            payload
                .get("scan_session_id")
                .and_then(serde_json::Value::as_i64),
            payload.get("case_id").and_then(serde_json::Value::as_i64),
            payload
                .get("snapshot_sha256")
                .and_then(serde_json::Value::as_str),
        ) {
            audit_snapshots.insert(id, (case, snapshot_hash.to_owned(), payload));
        }
    }
    let mut statement = db
        .prepare("SELECT id,evidence_id,case_id,volume_offset,source_sha256,completed_at,records,skipped,found,limited,boot_json,candidates_json,snapshot_sha256 FROM scan_sessions WHERE case_id=?1 ORDER BY id DESC")
        .map_err(err)?;
    let rows = statement
        .query_map([case_id], |row| {
            Ok((
                CaseScanSession {
                    id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    case_id: row.get(2)?,
                    volume_offset: row.get(3)?,
                    source_sha256: row.get(4)?,
                    completed_at: row.get(5)?,
                    records: row.get(6)?,
                    skipped: row.get(7)?,
                    found: row.get(8)?,
                    limited: row.get::<_, i64>(9)? != 0,
                },
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
            ))
        })
        .map_err(err)?;
    let mut sessions = Vec::new();
    for row in rows {
        let (session, boot_json, candidates_json, stored_hash) = row.map_err(err)?;
        let calculated_hash = scan_snapshot_digest(&boot_json, &candidates_json);
        let payload = audit_snapshots
            .get(&session.id)
            .ok_or("A stored scan snapshot has no matching audit record.")?;
        let candidates: serde_json::Value = serde_json::from_str(&candidates_json).map_err(err)?;
        let boot: serde_json::Value = serde_json::from_str(&boot_json).map_err(err)?;
        if payload.0 != case_id
            || payload.1 != stored_hash
            || stored_hash != calculated_hash
            || payload.2["evidence_id"].as_i64() != Some(session.evidence_id)
            || payload.2["source_sha256"].as_str() != Some(session.source_sha256.as_str())
            || payload.2["records"].as_u64() != Some(session.records)
            || payload.2["skipped"].as_u64() != Some(session.skipped)
            || payload.2["found"].as_u64() != Some(session.found as u64)
            || payload.2["limited"].as_bool() != Some(session.limited)
            || !boot.is_object()
            || candidates
                .as_array()
                .is_none_or(|values| values.len() != session.found)
        {
            return Err(format!(
                "Stored scan snapshot {} does not match its audited contents.",
                session.id
            ));
        }
        sessions.push(session);
    }
    Ok(sessions)
}

struct AuditSource<'a> {
    case_id: i64,
    evidence_record_id: i64,
    scan_session_id: i64,
    source_id: u64,
    source_path: &'a str,
    source_sha256: &'a str,
}

fn export_audit_payload(
    source: AuditSource<'_>,
    selected: &[ntfs::Candidate],
    destination: Option<&std::path::Path>,
    outcome: Option<&Job>,
) -> String {
    let records = selected
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "record": candidate.id,
                "record_sha256": candidate.fingerprint,
                "size": candidate.size,
                "filename_references": candidate.filename_references,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "case_id": source.case_id,
        "evidence_record_id": source.evidence_record_id,
        "scan_session_id": source.scan_session_id,
        "source_id": source.source_id,
        "source_path": source.source_path,
        "source_sha256": source.source_sha256,
        "records": records,
        "destination": destination.map(|path| path.to_string_lossy().into_owned()),
        "outcome": outcome,
    })
    .to_string()
}

#[tauri::command]
pub fn start_ntfs_scan(offset: u64, app: tauri::AppHandle, state: State<AppState>) -> Result<()> {
    let source = state.source.lock().map_err(err)?;
    let source = source.as_ref().ok_or("Open an image first.")?;
    if source.integrity_compromised {
        return Err(
            "The source changed during examination. Reopen a verified working copy.".into(),
        );
    }
    let source_sha256 = source
        .info
        .sha256
        .clone()
        .ok_or("Calculate the source SHA-256 before scanning.")?;
    source.image.verify_unchanged().map_err(err)?;
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("An operation is already running.".into());
    }
    if offset >= source.image.len() {
        return Err("Volume offset is outside the image.".into());
    }
    let image = source.image.clone();
    let source_id = source.info.id;
    let case_id = source.info.case_id;
    let evidence_record_id = source.info.evidence_record_id;
    audit(
        &*state.db.lock().map_err(err)?,
        "ntfs_scan_started",
        &serde_json::json!({"case_id":case_id,"source_id":source_id,"source_sha256":source_sha256,"offset":offset})
            .to_string(),
    )
    .map_err(err)?;
    *state.scan.lock().map_err(err)? = None;
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "ntfs_scan".into(),
        message: Some("Reading NTFS metadata".into()),
        ..Job::default()
    };
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = crate::guarded(|| {
            ntfs::scan(
                image.as_ref(),
                offset,
                &state.cancel,
                |processed, total, found| {
                    if let Ok(mut job) = state.job.lock() {
                        job.processed = processed;
                        job.total = total;
                        job.discovered = found;
                    }
                },
            )
        })
        .and_then(|scan| {
            image.verify_unchanged().map_err(err)?;
            if scan.cancelled {
                return Err("Scan cancelled before source integrity could be rechecked; results were discarded.".into());
            }
            if let Ok(mut job) = state.job.lock() {
                job.message = Some("Rechecking the complete source SHA-256".into());
                job.total = image.len();
                job.processed = 0;
            }
            let after = crate::hash_source(image.as_ref(), &state.cancel, |processed| {
                if let Ok(mut job) = state.job.lock() {
                    job.processed = processed;
                }
            })?
                .ok_or("Source verification was cancelled; scan results were discarded.")?;
            if after != source_sha256 {
                if let Ok(mut source) = state.source.lock() {
                    if let Some(source) = source.as_mut().filter(|source| source.info.id == source_id) {
                        source.info.sha256 = None;
                        source.integrity_compromised = true;
                    }
                }
                return Err("Source SHA-256 changed during scan. Results were discarded; quarantine this working copy and investigate the change.".into());
            }
            Ok(scan)
        });
        if let Ok(mut job) = state.job.lock() {
            match result {
                Ok(result) => {
                    job.discovered = result.candidates.len();
                    job.message = Some(format!(
                        "{} records examined; {} deleted-file candidates; {} records skipped.{}",
                        result.records,
                        result.candidates.len(),
                        result.invalid_records,
                        if result.limited {
                            " Safety limit reached; this is a partial scan."
                        } else {
                            ""
                        }
                    ));
                    let persisted = state.db.lock().map_err(err).and_then(|mut db| {
                        persist_scan_snapshot(
                            &mut db,
                            &ScanSnapshot {
                                evidence_id: evidence_record_id,
                                case_id,
                                source_id,
                                volume_offset: offset,
                                source_sha256: &source_sha256,
                                boot: &result.boot,
                                records: result.records,
                                skipped: result.invalid_records,
                                limited: result.limited,
                                candidates: &result.candidates,
                            },
                        )
                    });
                    if let Ok(persistent_id) = persisted {
                        let session = ScanSession {
                            case_id,
                            evidence_record_id,
                            persistent_id,
                            source_id,
                            source_sha256: source_sha256.clone(),
                            source: image,
                            result,
                        };
                        if let Ok(mut cache) = state.scan.lock() {
                            *cache = Some(Arc::new(session));
                            job.state = "completed".into();
                        } else {
                            job.state = "failed".into();
                            job.error = Some("Could not retain the scan results.".into());
                        }
                    } else {
                        job.state = "failed".into();
                        job.error = Some(format!(
                            "Scan results could not be committed to the case record: {}",
                            persisted.unwrap_err()
                        ));
                    }
                }
                Err(e) => {
                    job.state = if state.cancel.load(Ordering::SeqCst) {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    job.error = Some(e);
                }
            }
            if job.state != "completed" {
                if let Ok(db) = state.db.lock() {
                    if let Err(e) = audit(
                        &db,
                        "ntfs_scan_finished",
                        &serde_json::json!({"case_id":case_id,"source_id":source_id,"job":&*job})
                            .to_string(),
                    ) {
                        job.state = "failed".into();
                        job.error = Some(e.to_string());
                    }
                }
            }
        };
    });
    Ok(())
}
#[tauri::command]
pub fn scan_summary(state: State<AppState>) -> Result<Option<ScanSummary>> {
    let scan = state.scan.lock().map_err(err)?;
    Ok(scan.as_ref().map(|scan| ScanSummary {
        scan_session_id: scan.persistent_id,
        source_id: scan.source_id,
        boot: scan.result.boot.clone(),
        records: scan.result.records,
        skipped: scan.result.invalid_records,
        found: scan.result.candidates.len(),
        limited: scan.result.limited,
        cancelled: scan.result.cancelled,
        source_sha256: scan.source_sha256.clone(),
    }))
}
#[tauri::command]
pub fn scan_results(
    source_id: u64,
    offset: usize,
    limit: usize,
    query: String,
    only_exportable: bool,
    state: State<AppState>,
) -> Result<Page> {
    if limit == 0 || limit > 200 || query.len() > 200 {
        return Err("Invalid results page or filter.".into());
    }
    let cache = state.scan.lock().map_err(err)?;
    let scan = cache.as_ref().ok_or("No scan results are available.")?;
    if scan.source_id != source_id {
        return Err("These results belong to another source. Refresh the workspace.".into());
    }
    let query = query.to_lowercase();
    let filtered = scan
        .result
        .candidates
        .iter()
        .filter(|c| (!only_exportable || c.exportable) && c.name.to_lowercase().contains(&query))
        .collect::<Vec<_>>();
    Ok(Page {
        total: filtered.len(),
        rows: filtered
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect(),
    })
}
#[tauri::command]
pub async fn export_selected(
    source_id: u64,
    ids: Vec<u64>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool> {
    if ids.is_empty() || ids.len() > 1000 {
        return Err("Select between 1 and 1,000 candidates.".into());
    }
    let scan = {
        let cache = state.scan.lock().map_err(err)?;
        cache.as_ref().ok_or("Run a metadata scan first.")?.clone()
    };
    if scan.source_id != source_id {
        return Err("The scan belongs to another image.".into());
    }
    {
        let current = state.source.lock().map_err(err)?;
        let evidence = current.as_ref().ok_or("Open the source image first.")?;
        if evidence.integrity_compromised
            || evidence.info.id != source_id
            || evidence.info.sha256.as_deref() != Some(scan.source_sha256.as_str())
        {
            return Err("The source no longer matches the verified scan digest. Reopen and rehash the image before exporting.".into());
        }
    }
    let unique = ids.into_iter().collect::<std::collections::BTreeSet<_>>();
    let mut selected = Vec::new();
    let mut required = 0u64;
    for id in unique {
        let candidate = scan
            .result
            .candidates
            .iter()
            .find(|c| c.id == id)
            .ok_or("A selected candidate is not in this scan.")?;
        if !candidate.exportable {
            return Err(format!(
                "{} is blocked by its stream/allocation checks.",
                candidate.name
            ));
        }
        required = required
            .checked_add(candidate.size)
            .ok_or("Export size overflow")?;
        selected.push(candidate.clone());
    }
    if state.job.lock().map_err(err)?.state == "running" {
        return Err("Wait for the active operation before exporting.".into());
    }
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Recover to a different physical disk")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(false);
    };
    let image = scan.source.clone();
    let source_path = image.path.to_string_lossy().into_owned();
    let destination_result = tauri::async_runtime::spawn_blocking(move || {
        crate::destination::check_destination(&image.path, &folder, required)
    })
    .await
    .map_err(err)?;
    let destination = match destination_result {
        Ok(path) => path,
        Err(reason) => {
            audit(
                &*state.db.lock().map_err(err)?,
                "recovery_export_rejected",
                &serde_json::json!({"case_id":scan.case_id,"source_id":source_id,"reason":reason})
                    .to_string(),
            )
            .map_err(err)?;
            return Err(reason);
        }
    };
    let source = state.source.lock().map_err(err)?;
    if source.as_ref().is_none_or(|s| {
        s.info.id != source_id
            || s.integrity_compromised
            || s.info.sha256.as_deref() != Some(scan.source_sha256.as_str())
    }) {
        return Err(
            "The source changed while selecting a destination. Rescan the current image.".into(),
        );
    }
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Another operation started while selecting a destination.".into());
    }
    scan.source.verify_unchanged().map_err(err)?;
    audit(
        &*state.db.lock().map_err(err)?,
        "recovery_export_started",
        &export_audit_payload(
            AuditSource {
                case_id: scan.case_id,
                evidence_record_id: scan.evidence_record_id,
                scan_session_id: scan.persistent_id,
                source_id,
                source_path: &source_path,
                source_sha256: &scan.source_sha256,
            },
            &selected,
            Some(&destination),
            None,
        ),
    )
    .map_err(err)?;
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "recovery_export".into(),
        message: Some(
            "Verifying the source, extracting files, then rechecking source and output hashes"
                .into(),
        ),
        ..Job::default()
    };
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = crate::guarded(|| {
            recovery::export_to(
                scan.source.as_ref(),
                &scan.result,
                &selected,
                &destination,
                recovery::SourceIdentity {
                    case_id: scan.case_id,
                    evidence_record_id: scan.evidence_record_id,
                    scan_session_id: scan.persistent_id,
                    id: source_id,
                    path: &source_path,
                    sha256: &scan.source_sha256,
                },
                &state.cancel,
                |processed, total| {
                    if let Ok(mut job) = state.job.lock() {
                        job.processed = processed;
                        job.total = total;
                    }
                },
            )
        })
        .and_then(|summary| {
            scan.source.verify_unchanged().map_err(err)?;
            Ok(summary)
        });
        if let Err(error) = &result {
            if error.contains("Source SHA-256 changed during export")
                || error.contains("Evidence image changed during examination")
            {
                if let Ok(mut source) = state.source.lock() {
                    if let Some(source) =
                        source.as_mut().filter(|source| source.info.id == source_id)
                    {
                        source.info.sha256 = None;
                        source.integrity_compromised = true;
                    }
                }
            }
        }
        if let Ok(mut job) = state.job.lock() {
            match result {
                Ok(summary) => {
                    job.state = if summary.cancelled {
                        "cancelled"
                    } else if summary.failed > 0 {
                        "failed"
                    } else {
                        "completed"
                    }
                    .into();
                    job.output_directory = Some(summary.directory);
                    job.message=Some(format!("{} files exported and destination-verified; {} failed. File content integrity has not been established.",summary.exported,summary.failed));
                    if summary.failed > 0 {
                        job.error=Some("Some candidates could not be extracted; see inventory.jsonl in the recovery folder.".into());
                    }
                }
                Err(e) => {
                    job.state = if state.cancel.load(Ordering::SeqCst) {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    job.error = Some(e);
                }
            };
            if let Ok(db) = state.db.lock() {
                if let Err(e) = audit(
                    &db,
                    "recovery_export_finished",
                    &export_audit_payload(
                        AuditSource {
                            case_id: scan.case_id,
                            evidence_record_id: scan.evidence_record_id,
                            scan_session_id: scan.persistent_id,
                            source_id,
                            source_path: &source_path,
                            source_sha256: &scan.source_sha256,
                        },
                        &selected,
                        None,
                        Some(&job),
                    ),
                ) {
                    job.state = "failed".into();
                    job.error = Some(e.to_string());
                }
            }
        };
    });
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_candidate() -> ntfs::Candidate {
        ntfs::Candidate {
            id: 41,
            name: "recovered.bin".into(),
            parent_record: 5,
            parent_sequence: 1,
            parent_ambiguous: false,
            parent_path: None,
            filename_references: Vec::new(),
            size: 12,
            deleted: true,
            storage: "resident".into(),
            allocation: "unallocated".into(),
            exportable: true,
            notes: vec![],
            fingerprint: "a".repeat(64),
            created_filetime: None,
            modified_filetime: None,
        }
    }

    fn scan_boot() -> ntfs::Boot {
        ntfs::Boot {
            offset: 0,
            sector_size: 512,
            cluster_size: 4096,
            record_size: 1024,
            volume_size: 2 * 1024 * 1024,
            mft_offset: 4096,
            serial: "fixture".into(),
        }
    }

    #[test]
    fn completed_scan_snapshot_persists_candidates_and_audit_together() {
        let mut db = crate::database(std::path::PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'case','examiner')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO evidence_sources(id,case_id,original_path,name,size_bytes,filesystem,opened_at,status) VALUES (2,1,'evidence.img','evidence.img',4096,'NTFS','1','hashed')", []).unwrap();
        let boot = scan_boot();
        let candidates = [scan_candidate()];
        let scan_id = persist_scan_snapshot(
            &mut db,
            &ScanSnapshot {
                evidence_id: 2,
                case_id: 1,
                source_id: 9,
                volume_offset: 0,
                source_sha256: &"b".repeat(64),
                boot: &boot,
                records: 100,
                skipped: 3,
                limited: false,
                candidates: &candidates,
            },
        )
        .unwrap();
        let (found, candidates): (i64, String) = db
            .query_row(
                "SELECT found,candidates_json FROM scan_sessions WHERE id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(found, 1);
        assert!(candidates.contains("recovered.bin"));
        assert!(crate::verify_audit_chain(&db).unwrap().valid);
        let sessions = list_case_scan_sessions_from(&db, 1).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, scan_id);
        let archived = archived_scan_results_from(&db, 1, scan_id, 0, 10).unwrap();
        assert_eq!(archived.total, 1);
        assert_eq!(archived.rows[0].name, "recovered.bin");
        assert!(archived_scan_results_from(&db, 2, scan_id, 0, 10).is_err());
        db.execute(
            "UPDATE scan_sessions SET candidates_json='[]' WHERE id=?1",
            [scan_id],
        )
        .unwrap();
        assert!(list_case_scan_sessions_from(&db, 1).is_err());
        assert!(archived_scan_results_from(&db, 1, scan_id, 0, 10).is_err());
    }

    #[test]
    fn scan_snapshot_and_audit_roll_back_together_on_chain_tampering() {
        let mut db = crate::database(std::path::PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'case','examiner')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO evidence_sources(id,case_id,original_path,name,size_bytes,filesystem,opened_at,status) VALUES (2,1,'evidence.img','evidence.img',4096,'NTFS','1','hashed')", []).unwrap();
        audit(&db, "first", "{}").unwrap();
        db.execute("UPDATE audit SET payload='tampered' WHERE id=1", [])
            .unwrap();
        let boot = scan_boot();
        let candidates = [scan_candidate()];
        assert!(persist_scan_snapshot(
            &mut db,
            &ScanSnapshot {
                evidence_id: 2,
                case_id: 1,
                source_id: 9,
                volume_offset: 0,
                source_sha256: &"b".repeat(64),
                boot: &boot,
                records: 100,
                skipped: 3,
                limited: false,
                candidates: &candidates,
            },
        )
        .is_err());
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM scan_sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn recovery_audit_payload_binds_source_and_record_fingerprints() {
        let candidate = ntfs::Candidate {
            id: 41,
            name: "evidence.bin".into(),
            parent_record: 5,
            parent_sequence: 1,
            parent_ambiguous: false,
            parent_path: None,
            filename_references: vec![ntfs::FilenameReference {
                name: "evidence.bin".into(),
                attribute_record: 41,
                attribute_record_sequence: 1,
                parent_record: 5,
                parent_sequence: 1,
                namespace: 1,
                attribute_id: 0,
            }],
            size: 1234,
            deleted: true,
            storage: "nonresident".into(),
            allocation: "unallocated".into(),
            exportable: true,
            notes: Vec::new(),
            fingerprint: "a".repeat(64),
            created_filetime: None,
            modified_filetime: None,
        };
        let destination = std::path::Path::new(r"Z:\Case-42");
        let payload = export_audit_payload(
            AuditSource {
                case_id: 3,
                evidence_record_id: 4,
                scan_session_id: 5,
                source_id: 7,
                source_path: r"C:\evidence\disk.img",
                source_sha256: &"b".repeat(64),
            },
            std::slice::from_ref(&candidate),
            Some(destination),
            None,
        );
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["source_id"], 7);
        assert_eq!(payload["case_id"], 3);
        assert_eq!(payload["evidence_record_id"], 4);
        assert_eq!(payload["scan_session_id"], 5);
        assert_eq!(payload["source_path"], r"C:\evidence\disk.img");
        assert_eq!(payload["source_sha256"], "b".repeat(64));
        assert_eq!(payload["destination"], r"Z:\Case-42");
        assert_eq!(payload["records"][0]["record"], 41);
        assert_eq!(payload["records"][0]["record_sha256"], "a".repeat(64));
        assert_eq!(payload["records"][0]["size"], 1234);
        assert_eq!(
            payload["records"][0]["filename_references"][0]["name"],
            "evidence.bin"
        );
        assert!(payload["outcome"].is_null());

        let outcome = Job {
            state: "completed".into(),
            kind: "recovery_export".into(),
            processed: 1234,
            total: 1234,
            discovered: 1,
            sha256: None,
            error: None,
            message: Some("verified".into()),
            output_directory: Some(r"Z:\Case-42\export".into()),
        };
        let finished = export_audit_payload(
            AuditSource {
                case_id: 3,
                evidence_record_id: 4,
                scan_session_id: 5,
                source_id: 7,
                source_path: r"C:\evidence\disk.img",
                source_sha256: &"b".repeat(64),
            },
            std::slice::from_ref(&candidate),
            None,
            Some(&outcome),
        );
        let finished: serde_json::Value = serde_json::from_str(&finished).unwrap();
        assert_eq!(finished["outcome"]["state"], "completed");
        assert_eq!(
            finished["outcome"]["output_directory"],
            r"Z:\Case-42\export"
        );
    }
}
