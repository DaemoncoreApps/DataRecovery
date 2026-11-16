use crate::{audit, err, storage::BlockSource, AppState, Job, Result};
use daemoncore_ntfs_core::fat32::{self, TreeEntry};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};
use tauri::{Manager, State};

const MAX_FAT32_SNAPSHOT_BYTES: usize = 48 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Fat32ScanCache {
    case_id: i64,
    persistent_id: i64,
    source_id: u64,
    source_sha256: String,
    volume_offset: u64,
    entries: Vec<TreeEntry>,
}

#[derive(Serialize)]
pub struct Fat32ScanSummary {
    pub scan_session_id: i64,
    pub source_id: u64,
    pub volume_offset: String,
    pub source_sha256: String,
    pub entries: usize,
    pub deleted_entries: usize,
}

#[derive(Serialize)]
pub struct Fat32Page {
    pub total: usize,
    pub rows: Vec<TreeEntry>,
}

#[derive(Debug, Serialize)]
pub struct Fat32CaseScanSession {
    pub id: i64,
    pub evidence_id: i64,
    pub case_id: i64,
    pub volume_offset: String,
    pub source_sha256: String,
    pub completed_at: String,
    pub records: u64,
    pub found: usize,
    pub deleted: usize,
}

pub(super) struct ScanSnapshot<'a> {
    pub(super) evidence_id: i64,
    pub(super) case_id: i64,
    pub(super) source_id: u64,
    pub(super) volume_offset: u64,
    pub(super) source_sha256: &'a str,
    pub(super) boot: &'a serde_json::Value,
    pub(super) entries: &'a [TreeEntry],
}

fn snapshot_digest(boot_json: &str, entries_json: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"DaemonCore FAT32 scan snapshot v1\0");
    digest.update((boot_json.len() as u64).to_le_bytes());
    digest.update(boot_json.as_bytes());
    digest.update((entries_json.len() as u64).to_le_bytes());
    digest.update(entries_json.as_bytes());
    format!("{:x}", digest.finalize())
}

pub(super) fn persist_scan_snapshot(
    db: &mut rusqlite::Connection,
    snapshot: &ScanSnapshot<'_>,
) -> Result<i64> {
    let entries_json = serde_json::to_string(snapshot.entries).map_err(err)?;
    let boot_json = serde_json::to_string(snapshot.boot).map_err(err)?;
    if entries_json.len() > MAX_FAT32_SNAPSHOT_BYTES {
        return Err(format!(
            "FAT32 directory snapshot exceeds the {} MiB case database limit.",
            MAX_FAT32_SNAPSHOT_BYTES / (1024 * 1024)
        ));
    }
    let digest = snapshot_digest(&boot_json, &entries_json);
    let completed_at = crate::audit_timestamp(std::time::SystemTime::now())?;
    let deleted = snapshot
        .entries
        .iter()
        .filter(|entry| entry.entry.deleted)
        .count();
    let tx = db.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO fat32_scan_sessions(evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,records,found,deleted,entries_json,snapshot_sha256) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        rusqlite::params![
            snapshot.evidence_id,
            snapshot.case_id,
            snapshot.volume_offset.to_string(),
            snapshot.source_sha256,
            completed_at,
            boot_json,
            snapshot.entries.len() as i64,
            snapshot.entries.len() as i64,
            deleted as i64,
            entries_json,
            digest,
        ],
    ).map_err(err)?;
    let scan_session_id = tx.last_insert_rowid();
    audit(
        &tx,
        "fat32_scan_persisted",
        &serde_json::json!({
            "case_id": snapshot.case_id,
            "evidence_id": snapshot.evidence_id,
            "scan_session_id": scan_session_id,
            "source_id": snapshot.source_id,
            "volume_offset": snapshot.volume_offset,
            "source_sha256": snapshot.source_sha256,
            "records": snapshot.entries.len(),
            "found": snapshot.entries.len(),
            "deleted": deleted,
            "snapshot_sha256": digest,
        })
        .to_string(),
    )?;
    tx.commit().map_err(err)?;
    Ok(scan_session_id)
}

#[tauri::command]
pub fn start_fat32_scan(offset: u64, app: tauri::AppHandle, state: State<AppState>) -> Result<()> {
    let source_guard = state.source.lock().map_err(err)?;
    let source = source_guard.as_ref().ok_or("Open an image first.")?;
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
    let image = source.image.clone();
    let source_id = source.info.id;
    let case_id = source.info.case_id;
    let evidence_record_id = source.info.evidence_record_id;
    if offset >= image.len() {
        return Err("Volume offset is outside the image.".into());
    }
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("An operation is already running.".into());
    }
    {
        let db = state.db.lock().map_err(err)?;
        if crate::require_audited_active_case(&db)? != case_id {
            return Err("Select the evidence source's case before scanning.".into());
        }
        audit(
            &db,
            "fat32_scan_started",
            &serde_json::json!({
                "case_id": case_id,
                "evidence_id": evidence_record_id,
                "source_id": source_id,
                "source_sha256": &source_sha256,
                "volume_offset": offset,
            })
            .to_string(),
        )
        .map_err(err)?;
    }
    *state.scan.lock().map_err(err)? = None;
    *state.fat32_scan.lock().map_err(err)? = None;
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "fat32_scan".into(),
        message: Some(
            "Validating FAT32 volume and enumerating directory records; cancellation becomes available during the source recheck".into(),
        ),
        ..Job::default()
    };

    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let scan = crate::guarded(|| {
            let volume = fat32::Volume::open(image.as_ref(), offset, image.len() - offset)?;
            let entries = volume.read_tree_including_deleted(image.as_ref())?;
            if state.cancel.load(Ordering::SeqCst) {
                return Err("FAT32 scan was cancelled; no results were recorded.".into());
            }
            image.verify_unchanged().map_err(err)?;

            let mut primary_boot = [0; 512];
            image
                .read_exact_at(offset, &mut primary_boot)
                .map_err(err)?;
            let bytes_per_sector =
                u64::from(u16::from_le_bytes([primary_boot[11], primary_boot[12]]));
            let backup_sector = u64::from(u16::from_le_bytes([primary_boot[50], primary_boot[51]]));
            let mut backup_boot = None;
            if backup_sector != 0 {
                let backup_offset = offset
                    .checked_add(
                        backup_sector
                            .checked_mul(bytes_per_sector)
                            .ok_or("FAT32 backup offset overflow")?,
                    )
                    .ok_or("FAT32 backup offset overflow")?;
                let mut bytes = [0; 512];
                image
                    .read_exact_at(backup_offset, &mut bytes)
                    .map_err(err)?;
                backup_boot = Some(bytes);
            }
            let boot = serde_json::json!({
                "primary_sector_hex": hex(&primary_boot),
                "backup_sector_hex": backup_boot.as_ref().map(|bytes| hex(bytes)),
                "volume_offset": offset,
                "cluster_count": volume.cluster_count(),
                "root_cluster": volume.root_cluster(),
            });

            if let Ok(mut job) = state.job.lock() {
                job.message = Some("Rechecking the complete source SHA-256".into());
                job.total = image.len();
                job.processed = 0;
                job.discovered = entries.len();
            }
            let after = crate::hash_source(image.as_ref(), &state.cancel, |processed| {
                if let Ok(mut job) = state.job.lock() {
                    job.processed = processed;
                }
            })?
            .ok_or("Source verification was cancelled; FAT32 results were discarded.")?;
            if after != source_sha256 {
                if let Ok(mut source) = state.source.lock() {
                    if let Some(source) =
                        source.as_mut().filter(|source| source.info.id == source_id)
                    {
                        source.info.sha256 = None;
                        source.integrity_compromised = true;
                    }
                }
                return Err("Source SHA-256 changed during FAT32 scan. Results were discarded; quarantine this working copy and investigate the change.".into());
            }
            let current_source = state.source.lock().map_err(err)?;
            let still_active = current_source.as_ref().is_some_and(|current| {
                current.info.id == source_id
                    && current.info.case_id == case_id
                    && current.info.sha256.as_deref() == Some(source_sha256.as_str())
                    && !current.integrity_compromised
            });
            if !still_active {
                return Err("The active evidence source changed during FAT32 scanning. Results were discarded.".into());
            }
            Ok((boot, entries))
        });

        let mut job = match state.job.lock() {
            Ok(job) => job,
            Err(_) => return,
        };
        match scan {
            Ok((boot, entries)) => {
                let persisted = state.db.lock().map_err(err).and_then(|mut db| {
                    if crate::require_audited_active_case(&db)? != case_id {
                        return Err("The active case changed during FAT32 scanning; no scan snapshot was recorded.".into());
                    }
                    persist_scan_snapshot(
                        &mut db,
                        &ScanSnapshot {
                            evidence_id: evidence_record_id,
                            case_id,
                            source_id,
                            volume_offset: offset,
                            source_sha256: &source_sha256,
                            boot: &boot,
                            entries: &entries,
                        },
                    )
                });
                match persisted {
                    Ok(persistent_id) => {
                        let entry_count = entries.len();
                        let deleted_entries =
                            entries.iter().filter(|entry| entry.entry.deleted).count();
                        match state.fat32_scan.lock() {
                            Ok(mut cache) => {
                                *cache = Some(Arc::new(Fat32ScanCache {
                                    case_id,
                                    persistent_id,
                                    source_id,
                                    source_sha256,
                                    volume_offset: offset,
                                    entries,
                                }));
                                job.state = "completed".into();
                                job.discovered = deleted_entries;
                                job.message = Some(format!(
                                    "{entry_count} directory entries recorded; {deleted_entries} are deleted records."
                                ));
                            }
                            Err(error) => {
                                job.state = "failed".into();
                                job.error = Some(format!(
                                    "Could not retain the FAT32 scan results: {error}"
                                ));
                            }
                        }
                    }
                    Err(error) => {
                        job.state = "failed".into();
                        job.error = Some(format!(
                            "FAT32 scan could not be committed to the case record: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                job.state = if state.cancel.load(Ordering::SeqCst) {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                job.error = Some(error);
            }
        }
        if job.state != "completed" {
            let audit_result = state.db.lock().map_err(err).and_then(|db| {
                audit(
                    &db,
                    "fat32_scan_finished",
                    &serde_json::json!({
                        "case_id": case_id,
                        "source_id": source_id,
                        "job": &*job,
                    })
                    .to_string(),
                )
            });
            crate::mark_job_audit_failure(&mut job, audit_result);
        };
    });
    Ok(())
}

#[tauri::command]
pub async fn export_fat32_deleted(
    source_id: u64,
    scan_session_id: i64,
    entry_offsets: Vec<u64>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool> {
    if entry_offsets.is_empty() || entry_offsets.len() > 1000 {
        return Err("Select between 1 and 1,000 deleted FAT32 files.".into());
    }
    let scan = state
        .fat32_scan
        .lock()
        .map_err(err)?
        .as_ref()
        .ok_or("Run a FAT32 directory scan first.")?
        .clone();
    if scan.source_id != source_id || scan.persistent_id != scan_session_id {
        return Err("The FAT32 selection does not belong to the current scan.".into());
    }
    let (image, evidence_record_id) = {
        let source = state.source.lock().map_err(err)?;
        let evidence = source.as_ref().ok_or("Open the source image first.")?;
        if evidence.integrity_compromised
            || evidence.info.id != source_id
            || evidence.info.case_id != scan.case_id
            || evidence.info.sha256.as_deref() != Some(scan.source_sha256.as_str())
        {
            return Err("The source no longer matches the verified FAT32 scan. Reopen and rehash it before exporting.".into());
        }
        (evidence.image.clone(), evidence.info.evidence_record_id)
    };
    let mut unique_offsets = std::collections::BTreeSet::new();
    let requested_count = entry_offsets.len();
    let mut selected = Vec::with_capacity(requested_count);
    let mut required = 0_u64;
    for offset in entry_offsets {
        if !unique_offsets.insert(offset) {
            return Err("A FAT32 directory record was selected more than once.".into());
        }
    }
    for entry in &scan.entries {
        if !unique_offsets.contains(&entry.entry.source_offset) {
            continue;
        }
        if !entry.entry.deleted
            || entry.entry.is_directory()
            || entry.entry.is_volume_label()
            || entry.entry.size == 0
        {
            return Err(format!(
                "{} is not a nonempty deleted FAT32 file entry.",
                entry.entry.display_name()
            ));
        }
        required = required
            .checked_add(u64::from(entry.entry.size))
            .ok_or("FAT32 recovery size overflow")?;
        selected.push(entry.clone());
    }
    if selected.len() != requested_count {
        return Err("A selected FAT32 record is not part of this scan.".into());
    }
    if state.job.lock().map_err(err)?.state == "running" {
        return Err("Wait for the active operation before exporting.".into());
    }
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Recover FAT32 files to a different physical disk")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(false);
    };
    let source_path = image.path.to_string_lossy().into_owned();
    let destination_result = tauri::async_runtime::spawn_blocking({
        let image_path = image.path.clone();
        move || crate::destination::check_destination(&image_path, &folder, required)
    })
    .await
    .map_err(err)?;
    let destination = match destination_result {
        Ok(path) => path,
        Err(reason) => {
            audit(
                &*state.db.lock().map_err(err)?,
                "fat32_recovery_export_rejected",
                &serde_json::json!({
                    "case_id": scan.case_id,
                    "evidence_record_id": evidence_record_id,
                    "scan_session_id": scan.persistent_id,
                    "source_id": source_id,
                    "source_sha256": scan.source_sha256,
                    "reason": reason,
                    "selected_offsets": unique_offsets,
                })
                .to_string(),
            )
            .map_err(err)?;
            return Err(reason);
        }
    };
    let current = state.source.lock().map_err(err)?;
    if current.as_ref().is_none_or(|current| {
        current.info.id != source_id
            || current.integrity_compromised
            || current.info.sha256.as_deref() != Some(scan.source_sha256.as_str())
    }) {
        return Err("The evidence source changed while selecting the recovery destination.".into());
    }
    image.verify_unchanged().map_err(err)?;
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Another operation started while selecting the destination.".into());
    }
    let selected_audit = selected
        .iter()
        .map(|tree_entry| {
            serde_json::json!({
                "source_offset": tree_entry.entry.source_offset,
                "raw_record_sha256": format!("{:x}", Sha256::digest(tree_entry.entry.raw_record)),
                "name": tree_entry.entry.display_name(),
                "size": tree_entry.entry.size,
                "first_cluster": tree_entry.entry.first_cluster,
                "recovery_assumption": "contiguous_assumed_free_clusters",
            })
        })
        .collect::<Vec<_>>();
    {
        let db = state.db.lock().map_err(err)?;
        if crate::require_audited_active_case(&db)? != scan.case_id {
            return Err(
                "Select the audited case recorded by this FAT32 scan before exporting.".into(),
            );
        }
        audit(
            &db,
            "fat32_recovery_export_started",
            &serde_json::json!({
                "case_id": scan.case_id,
                "evidence_record_id": evidence_record_id,
                "scan_session_id": scan.persistent_id,
                "source_id": source_id,
                "source_path": source_path,
                "source_sha256": scan.source_sha256,
                "volume_offset": scan.volume_offset,
                "destination": destination,
                "selected": selected_audit,
            })
            .to_string(),
        )
        .map_err(err)?;
    }
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "fat32_recovery_export".into(),
        message: Some("Checking that candidate clusters are free, extracting with a contiguous-cluster assumption, then rechecking source and output hashes".into()),
        ..Job::default()
    };
    drop(job);
    drop(current);

    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = crate::guarded(|| {
            crate::recovery::export_fat32_to(
                image.as_ref(),
                scan.volume_offset,
                &selected,
                &destination,
                crate::recovery::SourceIdentity {
                    case_id: scan.case_id,
                    evidence_record_id,
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
            image.verify_unchanged().map_err(err)?;
            Ok(summary)
        });
        if let Err(error) = &result {
            if error.contains("Source SHA-256 changed")
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
                    job.discovered = summary.exported;
                    job.output_directory = Some(summary.directory.clone());
                    job.message = Some(format!(
                        "{} FAT32 files exported and destination-hash verified; {} failed. Cluster mapping is contiguous-assumed; original content integrity was not established.",
                        summary.exported, summary.failed
                    ));
                    if summary.failed > 0 {
                        job.error = Some("Some FAT32 candidates were not exportable; see inventory.jsonl for per-file reasons.".into());
                    }
                }
                Err(error) => {
                    job.state = if state.cancel.load(Ordering::SeqCst) {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    job.error = Some(error);
                }
            }
            let audit_result = state.db.lock().map_err(err).and_then(|db| {
                audit(
                    &db,
                    "fat32_recovery_export_finished",
                    &serde_json::json!({
                        "case_id": scan.case_id,
                        "evidence_record_id": evidence_record_id,
                        "scan_session_id": scan.persistent_id,
                        "source_id": source_id,
                        "source_sha256": scan.source_sha256,
                        "selected": selected_audit,
                        "job": &*job,
                    })
                    .to_string(),
                )
            });
            crate::mark_job_audit_failure(&mut job, audit_result);
        };
    });
    Ok(true)
}

#[tauri::command]
pub fn fat32_scan_summary(state: State<AppState>) -> Result<Option<Fat32ScanSummary>> {
    let cache = state.fat32_scan.lock().map_err(err)?;
    Ok(cache.as_ref().map(|cache| Fat32ScanSummary {
        scan_session_id: cache.persistent_id,
        source_id: cache.source_id,
        volume_offset: cache.volume_offset.to_string(),
        source_sha256: cache.source_sha256.clone(),
        entries: cache.entries.len(),
        deleted_entries: cache
            .entries
            .iter()
            .filter(|entry| entry.entry.deleted)
            .count(),
    }))
}

#[tauri::command]
pub fn fat32_scan_results(
    source_id: u64,
    offset: usize,
    limit: usize,
    query: String,
    deleted_only: bool,
    state: State<AppState>,
) -> Result<Fat32Page> {
    if limit == 0 || limit > 200 || query.len() > 200 {
        return Err("Invalid FAT32 results page or filter.".into());
    }
    let source = state.source.lock().map_err(err)?;
    let active_source = source.as_ref().ok_or("Open an image first.")?;
    if active_source.info.id != source_id
        || active_source.integrity_compromised
        || active_source.info.sha256.is_none()
    {
        return Err("The active evidence source changed or is no longer verified.".into());
    }
    let cache = state.fat32_scan.lock().map_err(err)?;
    let scan = cache
        .as_ref()
        .ok_or("No FAT32 scan results are available.")?;
    if scan.source_id != source_id {
        return Err("These FAT32 results belong to another source. Refresh the workspace.".into());
    }
    if scan.case_id != active_source.info.case_id {
        return Err("Select the case recorded by this FAT32 scan before reviewing it.".into());
    }
    if scan.source_sha256 != active_source.info.sha256.as_deref().unwrap_or_default() {
        return Err("The active evidence source no longer matches this FAT32 scan.".into());
    }
    let db = state.db.lock().map_err(err)?;
    if crate::require_audited_active_case(&db)? != scan.case_id {
        return Err(
            "Select the audited case recorded by this FAT32 scan before reviewing it.".into(),
        );
    }
    let query = query.to_lowercase();
    let filtered = scan
        .entries
        .iter()
        .filter(|entry| !deleted_only || entry.entry.deleted)
        .filter(|entry| {
            entry.entry.display_name().to_lowercase().contains(&query)
                || entry
                    .entry
                    .deleted_long_name_lead
                    .as_ref()
                    .is_some_and(|lead| lead.to_lowercase().contains(&query))
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(Fat32Page {
        total: filtered.len(),
        rows: filtered.into_iter().skip(offset).take(limit).collect(),
    })
}

#[tauri::command]
pub fn list_case_fat32_scan_sessions(
    case_id: i64,
    state: State<AppState>,
) -> Result<Vec<Fat32CaseScanSession>> {
    let db = state.db.lock().map_err(err)?;
    list_case_fat32_scan_sessions_from(&db, case_id)
}

pub(super) fn list_case_fat32_scan_sessions_from(
    db: &rusqlite::Connection,
    case_id: i64,
) -> Result<Vec<Fat32CaseScanSession>> {
    let chain = crate::verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='fat32_scan_persisted' AND CASE WHEN json_valid(payload) THEN json_extract(payload, '$.case_id') ELSE NULL END=?1")
        .map_err(err)?;
    let audit_rows = audit_statement
        .query_map([case_id], |row| row.get::<_, String>(0))
        .map_err(err)?;
    let mut audit_snapshots = std::collections::HashMap::new();
    for row in audit_rows {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        let id = payload
            .get("scan_session_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or("A FAT32 scan audit record has no valid session ID.")?;
        let case = payload
            .get("case_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or("A FAT32 scan audit record has no valid case ID.")?;
        let hash = payload
            .get("snapshot_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or("A FAT32 scan audit record has no snapshot hash.")?;
        if audit_snapshots
            .insert(id, (case, hash.to_owned(), payload))
            .is_some()
        {
            return Err(format!("Duplicate FAT32 scan audit reference: {id}."));
        }
    }
    let mut statement = db.prepare(
        "SELECT id,evidence_id,case_id,volume_offset,source_sha256,completed_at,records,found,deleted,boot_json,entries_json,snapshot_sha256 FROM fat32_scan_sessions WHERE case_id=?1 ORDER BY id DESC",
    ).map_err(err)?;
    let rows = statement
        .query_map([case_id], |row| {
            Ok((
                Fat32CaseScanSession {
                    id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    case_id: row.get(2)?,
                    volume_offset: row.get(3)?,
                    source_sha256: row.get(4)?,
                    completed_at: row.get(5)?,
                    records: row.get(6)?,
                    found: row.get::<_, i64>(7)? as usize,
                    deleted: row.get::<_, i64>(8)? as usize,
                },
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
            ))
        })
        .map_err(err)?;
    let mut sessions = Vec::new();
    let mut session_ids = std::collections::HashSet::new();
    for row in rows {
        let (session, boot_json, entries_json, stored_hash) = row.map_err(err)?;
        session_ids.insert(session.id);
        let audit_record = audit_snapshots
            .get(&session.id)
            .ok_or("A stored FAT32 scan has no matching audit record.")?;
        let entries: Vec<TreeEntry> = serde_json::from_str(&entries_json).map_err(|error| {
            format!("Stored FAT32 scan entries do not match the supported schema: {error}")
        })?;
        let boot: serde_json::Value = serde_json::from_str(&boot_json).map_err(err)?;
        let calculated_hash = snapshot_digest(&boot_json, &entries_json);
        let deleted = entries.iter().filter(|entry| entry.entry.deleted).count();
        let volume_offset = session.volume_offset.parse::<u64>().map_err(err)?;
        if audit_record.0 != case_id
            || audit_record.1 != stored_hash
            || stored_hash != calculated_hash
            || audit_record.2["evidence_id"].as_i64() != Some(session.evidence_id)
            || audit_record.2["source_sha256"].as_str() != Some(session.source_sha256.as_str())
            || audit_record.2["records"].as_u64() != Some(session.records)
            || audit_record.2["found"].as_u64() != Some(session.found as u64)
            || audit_record.2["deleted"].as_u64() != Some(session.deleted as u64)
            || audit_record.2["volume_offset"].as_u64() != Some(volume_offset)
            || entries.len() != session.found
            || session.records != entries.len() as u64
            || session.found != entries.len()
            || deleted != session.deleted
            || boot["volume_offset"].as_u64() != Some(volume_offset)
            || !boot.is_object()
        {
            return Err(format!(
                "Stored FAT32 scan {} does not match its audited contents.",
                session.id
            ));
        }
        sessions.push(session);
    }
    if audit_snapshots
        .iter()
        .any(|(id, (record_case_id, _, _))| *record_case_id == case_id && !session_ids.contains(id))
    {
        return Err("An audited FAT32 scan has no matching stored snapshot.".into());
    }
    Ok(sessions)
}

#[tauri::command]
pub fn archived_fat32_scan_results(
    case_id: i64,
    scan_session_id: i64,
    offset: usize,
    limit: usize,
    state: State<AppState>,
) -> Result<Fat32Page> {
    if limit == 0 || limit > 200 {
        return Err("Invalid archived FAT32-results page size.".into());
    }
    let db = state.db.lock().map_err(err)?;
    let session = list_case_fat32_scan_sessions_from(&db, case_id)?
        .into_iter()
        .find(|session| session.id == scan_session_id)
        .ok_or("The archived FAT32 scan does not belong to the selected case.")?;
    let entries_json: String = db
        .query_row(
            "SELECT entries_json FROM fat32_scan_sessions WHERE id=?1 AND case_id=?2",
            rusqlite::params![scan_session_id, case_id],
            |row| row.get(0),
        )
        .map_err(err)?;
    let entries: Vec<TreeEntry> = serde_json::from_str(&entries_json).map_err(err)?;
    if entries.len() != session.found {
        return Err("Archived FAT32 entry count does not match the audited record.".into());
    }
    Ok(Fat32Page {
        total: entries.len(),
        rows: entries.into_iter().skip(offset).take(limit).collect(),
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemoncore_ntfs_core::fat32::DirectoryEntry;
    use std::path::PathBuf;

    fn entry(deleted: bool) -> TreeEntry {
        let mut raw_record = [0; 32];
        raw_record[0] = if deleted { 0xe5 } else { b'F' };
        raw_record[11] = 0x20;
        TreeEntry {
            path: vec!["?ILE.TXT".into()],
            entry: DirectoryEntry {
                source_offset: 540_672,
                raw_record,
                short_name: *b"?ILE    TXT",
                long_name: None,
                deleted_long_name_lead: None,
                deleted,
                attributes: 0x20,
                first_cluster: 10,
                size: 512,
            },
        }
    }

    fn test_db() -> rusqlite::Connection {
        let db = crate::database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Case','Examiner')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO evidence_sources(id,case_id,original_path,name,size_bytes,filesystem,opened_at,sha256,status) VALUES (2,1,'evidence.img','evidence.img',4096,'FAT32','1',?1,'hashed')",
            [&"a".repeat(64)],
        )
        .unwrap();
        db
    }

    fn persist(db: &mut rusqlite::Connection) -> i64 {
        let entries = [entry(false), entry(true)];
        let boot = serde_json::json!({
            "primary_sector_hex": "00",
            "backup_sector_hex": null,
            "volume_offset": 0,
            "cluster_count": 65_525,
            "root_cluster": 2,
        });
        persist_scan_snapshot(
            db,
            &ScanSnapshot {
                evidence_id: 2,
                case_id: 1,
                source_id: 3,
                volume_offset: 0,
                source_sha256: &"a".repeat(64),
                boot: &boot,
                entries: &entries,
            },
        )
        .unwrap()
    }

    #[test]
    fn completed_fat32_snapshot_and_audit_commit_together() {
        let mut db = test_db();
        let id = persist(&mut db);
        let sessions = list_case_fat32_scan_sessions_from(&db, 1).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].records, 2);
        assert_eq!(sessions[0].found, 2);
        assert_eq!(sessions[0].deleted, 1);
    }

    #[test]
    fn fat32_snapshot_tampering_is_detected_after_rehashing_the_audit_chain() {
        let mut db = test_db();
        let id = persist(&mut db);
        db.execute(
            "UPDATE fat32_scan_sessions SET entries_json='[]' WHERE id=?1",
            [id],
        )
        .unwrap();
        let error = list_case_fat32_scan_sessions_from(&db, 1).unwrap_err();
        assert!(error.contains("does not match its audited contents"));
    }

    #[test]
    fn fat32_scan_listing_rejects_orphan_and_duplicate_audit_references() {
        let mut db = test_db();
        let id = persist(&mut db);
        let audit_payload = serde_json::json!({
            "case_id": 1,
            "evidence_id": 2,
            "scan_session_id": id,
            "source_id": 3,
            "volume_offset": 0,
            "source_sha256": "a".repeat(64),
            "records": 2,
            "found": 2,
            "deleted": 1,
            "snapshot_sha256": "f".repeat(64),
        });
        crate::audit(&db, "fat32_scan_persisted", &audit_payload.to_string()).unwrap();
        let duplicate_error = list_case_fat32_scan_sessions_from(&db, 1).unwrap_err();
        assert!(duplicate_error.contains("Duplicate FAT32 scan audit reference"));

        let mut orphan_db = test_db();
        let orphan_id = persist(&mut orphan_db);
        let orphan_payload = serde_json::json!({
            "case_id": 1,
            "evidence_id": 2,
            "scan_session_id": orphan_id + 100,
            "source_id": 3,
            "volume_offset": 0,
            "source_sha256": "a".repeat(64),
            "records": 0,
            "found": 0,
            "deleted": 0,
            "snapshot_sha256": "e".repeat(64),
        });
        crate::audit(
            &orphan_db,
            "fat32_scan_persisted",
            &orphan_payload.to_string(),
        )
        .unwrap();
        let orphan_error = list_case_fat32_scan_sessions_from(&orphan_db, 1).unwrap_err();
        assert!(orphan_error.contains("no matching stored snapshot"));
    }
}
