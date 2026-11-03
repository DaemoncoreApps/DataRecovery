use crate::{audit, err, storage::BlockSource, AppState, Job, Result};
use daemoncore_ntfs_core::exfat::{self, TreeEntry};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};
use tauri::{Manager, State};

const MAX_SNAPSHOT_BYTES: usize = 48 * 1024 * 1024;

pub(super) struct ExfatScanCache {
    case_id: i64,
    source_id: u64,
    source_sha256: String,
    volume_offset: u64,
    persistent_id: i64,
    entries: Vec<TreeEntry>,
}

#[derive(Serialize)]
pub struct ExfatScanSummary {
    pub scan_session_id: i64,
    pub source_id: u64,
    pub source_sha256: String,
    pub volume_offset: String,
    pub entries: usize,
}

#[derive(Serialize)]
pub struct ExfatPage {
    pub total: usize,
    pub rows: Vec<TreeEntry>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ExfatCaseScanSession {
    pub id: i64,
    pub evidence_id: i64,
    pub case_id: i64,
    pub volume_offset: String,
    pub source_sha256: String,
    pub completed_at: String,
    pub records: usize,
}

pub(super) fn snapshot_digest(source_sha256: &str, boot: &str, entries: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"DaemonCore exFAT directory snapshot v1\0");
    for bytes in [
        source_sha256.as_bytes(),
        boot.as_bytes(),
        entries.as_bytes(),
    ] {
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

#[tauri::command]
pub fn start_exfat_scan(offset: u64, app: tauri::AppHandle, state: State<AppState>) -> Result<()> {
    let (image, source_id, evidence_id, case_id, expected_sha256, source_path) = {
        let current = state.source.lock().map_err(err)?;
        let evidence = current.as_ref().ok_or("Open an evidence image first.")?;
        if evidence.integrity_compromised {
            return Err(
                "The source integrity is compromised. Reopen a verified working copy.".into(),
            );
        }
        let hash = evidence
            .info
            .sha256
            .clone()
            .ok_or("Calculate the source SHA-256 before scanning.")?;
        evidence.image.verify_unchanged().map_err(err)?;
        (
            evidence.image.clone(),
            evidence.info.id,
            evidence.info.evidence_record_id,
            evidence.info.case_id,
            hash,
            evidence.image.path.to_string_lossy().into_owned(),
        )
    };
    if offset >= image.len() {
        return Err("Volume offset is outside the image.".into());
    }
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Wait for the active operation before starting exFAT analysis.".into());
    }
    {
        let db = state.db.lock().map_err(err)?;
        if crate::require_audited_active_case(&db)? != case_id {
            return Err("Select the evidence image's audited case before scanning.".into());
        }
        audit(&db, "exfat_scan_started", &serde_json::json!({"case_id":case_id,"evidence_id":evidence_id,"source_id":source_id,"source_path":source_path,"source_sha256":expected_sha256,"volume_offset":offset}).to_string())?;
    }
    *state.exfat_scan.lock().map_err(err)? = None;
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "exfat_scan".into(),
        message: Some(
            "Validating exFAT boot regions, allocation metadata, and directory entries".into(),
        ),
        ..Job::default()
    };

    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let operation = crate::guarded(|| {
            let volume = exfat::Volume::open(image.as_ref(), offset, image.len() - offset)?;
            let entries = volume.read_tree(image.as_ref())?;
            if state.cancel.load(Ordering::SeqCst) {
                return Err("exFAT scan was cancelled; no results were recorded.".into());
            }
            image.verify_unchanged().map_err(err)?;
            let boot = serde_json::json!({"volume_offset":offset,"bytes_per_sector":volume.bytes_per_sector(),"cluster_count":volume.cluster_count(),"root_cluster":volume.root_cluster(),"source_path":source_path});
            let boot_json = serde_json::to_string(&boot).map_err(err)?;
            let entries_json = serde_json::to_string(&entries).map_err(err)?;
            if entries_json.len() > MAX_SNAPSHOT_BYTES {
                return Err(
                    "exFAT directory snapshot exceeds the 48 MiB case database limit.".into(),
                );
            }
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
            .ok_or("Source verification was cancelled; exFAT results were discarded.")?;
            if after != expected_sha256 {
                if let Ok(mut source) = state.source.lock() {
                    if let Some(source) =
                        source.as_mut().filter(|source| source.info.id == source_id)
                    {
                        source.info.sha256 = None;
                        source.integrity_compromised = true;
                    }
                }
                return Err(
                    "Source SHA-256 changed during exFAT analysis. Results were discarded.".into(),
                );
            }
            let current = state.source.lock().map_err(err)?;
            if !current.as_ref().is_some_and(|source| {
                source.info.id == source_id
                    && source.info.case_id == case_id
                    && source.info.sha256.as_deref() == Some(expected_sha256.as_str())
                    && !source.integrity_compromised
            }) {
                return Err("The active evidence source changed during exFAT analysis.".into());
            }
            Ok((boot_json, entries_json, entries))
        });
        let Ok(mut job) = state.job.lock() else {
            return;
        };
        match operation {
            Ok((boot_json, entries_json, entries)) => {
                let stored = state.db.lock().map_err(err).and_then(|mut db| {
                    if crate::require_audited_active_case(&db)? != case_id {
                        return Err("The active case changed during exFAT analysis.".into());
                    }
                    let digest = snapshot_digest(&expected_sha256, &boot_json, &entries_json);
                    let completed = crate::audit_timestamp(std::time::SystemTime::now())?;
                    let tx = db.transaction().map_err(err)?;
                    tx.execute("INSERT INTO exfat_scan_sessions(evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,entries_json,snapshot_sha256) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![evidence_id,case_id,offset.to_string(),expected_sha256,completed,boot_json,entries_json,digest]).map_err(err)?;
                    let id = tx.last_insert_rowid();
                    audit(&tx, "exfat_scan_persisted", &serde_json::json!({"case_id":case_id,"evidence_id":evidence_id,"source_id":source_id,"scan_session_id":id,"volume_offset":offset,"source_sha256":expected_sha256,"records":entries.len(),"snapshot_sha256":digest}).to_string())?;
                    tx.commit().map_err(err)?;
                    Ok(id)
                });
                match stored {
                    Ok(id) => match state.exfat_scan.lock() {
                        Ok(mut cache) => {
                            *cache = Some(Arc::new(ExfatScanCache {
                                case_id,
                                source_id,
                                source_sha256: expected_sha256,
                                volume_offset: offset,
                                persistent_id: id,
                                entries,
                            }));
                            job.state = "completed".into();
                            job.discovered = cache.as_ref().map_or(0, |scan| scan.entries.len());
                            job.message = Some("exFAT directory inventory verified and recorded in the case audit trail.".into());
                        }
                        Err(error) => {
                            job.state = "failed".into();
                            job.error = Some(format!("Could not retain exFAT results: {error}"));
                        }
                    },
                    Err(error) => {
                        job.state = "failed".into();
                        job.error = Some(format!(
                            "exFAT scan could not be committed to the case record: {error}"
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
            if let Ok(db) = state.db.lock() {
                let _ = audit(
                    &db,
                    "exfat_scan_finished",
                    &serde_json::json!({"case_id":case_id,"source_id":source_id,"job":&*job})
                        .to_string(),
                );
            }
        }
    });
    Ok(())
}

#[tauri::command]
pub fn exfat_scan_summary(state: State<AppState>) -> Result<Option<ExfatScanSummary>> {
    let cache = state.exfat_scan.lock().map_err(err)?;
    Ok(cache.as_ref().map(|scan| ExfatScanSummary {
        scan_session_id: scan.persistent_id,
        source_id: scan.source_id,
        source_sha256: scan.source_sha256.clone(),
        volume_offset: scan.volume_offset.to_string(),
        entries: scan.entries.len(),
    }))
}

#[tauri::command]
pub fn exfat_scan_results(
    source_id: u64,
    offset: usize,
    limit: usize,
    state: State<AppState>,
) -> Result<ExfatPage> {
    if limit == 0 || limit > 200 {
        return Err("Invalid exFAT results page size.".into());
    }
    let current = state.source.lock().map_err(err)?;
    let evidence = current.as_ref().ok_or("Open an image first.")?;
    if evidence.info.id != source_id
        || evidence.integrity_compromised
        || evidence.info.sha256.is_none()
    {
        return Err("The active source is unverified or has changed.".into());
    }
    let scan = state
        .exfat_scan
        .lock()
        .map_err(err)?
        .as_ref()
        .cloned()
        .ok_or("No exFAT scan results are available.")?;
    if scan.source_id != source_id
        || scan.case_id != evidence.info.case_id
        || evidence.info.sha256.as_deref() != Some(scan.source_sha256.as_str())
    {
        return Err("These exFAT results do not match the active source and case.".into());
    }
    let db = state.db.lock().map_err(err)?;
    if crate::require_audited_active_case(&db)? != scan.case_id {
        return Err("Select the audited case recorded by this scan.".into());
    }
    let chain = crate::verify_audit_chain(&db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let (stored_offset, stored_hash, boot, entries, stored_digest): (String, String, String, String, String) = db.query_row(
        "SELECT volume_offset,source_sha256,boot_json,entries_json,snapshot_sha256 FROM exfat_scan_sessions WHERE id=?1 AND case_id=?2",
        rusqlite::params![scan.persistent_id, scan.case_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).map_err(err)?;
    if entries.len() > MAX_SNAPSHOT_BYTES {
        return Err("Persisted exFAT snapshot exceeds the supported verification limit.".into());
    }
    if stored_offset != scan.volume_offset.to_string()
        || stored_hash != scan.source_sha256
        || snapshot_digest(&stored_hash, &boot, &entries) != stored_digest
        || serde_json::from_str::<Vec<TreeEntry>>(&entries).map_err(err)? != scan.entries
    {
        return Err(
            "The persisted exFAT snapshot does not match its verified in-memory results.".into(),
        );
    }
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='exfat_scan_persisted'")
        .map_err(err)?;
    let audit_rows = audit_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(err)?;
    let mut matching_payload = None;
    for row in audit_rows {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        if payload["scan_session_id"].as_i64() == Some(scan.persistent_id)
            && matching_payload.replace(payload).is_some()
        {
            return Err("Duplicate exFAT scan audit records were found.".into());
        }
    }
    let audit_payload =
        matching_payload.ok_or("The exFAT scan has no matching case audit record.")?;
    if audit_payload["case_id"].as_i64() != Some(scan.case_id)
        || audit_payload["source_sha256"].as_str() != Some(scan.source_sha256.as_str())
        || audit_payload["snapshot_sha256"].as_str() != Some(stored_digest.as_str())
        || audit_payload["volume_offset"].as_u64() != Some(scan.volume_offset)
        || audit_payload["records"].as_u64() != Some(scan.entries.len() as u64)
    {
        return Err("The exFAT scan snapshot does not match its case audit record.".into());
    }
    Ok(ExfatPage {
        total: scan.entries.len(),
        rows: scan
            .entries
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect(),
    })
}

#[tauri::command]
pub fn list_case_exfat_scan_sessions(
    case_id: i64,
    state: State<AppState>,
) -> Result<Vec<ExfatCaseScanSession>> {
    let db = state.db.lock().map_err(err)?;
    list_case_exfat_scan_sessions_from(&db, case_id)
}

pub(super) fn list_case_exfat_scan_sessions_from(
    db: &rusqlite::Connection,
    case_id: i64,
) -> Result<Vec<ExfatCaseScanSession>> {
    let chain = crate::verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='exfat_scan_persisted'")
        .map_err(err)?;
    let mut audit_records = std::collections::HashMap::new();
    for row in audit_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(err)?
    {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        let id = payload["scan_session_id"]
            .as_i64()
            .ok_or("An exFAT audit record has no valid scan ID.")?;
        if audit_records.insert(id, payload).is_some() {
            return Err(format!("Duplicate exFAT scan audit record for {id}."));
        }
    }
    let mut statement = db
        .prepare("SELECT id,evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,entries_json,snapshot_sha256 FROM exfat_scan_sessions WHERE case_id=?1 ORDER BY id DESC")
        .map_err(err)?;
    let rows = statement
        .query_map([case_id], |row| {
            Ok((
                ExfatCaseScanSession {
                    id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    case_id: row.get(2)?,
                    volume_offset: row.get(3)?,
                    source_sha256: row.get(4)?,
                    completed_at: row.get(5)?,
                    records: 0,
                },
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(err)?;
    let mut sessions = Vec::new();
    let mut session_ids = std::collections::HashSet::new();
    for row in rows {
        let (mut session, boot_json, entries_json, stored_digest) = row.map_err(err)?;
        if entries_json.len() > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "Stored exFAT scan {} exceeds the supported verification limit.",
                session.id
            ));
        }
        let payload = audit_records
            .get(&session.id)
            .ok_or("A stored exFAT scan has no matching audit record.")?;
        let boot: serde_json::Value = serde_json::from_str(&boot_json).map_err(err)?;
        let entries: Vec<TreeEntry> = serde_json::from_str(&entries_json).map_err(|error| {
            format!("Stored exFAT scan entries have an invalid schema: {error}")
        })?;
        let offset = session.volume_offset.parse::<u64>().map_err(err)?;
        session.records = entries.len();
        if session.case_id != case_id
            || payload["case_id"].as_i64() != Some(case_id)
            || payload["evidence_id"].as_i64() != Some(session.evidence_id)
            || payload["source_sha256"].as_str() != Some(session.source_sha256.as_str())
            || payload["snapshot_sha256"].as_str() != Some(stored_digest.as_str())
            || payload["volume_offset"].as_u64() != Some(offset)
            || payload["records"].as_u64() != Some(entries.len() as u64)
            || snapshot_digest(&session.source_sha256, &boot_json, &entries_json) != stored_digest
            || !boot.is_object()
            || boot["volume_offset"].as_u64() != Some(offset)
        {
            return Err(format!(
                "Stored exFAT scan {} does not match its audited contents.",
                session.id
            ));
        }
        session_ids.insert(session.id);
        sessions.push(session);
    }
    if audit_records.iter().any(|(id, payload)| {
        payload["case_id"].as_i64() == Some(case_id) && !session_ids.contains(id)
    }) {
        return Err("An audited exFAT scan has no matching stored snapshot.".into());
    }
    Ok(sessions)
}

#[tauri::command]
pub fn archived_exfat_scan_results(
    case_id: i64,
    scan_session_id: i64,
    offset: usize,
    limit: usize,
    state: State<AppState>,
) -> Result<ExfatPage> {
    if limit == 0 || limit > 200 {
        return Err("Invalid archived exFAT-results page size.".into());
    }
    let db = state.db.lock().map_err(err)?;
    let session = list_case_exfat_scan_sessions_from(&db, case_id)?
        .into_iter()
        .find(|session| session.id == scan_session_id)
        .ok_or("The archived exFAT scan does not belong to the selected case.")?;
    let entries_json: String = db
        .query_row(
            "SELECT entries_json FROM exfat_scan_sessions WHERE id=?1 AND case_id=?2",
            rusqlite::params![scan_session_id, case_id],
            |row| row.get(0),
        )
        .map_err(err)?;
    let entries: Vec<TreeEntry> = serde_json::from_str(&entries_json).map_err(err)?;
    if entries.len() != session.records {
        return Err("Archived exFAT entry count does not match its audited record.".into());
    }
    Ok(ExfatPage {
        total: entries.len(),
        rows: entries.into_iter().skip(offset).take(limit).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemoncore_ntfs_core::exfat::DirectoryEntry;
    use std::path::PathBuf;

    fn fixture_db() -> rusqlite::Connection {
        let db = crate::database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Case','Examiner')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO evidence_sources(id,case_id,original_path,name,size_bytes,filesystem,opened_at,sha256,status) VALUES (2,1,'evidence.img','evidence.img',4096,'exFAT','1',?1,'hashed')", ["b".repeat(64)])
            .unwrap();
        crate::audit(
            &db,
            "case_created",
            &serde_json::json!({"id":1,"title":"Case","examiner":"Examiner","selected":true})
                .to_string(),
        )
        .unwrap();
        db
    }

    fn persist_fixture(db: &rusqlite::Connection) {
        let entries = vec![TreeEntry {
            path: vec!["ROOT.TXT".into()],
            entry: DirectoryEntry {
                source_offset: 4096,
                raw_entries: vec![[0x85; 32], [0xc0; 32], [0xc1; 32]],
                name: "ROOT.TXT".into(),
                attributes: 0x20,
                first_cluster: 0,
                valid_data_length: 0,
                data_length: 0,
                no_fat_chain: false,
                name_hash: 0x1234,
            },
        }];
        let boot = serde_json::json!({"volume_offset":0,"bytes_per_sector":512,"cluster_count":2008,"root_cluster":2});
        let boot_json = serde_json::to_string(&boot).unwrap();
        let entries_json = serde_json::to_string(&entries).unwrap();
        let source_sha256 = "b".repeat(64);
        let digest = snapshot_digest(&source_sha256, &boot_json, &entries_json);
        db.execute("INSERT INTO exfat_scan_sessions(id,evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,entries_json,snapshot_sha256) VALUES (5,2,1,'0',?1,'12',?2,?3,?4)", rusqlite::params![source_sha256,boot_json,entries_json,digest]).unwrap();
        crate::audit(&db,"exfat_scan_persisted",&serde_json::json!({"case_id":1,"evidence_id":2,"source_id":9,"scan_session_id":5,"volume_offset":0,"source_sha256":source_sha256,"records":1,"snapshot_sha256":digest}).to_string()).unwrap();
    }

    #[test]
    fn archived_session_is_returned_only_when_snapshot_and_audit_match() {
        let db = fixture_db();
        persist_fixture(&db);
        let sessions = list_case_exfat_scan_sessions_from(&db, 1).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, 5);
        assert_eq!(sessions[0].records, 1);
    }

    #[test]
    fn archived_session_rejects_snapshot_tampering_and_orphan_audit_records() {
        let db = fixture_db();
        persist_fixture(&db);
        db.execute(
            "UPDATE exfat_scan_sessions SET entries_json='[]' WHERE id=5",
            [],
        )
        .unwrap();
        assert!(list_case_exfat_scan_sessions_from(&db, 1)
            .unwrap_err()
            .contains("does not match its audited contents"));

        let other = fixture_db();
        crate::audit(&other,"exfat_scan_persisted",&serde_json::json!({"case_id":1,"evidence_id":2,"scan_session_id":99,"volume_offset":0,"source_sha256":"b".repeat(64),"records":0,"snapshot_sha256":"c".repeat(64)}).to_string()).unwrap();
        assert!(list_case_exfat_scan_sessions_from(&other, 1)
            .unwrap_err()
            .contains("no matching stored snapshot"));
    }
}
