use crate::{
    audit, audit_timestamp, destination, err, list_case_evidence_from, list_cases_from,
    require_audited_active_case, verify_audit_chain, verify_evidence_record_integrity, AppState,
    Case, EvidenceRecord, Job, Result,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPORT_SCANS: usize = 200;
const ANCHOR_NOTE: &str = "This report includes an internally verified local audit-chain head. It is not digitally signed or externally anchored; preserve the head hash independently.";

#[derive(Serialize)]
struct ReportAudit {
    chain_valid: bool,
    records_checked: u64,
    head_sha256: String,
    externally_anchored: bool,
    note: &'static str,
}

#[derive(Serialize)]
struct ReportScan {
    id: i64,
    evidence_id: i64,
    volume_offset: String,
    source_sha256: String,
    completed_at: String,
    records: u64,
    skipped: u64,
    found: usize,
    limited: bool,
    snapshot_sha256: String,
    boot: serde_json::Value,
    candidates: Vec<crate::ntfs::Candidate>,
}

#[derive(Serialize)]
struct CaseReport {
    format: &'static str,
    generated_at_unix_ns: String,
    hash_algorithm: &'static str,
    case: Case,
    evidence: Vec<EvidenceRecord>,
    scans: Vec<ReportScan>,
    audit: ReportAudit,
    scope_note: &'static str,
}

#[derive(Serialize)]
pub struct CaseReportExport {
    path: String,
    sha256: String,
    bytes: u64,
    scans: usize,
    candidates: usize,
}

struct StagedFile(PathBuf);

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn case_report_from(db: &rusqlite::Connection, case_id: i64) -> Result<CaseReport> {
    if require_audited_active_case(db)? != case_id {
        return Err("Select the report's case as the active case before exporting.".into());
    }
    let case = list_cases_from(db)?
        .into_iter()
        .find(|case| case.id == case_id)
        .filter(|case| case.integrity == "audit_matched")
        .ok_or("The selected case does not have a verified creation record.")?;
    let evidence = list_case_evidence_from(db, case_id)?;
    verify_evidence_record_integrity(db, &evidence)?;
    let sessions = crate::recovery_commands::list_case_scan_sessions_from(db, case_id)?;
    if sessions.len() > MAX_REPORT_SCANS {
        return Err(format!(
            "The case exceeds the supported {MAX_REPORT_SCANS}-scan report limit."
        ));
    }
    let mut scans = Vec::with_capacity(sessions.len());
    for session in sessions {
        let (boot_json, candidates_json, snapshot_sha256): (String, String, String) = db
            .query_row(
                "SELECT boot_json,candidates_json,snapshot_sha256 FROM scan_sessions WHERE id=?1 AND case_id=?2",
                rusqlite::params![session.id, case_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(err)?;
        let boot = serde_json::from_str(&boot_json)
            .map_err(|error| format!("Scan {} boot metadata is invalid: {error}", session.id))?;
        let candidates: Vec<crate::ntfs::Candidate> = serde_json::from_str(&candidates_json)
            .map_err(|error| {
                format!("Scan {} candidate snapshot is invalid: {error}", session.id)
            })?;
        scans.push(ReportScan {
            id: session.id,
            evidence_id: session.evidence_id,
            volume_offset: session.volume_offset,
            source_sha256: session.source_sha256,
            completed_at: session.completed_at,
            records: session.records,
            skipped: session.skipped,
            found: session.found,
            limited: session.limited,
            snapshot_sha256,
            boot,
            candidates,
        });
    }
    let audit = verify_audit_chain(db)?;
    if !audit.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            audit.first_invalid_record.unwrap_or_default()
        ));
    }
    let generated_at_unix_ns = audit_timestamp(SystemTime::now())?;
    let report = CaseReport {
        format: "daemoncore-case-report-v1",
        generated_at_unix_ns,
        hash_algorithm: "SHA-256",
        case,
        evidence,
        scans,
        audit: ReportAudit {
            chain_valid: audit.valid,
            records_checked: audit.records_checked,
            head_sha256: audit.head_sha256,
            externally_anchored: false,
            note: ANCHOR_NOTE,
        },
        scope_note: "This report contains case records and NTFS metadata-scan candidate snapshots. It does not establish recovered-file content integrity, acquisition provenance, or an external trust anchor.",
    };
    Ok(report)
}

fn encode_report(report: &CaseReport) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(report).map_err(err)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "The case report exceeds the {} MiB export limit.",
            MAX_REPORT_BYTES / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

fn stage_report(destination: &Path, bytes: &[u8]) -> Result<StagedFile> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .ok_or("Choose a report filename.")?
        .to_string_lossy();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_nanos();
    let staging = parent.join(format!(
        ".{file_name}.partial-{}-{stamp}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(err)?;
    let staged = StagedFile(staging);
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    drop(file);
    Ok(staged)
}

#[tauri::command]
pub async fn export_case_report(
    case_id: i64,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<CaseReportExport>> {
    {
        let mut job = state.job.lock().map_err(err)?;
        if job.state == "running" {
            return Err("Wait for the active operation before exporting a case report.".into());
        }
        state.cancel.store(false, Ordering::SeqCst);
        *job = Job {
            state: "running".into(),
            kind: "case_report_export".into(),
            message: Some("Preparing a verified case report".into()),
            ..Job::default()
        };
    }
    let result: Result<Option<CaseReportExport>> = async {
        let destination = tauri::async_runtime::spawn_blocking(|| {
            rfd::FileDialog::new()
                .set_title("Export forensic case report")
                .add_filter("JSON case report", &["json"])
                .set_file_name("DaemonCore-Case-Report.json")
                .save_file()
        })
        .await
        .map_err(err)?;
        let Some(destination) = destination else {
            return Ok(None);
        };
        if state.cancel.load(Ordering::SeqCst) {
            return Err("Case report export was cancelled before report generation.".into());
        }
        let exported = tauri::async_runtime::spawn_blocking(move || {
            let state = app.state::<AppState>();
            let report = {
                let mut db = state.db.lock().map_err(err)?;
                let transaction = db.transaction().map_err(err)?;
                let report = case_report_from(&transaction, case_id)?;
                transaction.commit().map_err(err)?;
                report
            };
            let bytes = encode_report(&report)?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if let Ok(mut job) = state.job.lock() {
                job.message = Some("Staging the report and recording its digest".into());
                job.total = bytes.len() as u64;
            }
            let staged = stage_report(&destination, &bytes)?;
            {
                let db = state.db.lock().map_err(err)?;
                audit(
                    &db,
                    "case_report_export_prepared",
                    &serde_json::json!({
                        "case_id": case_id,
                        "destination": destination.to_string_lossy(),
                        "sha256": digest,
                        "bytes": bytes.len(),
                        "scans": report.scans.len(),
                        "candidates": report.scans.iter().map(|scan| scan.candidates.len()).sum::<usize>(),
                        "audit_head_in_report": report.audit.head_sha256,
                    })
                    .to_string(),
                )?;
            }
            destination::publish_new(&staged.0, &destination).map_err(|error| {
                format!(
                    "The report was staged and audited but could not be published to {}: {error}",
                    destination.display()
                )
            })?;
            let published = CaseReportExport {
                path: destination.to_string_lossy().into_owned(),
                sha256: digest,
                bytes: bytes.len() as u64,
                scans: report.scans.len(),
                candidates: report.scans.iter().map(|scan| scan.candidates.len()).sum(),
            };
            let db = state.db.lock().map_err(err)?;
            audit(
                &db,
                "case_report_exported",
                &serde_json::json!({
                    "case_id": case_id,
                    "destination": published.path,
                    "sha256": published.sha256,
                    "bytes": published.bytes,
                    "scans": published.scans,
                    "candidates": published.candidates,
                    "audit_head_in_report": report.audit.head_sha256,
                })
                .to_string(),
            )
            .map_err(|error| {
                format!(
                    "The report was written to {} but its completion could not be recorded in the audit log: {error}",
                    published.path
                )
            })?;
            Ok::<_, String>(published)
        })
        .await
        .map_err(err)??;
        Ok(Some(exported))
    }
    .await;
    if let Ok(mut job) = state.job.lock() {
        match &result {
            Ok(Some(report)) => {
                job.state = "completed".into();
                job.message = Some(format!(
                    "Case report exported · {} scans · {} candidates",
                    report.scans, report.candidates
                ));
                job.total = report.bytes;
                job.processed = report.bytes;
            }
            Ok(None) => {
                job.state = "cancelled".into();
                job.message = Some("Case report export cancelled".into());
            }
            Err(error) => {
                job.state = if state.cancel.load(Ordering::SeqCst) {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                job.error = Some(error.clone());
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_staging_is_no_replace_and_cleans_up() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "daemoncore-case-report-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir(&root).unwrap();
        let destination = root.join("report.json");
        let bytes = br#"{"format":"daemoncore-case-report-v1"}"#;
        let staged = stage_report(&destination, bytes).unwrap();
        assert_eq!(fs::read(&staged.0).unwrap(), bytes);
        destination::publish_new(&staged.0, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        let collision = stage_report(&destination, b"replacement").unwrap();
        assert!(destination::publish_new(&collision.0, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(fs::read(&collision.0).unwrap(), b"replacement");
        drop(collision);
        drop(staged);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_uses_json_schema_and_marks_the_chain_unanchored() {
        let db = crate::database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Case 1','Examiner')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO app_settings(key,value) VALUES ('active_case_id','1')",
            [],
        )
        .unwrap();
        audit(
            &db,
            "case_created",
            &serde_json::json!({"id":1,"title":"Case 1","examiner":"Examiner","selected":true})
                .to_string(),
        )
        .unwrap();
        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.case.id, 1);
        assert!(report.evidence.is_empty());
        assert!(report.scans.is_empty());
        assert!(report.audit.chain_valid);
        assert!(!report.audit.externally_anchored);
        let bytes = encode_report(&report).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["format"], "daemoncore-case-report-v1");
        assert_eq!(report["audit"]["externally_anchored"], false);
        assert_eq!(report["case"]["title"], "Case 1");
        db.execute("UPDATE audit SET payload='tampered' WHERE id=1", [])
            .unwrap();
        assert!(case_report_from(&db, 1).is_err());
    }
}
