use crate::{
    audit, audit_timestamp, destination, err, list_case_evidence_from, list_cases_from,
    require_audited_active_case, verify_audit_chain, verify_evidence_record_integrity, AppState,
    Case, EvidenceRecord, Job, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPORT_SCANS: usize = 200;
const MAX_REPORT_OPERATIONS: usize = 2_000;
const MAX_OPERATION_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_REPORT_OPERATION_BYTES: usize = 16 * 1024 * 1024;
const ANCHOR_NOTE: &str = "This report includes an internally verified local audit-chain head. It is not digitally signed or externally anchored; preserve the head hash independently.";

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Html,
}

impl ReportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
        }
    }

    fn filter_name(self) -> &'static str {
        match self {
            Self::Json => "JSON case report",
            Self::Html => "Printable HTML case report",
        }
    }
}

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
    evidence_hash_matches_current_record: bool,
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
struct ReportFat32Scan {
    id: i64,
    evidence_id: i64,
    evidence_hash_matches_current_record: bool,
    volume_offset: String,
    source_sha256: String,
    completed_at: String,
    records: u64,
    found: usize,
    deleted: usize,
    snapshot_sha256: String,
    boot: serde_json::Value,
    entries: Vec<daemoncore_ntfs_core::fat32::TreeEntry>,
}

#[derive(Serialize)]
struct ReportExfatScan {
    id: i64,
    evidence_id: i64,
    evidence_hash_matches_current_record: bool,
    volume_offset: String,
    source_sha256: String,
    completed_at: String,
    snapshot_sha256: String,
    boot: serde_json::Value,
    entries: Vec<daemoncore_ntfs_core::exfat::TreeEntry>,
}

#[derive(Serialize)]
struct ReportCarveScan {
    id: i64,
    evidence_id: i64,
    evidence_hash_matches_current_record: bool,
    source_sha256: String,
    completed_at: String,
    scanned_bytes: u64,
    candidates_limited: bool,
    snapshot_sha256: String,
    candidates: Vec<crate::carving::CarvedCandidate>,
}

#[derive(Serialize)]
struct ReportOperation {
    audit_record_id: i64,
    timestamp: String,
    event: String,
    record_sha256: String,
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct CaseReport {
    format: &'static str,
    generated_at_unix_ms: String,
    hash_algorithm: &'static str,
    case: Case,
    evidence: Vec<EvidenceRecord>,
    scans: Vec<ReportScan>,
    fat32_scans: Vec<ReportFat32Scan>,
    exfat_scans: Vec<ReportExfatScan>,
    carve_scans: Vec<ReportCarveScan>,
    imaging_and_raid_operations: Vec<ReportOperation>,
    recovery_operations: Vec<ReportOperation>,
    audit: ReportAudit,
    scope_note: &'static str,
}

#[derive(Serialize)]
pub struct CaseReportExport {
    case_id: i64,
    path: String,
    sha256: String,
    bytes: u64,
    scans: usize,
    candidates: usize,
    fat32_scans: usize,
    directory_entries: usize,
    exfat_scans: usize,
    exfat_entries: usize,
    carve_scans: usize,
    carved_candidates: usize,
    imaging_and_raid_operations: usize,
    recovery_operations: usize,
}

fn case_operations(
    db: &rusqlite::Connection,
    case_id: i64,
    events: &[&str],
    family: &str,
) -> Result<Vec<ReportOperation>> {
    let placeholders = vec!["?"; events.len()].join(",");
    let case_id_parameter = events.len() + 1;
    let query = format!(
        "SELECT id,timestamp,event,payload,hash FROM audit WHERE event IN ({placeholders}) AND CASE WHEN json_valid(payload) THEN json_extract(payload, '$.case_id') ELSE NULL END = ?{case_id_parameter} ORDER BY id"
    );
    let mut parameters = events
        .iter()
        .map(|event| rusqlite::types::Value::Text((*event).to_owned()))
        .collect::<Vec<_>>();
    parameters.push(rusqlite::types::Value::Integer(case_id));
    let mut statement = db.prepare(&query).map_err(err)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(parameters.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(err)?;
    let mut operations = Vec::new();
    let mut operation_bytes = 0usize;
    for row in rows {
        let (id, timestamp, event, payload, record_sha256) = row.map_err(err)?;
        if !events.contains(&event.as_str()) {
            return Err("The audit query returned an unexpected event type.".into());
        }
        if payload.len() > MAX_OPERATION_PAYLOAD_BYTES {
            return Err(format!(
                "Audit record {id} is too large to include safely in this report."
            ));
        }
        let payload_bytes = payload.len();
        let payload: serde_json::Value = serde_json::from_str(&payload)
            .map_err(|error| format!("Audit record {id} has invalid operation data: {error}"))?;
        if payload.get("case_id").and_then(serde_json::Value::as_i64) == Some(case_id) {
            operation_bytes = operation_bytes
                .checked_add(payload_bytes)
                .ok_or_else(|| format!("Case {family} report size overflow"))?;
            if operation_bytes > MAX_REPORT_OPERATION_BYTES {
                return Err(format!(
                    "Case {family} audit records exceed the {} MiB report limit.",
                    MAX_REPORT_OPERATION_BYTES / (1024 * 1024)
                ));
            }
            operations.push(ReportOperation {
                audit_record_id: id,
                timestamp,
                event,
                record_sha256,
                payload,
            });
        }
        if operations.len() > MAX_REPORT_OPERATIONS {
            return Err(format!(
                "The case exceeds the supported {MAX_REPORT_OPERATIONS}-operation report limit."
            ));
        }
    }
    Ok(operations)
}

fn check_report_scan_budget(
    db: &rusqlite::Connection,
    case_id: i64,
    max_snapshot_bytes: u64,
) -> Result<()> {
    let (scan_count, audit_count): (i64, i64) = db
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM scan_sessions WHERE case_id=?1) +
                (SELECT COUNT(*) FROM fat32_scan_sessions WHERE case_id=?1) +
                (SELECT COUNT(*) FROM exfat_scan_sessions WHERE case_id=?1) +
                (SELECT COUNT(*) FROM carve_scan_sessions WHERE case_id=?1),
                (SELECT COUNT(*) FROM audit
                 WHERE event IN ('ntfs_scan_persisted','fat32_scan_persisted','exfat_scan_persisted','carve_scan_persisted')
                   AND CASE WHEN json_valid(payload) THEN json_extract(payload, '$.case_id') ELSE NULL END=?1)",
            [case_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(err)?;
    if scan_count > MAX_REPORT_SCANS as i64 || audit_count > MAX_REPORT_SCANS as i64 {
        return Err(format!(
            "The case exceeds the supported {MAX_REPORT_SCANS}-scan report limit."
        ));
    }

    let mut statement = db
        .prepare(
            "SELECT length(CAST(boot_json AS BLOB)) + length(CAST(candidates_json AS BLOB)) FROM scan_sessions WHERE case_id=?1
             UNION ALL SELECT length(CAST(boot_json AS BLOB)) + length(CAST(entries_json AS BLOB)) FROM fat32_scan_sessions WHERE case_id=?1
             UNION ALL SELECT length(CAST(boot_json AS BLOB)) + length(CAST(entries_json AS BLOB)) FROM exfat_scan_sessions WHERE case_id=?1
             UNION ALL SELECT length(CAST(candidates_json AS BLOB)) FROM carve_scan_sessions WHERE case_id=?1
             UNION ALL SELECT length(CAST(payload AS BLOB)) FROM audit
                WHERE event IN ('ntfs_scan_persisted','fat32_scan_persisted','exfat_scan_persisted','carve_scan_persisted')
                  AND CASE WHEN json_valid(payload) THEN json_extract(payload, '$.case_id') ELSE NULL END=?1",
        )
        .map_err(err)?;
    let sizes = statement
        .query_map([case_id], |row| row.get::<_, i64>(0))
        .map_err(err)?;
    let mut snapshot_bytes = 0u64;
    for size in sizes {
        let size = u64::try_from(size.map_err(err)?).map_err(err)?;
        snapshot_bytes = snapshot_bytes
            .checked_add(size)
            .ok_or("Case scan snapshot size overflow")?;
        if snapshot_bytes > max_snapshot_bytes {
            return Err(format!(
                "Case scan snapshots exceed the {} byte report preflight limit.",
                max_snapshot_bytes
            ));
        }
    }
    Ok(())
}

fn case_imaging_and_raid_operations(
    db: &rusqlite::Connection,
    case_id: i64,
) -> Result<Vec<ReportOperation>> {
    const EVENTS: &[&str] = &[
        "physical_device_acquisition_started",
        "physical_device_acquisition_published",
        "physical_device_acquisition_cancelled",
        "physical_device_acquisition_failed",
        "physical_device_acquisition_finalization_failed",
        "acquired_image_hash_recorded",
        "acquisition_package_verified",
        "raid_reconstruction_started",
        "raid_reconstruction_published",
        "raid_reconstruction_cancelled",
        "raid_reconstruction_failed",
        "raid_reconstruction_image_registered",
        "raid_package_verified",
    ];
    case_operations(db, case_id, EVENTS, "imaging/RAID operation")
}

fn case_recovery_operations(
    db: &rusqlite::Connection,
    case_id: i64,
) -> Result<Vec<ReportOperation>> {
    const EVENTS: &[&str] = &[
        "recovery_export_rejected",
        "recovery_export_started",
        "recovery_export_finished",
        "fat32_recovery_export_rejected",
        "fat32_recovery_export_started",
        "fat32_recovery_export_finished",
        "carve_export_started",
        "carve_export_finished",
        "carve_export_failed",
        "recovery_export_verified",
        "carving_package_verified",
    ];
    case_operations(db, case_id, EVENTS, "recovery")
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
    // Bound stored payloads before serde materializes the report's scan trees in memory.
    check_report_scan_budget(db, case_id, MAX_REPORT_BYTES as u64)?;
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
        let evidence_record = evidence
            .iter()
            .find(|record| record.id == session.evidence_id)
            .ok_or_else(|| {
                format!(
                    "Scan {} refers to evidence record {} outside this case report.",
                    session.id, session.evidence_id
                )
            })?;
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
            evidence_hash_matches_current_record: evidence_record.status == "hashed"
                && evidence_record.sha256.as_deref() == Some(session.source_sha256.as_str()),
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
    let fat32_sessions = crate::fat32_commands::list_case_fat32_scan_sessions_from(db, case_id)?;
    if scans.len() + fat32_sessions.len() > MAX_REPORT_SCANS {
        return Err(format!(
            "The case exceeds the supported {MAX_REPORT_SCANS}-scan report limit."
        ));
    }
    let mut fat32_scans = Vec::with_capacity(fat32_sessions.len());
    for session in fat32_sessions {
        let evidence_record = evidence
            .iter()
            .find(|record| record.id == session.evidence_id)
            .ok_or_else(|| {
                format!(
                    "FAT32 scan {} refers to evidence outside this case.",
                    session.id
                )
            })?;
        let (boot_json, entries_json, snapshot_sha256): (String, String, String) = db
            .query_row(
                "SELECT boot_json,entries_json,snapshot_sha256 FROM fat32_scan_sessions WHERE id=?1 AND case_id=?2",
                rusqlite::params![session.id, case_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(err)?;
        let boot = serde_json::from_str(&boot_json).map_err(|error| {
            format!(
                "FAT32 scan {} boot metadata is invalid: {error}",
                session.id
            )
        })?;
        let entries: Vec<daemoncore_ntfs_core::fat32::TreeEntry> =
            serde_json::from_str(&entries_json).map_err(|error| {
                format!(
                    "FAT32 scan {} entry snapshot is invalid: {error}",
                    session.id
                )
            })?;
        fat32_scans.push(ReportFat32Scan {
            id: session.id,
            evidence_id: session.evidence_id,
            evidence_hash_matches_current_record: evidence_record.status == "hashed"
                && evidence_record.sha256.as_deref() == Some(session.source_sha256.as_str()),
            volume_offset: session.volume_offset,
            source_sha256: session.source_sha256,
            completed_at: session.completed_at,
            records: session.records,
            found: session.found,
            deleted: session.deleted,
            snapshot_sha256,
            boot,
            entries,
        });
    }
    let mut exfat_statement = db.prepare(
        "SELECT id,evidence_id,volume_offset,source_sha256,completed_at,boot_json,entries_json,snapshot_sha256 FROM exfat_scan_sessions WHERE case_id=?1 ORDER BY id",
    ).map_err(err)?;
    let exfat_rows = exfat_statement
        .query_map([case_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(err)?;
    let mut exfat_scans = Vec::new();
    let mut exfat_audit = std::collections::HashMap::new();
    let mut exfat_audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='exfat_scan_persisted' AND CASE WHEN json_valid(payload) THEN json_extract(payload, '$.case_id') ELSE NULL END=?1")
        .map_err(err)?;
    for row in exfat_audit_statement
        .query_map([case_id], |row| row.get::<_, String>(0))
        .map_err(err)?
    {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        let scan_id = payload["scan_session_id"]
            .as_i64()
            .ok_or("An exFAT audit record has no valid scan ID.")?;
        if exfat_audit.insert(scan_id, payload).is_some() {
            return Err(format!(
                "Duplicate exFAT scan audit record for scan {scan_id}."
            ));
        }
    }
    for row in exfat_rows {
        let (
            id,
            evidence_id,
            volume_offset,
            source_sha256,
            completed_at,
            boot_json,
            entries_json,
            stored_digest,
        ) = row.map_err(err)?;
        let evidence_record = evidence
            .iter()
            .find(|record| record.id == evidence_id)
            .ok_or_else(|| format!("exFAT scan {id} refers to evidence outside this case."))?;
        let calculated_digest =
            crate::exfat_commands::snapshot_digest(&source_sha256, &boot_json, &entries_json);
        if calculated_digest != stored_digest {
            return Err(format!(
                "exFAT scan {id} snapshot digest does not match the stored contents."
            ));
        }
        let boot: serde_json::Value = serde_json::from_str(&boot_json)
            .map_err(|error| format!("exFAT scan {id} boot metadata is invalid: {error}"))?;
        let entries: Vec<daemoncore_ntfs_core::exfat::TreeEntry> =
            serde_json::from_str(&entries_json).map_err(|error| {
                format!("exFAT scan {id} directory snapshot is invalid: {error}")
            })?;
        let audit_payload = exfat_audit
            .get(&id)
            .ok_or_else(|| format!("exFAT scan {id} has no matching case audit record."))?;
        if audit_payload["case_id"].as_i64() != Some(case_id)
            || audit_payload["evidence_id"].as_i64() != Some(evidence_id)
            || audit_payload["source_sha256"].as_str() != Some(source_sha256.as_str())
            || audit_payload["snapshot_sha256"].as_str() != Some(stored_digest.as_str())
            || audit_payload["volume_offset"].as_u64() != volume_offset.parse::<u64>().ok()
            || audit_payload["records"].as_u64() != Some(entries.len() as u64)
        {
            return Err(format!(
                "exFAT scan {id} does not match its case audit record."
            ));
        }
        exfat_scans.push(ReportExfatScan {
            id,
            evidence_id,
            evidence_hash_matches_current_record: evidence_record.status == "hashed"
                && evidence_record.sha256.as_deref() == Some(source_sha256.as_str()),
            volume_offset,
            source_sha256,
            completed_at,
            snapshot_sha256: stored_digest,
            boot,
            entries,
        });
    }
    if exfat_audit.iter().any(|(id, payload)| {
        payload["case_id"].as_i64() == Some(case_id)
            && !exfat_scans.iter().any(|scan| scan.id == *id)
    }) {
        return Err("An audited exFAT scan has no matching stored snapshot.".into());
    }
    let carve_sessions = crate::carving::list_case_scan_sessions_from(db, case_id)?;
    if scans.len() + fat32_scans.len() + exfat_scans.len() + carve_sessions.len() > MAX_REPORT_SCANS
    {
        return Err(format!(
            "The case exceeds the supported {MAX_REPORT_SCANS}-scan report limit."
        ));
    }
    let mut carve_scans = Vec::with_capacity(carve_sessions.len());
    for session in carve_sessions {
        let evidence_record = evidence
            .iter()
            .find(|record| record.id == session.evidence_id)
            .ok_or_else(|| {
                format!(
                    "Carving scan {} refers to evidence outside this case.",
                    session.id
                )
            })?;
        if session.scanned_bytes != evidence_record.size_bytes {
            return Err(format!(
                "Carving scan {} did not cover the complete recorded evidence image.",
                session.id
            ));
        }
        carve_scans.push(ReportCarveScan {
            id: session.id,
            evidence_id: session.evidence_id,
            evidence_hash_matches_current_record: evidence_record.status == "hashed"
                && evidence_record.sha256.as_deref() == Some(session.source_sha256.as_str()),
            source_sha256: session.source_sha256,
            completed_at: session.completed_at,
            scanned_bytes: session.scanned_bytes,
            candidates_limited: session.candidates_limited,
            snapshot_sha256: session.snapshot_sha256,
            candidates: session.candidates,
        });
    }
    let audit = verify_audit_chain(db)?;
    if !audit.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            audit.first_invalid_record.unwrap_or_default()
        ));
    }
    let generated_at_unix_ms = audit_timestamp(SystemTime::now())?;
    let imaging_and_raid_operations = case_imaging_and_raid_operations(db, case_id)?;
    let recovery_operations = case_recovery_operations(db, case_id)?;
    let report = CaseReport {
        format: "daemoncore-case-report-v6",
        generated_at_unix_ms,
        hash_algorithm: "SHA-256",
        case,
        evidence,
        scans,
        fat32_scans,
        exfat_scans,
        carve_scans,
        imaging_and_raid_operations,
        recovery_operations,
        audit: ReportAudit {
            chain_valid: audit.valid,
            records_checked: audit.records_checked,
            head_sha256: audit.head_sha256,
            externally_anchored: false,
            note: ANCHOR_NOTE,
        },
        scope_note: "This report contains case records, NTFS candidates, FAT32 and exFAT directory-entry snapshots, validated PNG/BMP/JPEG/GIF carving snapshots, case-scoped recovery export and verification records, and selected audit-linked physical acquisition and RAID operation records. exFAT deleted entry sets are metadata leads only; this application does not recover their file contents. Audit events are included as recorded and are not independent proof that device identity, write blocking, array geometry, or acquisition conditions were correct. It does not establish recovered-file content integrity, that carved files were deleted, or an external trust anchor.",
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

fn push_html_text(output: &mut String, value: &str) -> Result<()> {
    for character in value.chars() {
        output.push_str(match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                output.push(character);
                if output.len() > MAX_REPORT_BYTES {
                    return Err("The printable case report exceeds the 64 MiB export limit.".into());
                }
                continue;
            }
        });
        if output.len() > MAX_REPORT_BYTES {
            return Err("The printable case report exceeds the 64 MiB export limit.".into());
        }
    }
    Ok(())
}

fn encode_html_report(report: &CaseReport) -> Result<Vec<u8>> {
    let json = String::from_utf8(encode_report(report)?)
        .map_err(|error| format!("The encoded case report is not valid UTF-8: {error}"))?;
    let mut html = String::with_capacity(json.len().min(MAX_REPORT_BYTES));
    html.push_str(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Forensic case report</title>
  <style>
    body { font: 15px/1.55 system-ui, Segoe UI, sans-serif; color: #18212b; max-width: 1050px; margin: 40px auto; padding: 0 24px }
    h1, h2 { color: #101820 }
    h1 { margin-bottom: 4px }
    .muted { color: #5d6873 }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 24px 0 }
    .card, section { border: 1px solid #d7dee5; border-radius: 8px; padding: 16px; margin: 16px 0 }
    .card b { display: block; font-size: 22px }
    table { width: 100%; border-collapse: collapse }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e2e7ec; overflow-wrap: anywhere }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.5 ui-monospace, Consolas, monospace }
    @media print {
      body { margin: 0; max-width: none }
      .card, section { break-inside: avoid }
      details { break-before: page }
      details > summary { display: none }
    }
  </style>
</head>
<body>
  <header>
    <p class="muted">DAEMONCORE · DATA RECOVERY</p>
    <h1>"#,
    );
    push_html_text(&mut html, &report.case.title)?;
    html.push_str("</h1>\n    <p class=\"muted\">Case ");
    push_html_text(&mut html, &report.case.id.to_string())?;
    html.push_str(" · Examiner: ");
    push_html_text(&mut html, &report.case.examiner)?;
    html.push_str("</p></header><div class=\"grid\"><div class=\"card\"><b>");
    push_html_text(&mut html, &report.evidence.len().to_string())?;
    html.push_str("</b>Evidence records</div><div class=\"card\"><b>");
    push_html_text(
        &mut html,
        &(report.scans.len()
            + report.fat32_scans.len()
            + report.exfat_scans.len()
            + report.carve_scans.len())
        .to_string(),
    )?;
    html.push_str("</b>Scan snapshots</div><div class=\"card\"><b>");
    push_html_text(
        &mut html,
        &(report.imaging_and_raid_operations.len() + report.recovery_operations.len()).to_string(),
    )?;
    html.push_str("</b>Recorded operations</div></div><section><h2>Evidence register</h2><table><thead><tr><th>ID</th><th>Name</th><th>Original path</th><th>Type</th><th>Status</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>");
    for evidence in &report.evidence {
        html.push_str("<tr><td>");
        push_html_text(&mut html, &evidence.id.to_string())?;
        html.push_str("</td><td>");
        push_html_text(&mut html, &evidence.name)?;
        html.push_str("</td><td>");
        push_html_text(&mut html, &evidence.path)?;
        html.push_str("</td><td>");
        push_html_text(&mut html, &evidence.filesystem)?;
        html.push_str("</td><td>");
        push_html_text(&mut html, &evidence.status)?;
        html.push_str("</td><td>");
        push_html_text(&mut html, &evidence.size_bytes.to_string())?;
        html.push_str("</td><td>");
        push_html_text(
            &mut html,
            evidence.sha256.as_deref().unwrap_or("Not hashed"),
        )?;
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section><section><h2>Audit status</h2><p>Chain valid: ");
    push_html_text(&mut html, &report.audit.chain_valid.to_string())?;
    html.push_str(" · Records checked: ");
    push_html_text(&mut html, &report.audit.records_checked.to_string())?;
    html.push_str("</p><p>Audit head SHA-256: <code>");
    push_html_text(&mut html, &report.audit.head_sha256)?;
    html.push_str("</code></p><p class=\"muted\">");
    push_html_text(&mut html, report.audit.note)?;
    html.push_str("</p></section><section><h2>Scope and limitations</h2><p>");
    push_html_text(&mut html, report.scope_note)?;
    html.push_str("</p></section><details open><summary>Complete machine-readable report data (JSON)</summary><pre>");
    push_html_text(&mut html, &json)?;
    html.push_str("</pre></details></body></html>");
    if html.len() > MAX_REPORT_BYTES {
        return Err("The printable case report exceeds the 64 MiB export limit.".into());
    }
    Ok(html.into_bytes())
}

fn report_path_for_format(path: &Path, format: ReportFormat) -> Result<PathBuf> {
    let expected = format.extension();
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(actual) if actual.eq_ignore_ascii_case(expected) => Ok(path.to_path_buf()),
        Some(_) => Err(format!(
            "Choose a .{expected} filename for this report format."
        )),
        None => {
            let mut path = path.to_path_buf();
            path.set_extension(expected);
            Ok(path)
        }
    }
}

fn encode_report_for_format(report: &CaseReport, format: ReportFormat) -> Result<Vec<u8>> {
    match format {
        ReportFormat::Json => encode_report(report),
        ReportFormat::Html => encode_html_report(report),
    }
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

fn verify_published_report(path: &Path, expected_bytes: u64, expected_sha256: &str) -> Result<()> {
    let mut file = File::open(path).map_err(err)?;
    let initial_size = file.metadata().map_err(err)?.len();
    if initial_size != expected_bytes {
        return Err(format!(
            "The published report has {initial_size} bytes; expected {expected_bytes}."
        ));
    }

    let mut digest = Sha256::new();
    let mut total_read = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(err)?;
        if count == 0 {
            break;
        }
        total_read = total_read
            .checked_add(count as u64)
            .ok_or("Published report size overflow")?;
        digest.update(&buffer[..count]);
    }

    let final_size = file.metadata().map_err(err)?.len();
    if total_read != expected_bytes || final_size != expected_bytes {
        return Err(format!(
            "The published report changed size during read-back verification (read {total_read} bytes; final size {final_size})."
        ));
    }
    let actual_sha256 = format!("{:x}", digest.finalize());
    if actual_sha256 != expected_sha256 {
        return Err("The published report SHA-256 does not match the prepared report.".into());
    }
    Ok(())
}

fn audit_report_export_failure(
    db: &rusqlite::Connection,
    case_id: i64,
    format: ReportFormat,
    reason: &str,
) -> Result<()> {
    audit(
        db,
        "case_report_export_failed",
        &serde_json::json!({
            "case_id": case_id,
            "export_format": format.extension(),
            "reason": reason,
        })
        .to_string(),
    )
}

fn publish_case_report(
    db: &rusqlite::Connection,
    case_id: i64,
    report: &CaseReport,
    bytes: &[u8],
    path: &Path,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<CaseReportExport> {
    let export_format = path
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| {
            extension.eq_ignore_ascii_case("json") || extension.eq_ignore_ascii_case("html")
        })
        .ok_or("Case report destination must use a .json or .html extension.")?;
    if cancel.load(Ordering::SeqCst) {
        return Err("Case report export cancelled before staging.".into());
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    let staged = stage_report(path, bytes)?;
    if cancel.load(Ordering::SeqCst) {
        return Err("Case report export cancelled before publication.".into());
    }
    let imaging_and_raid_operations = report.imaging_and_raid_operations.len();
    let recovery_operations = report.recovery_operations.len();
    audit(
        db,
        "case_report_export_prepared",
        &serde_json::json!({
            "case_id": case_id,
            "export_format": export_format,
            "destination": path.to_string_lossy(),
            "sha256": digest,
            "bytes": bytes.len(),
            "scans": report.scans.len(),
            "candidates": report.scans.iter().map(|scan| scan.candidates.len()).sum::<usize>(),
            "fat32_scans": report.fat32_scans.len(),
            "directory_entries": report.fat32_scans.iter().map(|scan| scan.entries.len()).sum::<usize>(),
            "exfat_scans": report.exfat_scans.len(),
            "exfat_entries": report.exfat_scans.iter().map(|scan| scan.entries.len()).sum::<usize>(),
            "carve_scans": report.carve_scans.len(),
            "carved_candidates": report.carve_scans.iter().map(|scan| scan.candidates.len()).sum::<usize>(),
            "imaging_and_raid_operations": imaging_and_raid_operations,
            "recovery_operations": recovery_operations,
            "audit_head_in_report": report.audit.head_sha256,
        })
        .to_string(),
    )?;
    if cancel.load(Ordering::SeqCst) {
        return Err("Case report export cancelled before publication.".into());
    }
    destination::publish_new(&staged.0, path).map_err(|error| {
        format!(
            "The report was staged and audited but could not be published to {}: {error}",
            path.display()
        )
    })?;
    if let Err(error) = verify_published_report(path, bytes.len() as u64, &digest) {
        let audit_error = audit(
            db,
            "case_report_export_verification_failed",
            &serde_json::json!({
                "case_id": case_id,
                "export_format": export_format,
                "destination": path.to_string_lossy(),
                "expected_sha256": digest,
                "bytes": bytes.len(),
                "error": error,
            })
            .to_string(),
        )
        .err();
        return Err(match audit_error {
            Some(audit_error) => format!(
                "The report was published to {} but read-back verification failed; do not use it until verified: {error}. The failure could not be recorded in the audit log: {audit_error}",
                path.display()
            ),
            None => format!(
                "The report was published to {} but read-back verification failed; do not use it until verified: {error}",
                path.display()
            ),
        });
    }
    let published = CaseReportExport {
        case_id: report.case.id,
        path: path.to_string_lossy().into_owned(),
        sha256: digest,
        bytes: bytes.len() as u64,
        scans: report.scans.len(),
        candidates: report.scans.iter().map(|scan| scan.candidates.len()).sum(),
        fat32_scans: report.fat32_scans.len(),
        directory_entries: report
            .fat32_scans
            .iter()
            .map(|scan| scan.entries.len())
            .sum(),
        exfat_scans: report.exfat_scans.len(),
        exfat_entries: report
            .exfat_scans
            .iter()
            .map(|scan| scan.entries.len())
            .sum(),
        carve_scans: report.carve_scans.len(),
        carved_candidates: report
            .carve_scans
            .iter()
            .map(|scan| scan.candidates.len())
            .sum(),
        imaging_and_raid_operations,
        recovery_operations,
    };
    audit(
        db,
        "case_report_exported",
        &serde_json::json!({
            "case_id": case_id,
            "export_format": export_format,
            "destination": published.path,
            "sha256": published.sha256,
            "bytes": published.bytes,
            "scans": published.scans,
            "candidates": published.candidates,
            "fat32_scans": published.fat32_scans,
            "directory_entries": published.directory_entries,
            "exfat_scans": published.exfat_scans,
            "exfat_entries": published.exfat_entries,
            "carve_scans": published.carve_scans,
            "carved_candidates": published.carved_candidates,
            "imaging_and_raid_operations": published.imaging_and_raid_operations,
            "recovery_operations": published.recovery_operations,
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
    Ok(published)
}

#[tauri::command]
pub async fn export_case_report(
    case_id: i64,
    format: ReportFormat,
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
    let mut result: Result<Option<CaseReportExport>> = async {
        let destination = tauri::async_runtime::spawn_blocking(move || {
            let extension = format.extension();
            rfd::FileDialog::new()
                .set_title("Export forensic case report")
                .add_filter(format.filter_name(), &[extension])
                .set_file_name(format!("DaemonCore-Case-Report.{extension}"))
                .save_file()
        })
        .await
        .map_err(err)?;
        let Some(destination) = destination else {
            return Ok(None);
        };
        let destination = report_path_for_format(&destination, format)?;
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
            if state.cancel.load(Ordering::SeqCst) {
                return Err("Case report export cancelled during report generation.".into());
            }
            let bytes = encode_report_for_format(&report, format)?;
            if state.cancel.load(Ordering::SeqCst) {
                return Err("Case report export cancelled before staging.".into());
            }
            if let Ok(mut job) = state.job.lock() {
                job.message = Some("Staging the report and recording its digest".into());
                job.total = bytes.len() as u64;
            }
            let db = state.db.lock().map_err(err)?;
            publish_case_report(&db, case_id, &report, &bytes, &destination, &state.cancel)
        })
        .await
        .map_err(err)??;
        Ok(Some(exported))
    }
    .await;
    if matches!(&result, Ok(None)) || (state.cancel.load(Ordering::SeqCst) && result.is_err()) {
        let reason = match &result {
            Ok(None) => "Destination selection was cancelled.".to_owned(),
            Err(error) => error.chars().take(2048).collect(),
            Ok(Some(_)) => unreachable!(),
        };
        let audit_result = (|| -> Result<()> {
            let db = state.db.lock().map_err(err)?;
            audit(
                &db,
                "case_report_export_cancelled",
                &serde_json::json!({
                    "case_id": case_id,
                    "export_format": format.extension(),
                    "reason": reason,
                })
                .to_string(),
            )
        })();
        if let Err(error) = audit_result {
            result = Err(format!(
                "Case report export was cancelled, but the cancellation could not be recorded in the audit log: {error}"
            ));
        }
    } else if let Err(error) = &result {
        let reason = error.chars().take(2048).collect::<String>();
        let audit_result = (|| -> Result<()> {
            let db = state.db.lock().map_err(err)?;
            audit_report_export_failure(&db, case_id, format, &reason)
        })();
        if let Err(audit_error) = audit_result {
            result = Err(format!(
                "{reason} The failed report export could not be recorded in the audit log: {audit_error}"
            ));
        }
    }
    if let Ok(mut job) = state.job.lock() {
        match &result {
            Ok(Some(report)) => {
                job.state = "completed".into();
                job.message = Some(format!(
                    "Case report exported · {} NTFS scans · {} NTFS candidates · {} FAT32 scans · {} directory entries · {} carving scans · {} carved candidates · {} imaging/RAID events · {} recovery export/verification events",
                    report.scans, report.candidates, report.fat32_scans, report.directory_entries, report.carve_scans, report.carved_candidates, report.imaging_and_raid_operations, report.recovery_operations
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
    fn case_report_operation_query_ignores_unrelated_oversized_records() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE audit(id INTEGER PRIMARY KEY,timestamp TEXT,event TEXT,payload TEXT,hash TEXT);",
        )
        .unwrap();
        let unrelated_payload = serde_json::json!({
            "case_id": 2,
            "details": "x".repeat(MAX_OPERATION_PAYLOAD_BYTES + 1)
        })
        .to_string();
        db.execute(
            "INSERT INTO audit(timestamp,event,payload,hash) VALUES ('1','recovery_export_started',?1,'hash')",
            [&unrelated_payload],
        )
        .unwrap();

        let events = ["recovery_export_started"];
        let operations = case_operations(&db, 1, &events, "recovery").unwrap();
        assert!(operations.is_empty());

        let selected_payload = serde_json::json!({
            "case_id": 1,
            "details": "x".repeat(MAX_OPERATION_PAYLOAD_BYTES + 1)
        })
        .to_string();
        db.execute(
            "INSERT INTO audit(timestamp,event,payload,hash) VALUES ('2','recovery_export_started',?1,'hash')",
            [&selected_payload],
        )
        .unwrap();
        let error = match case_operations(&db, 1, &events, "recovery") {
            Ok(_) => panic!("oversized selected-case operation must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("too large to include safely"));
    }

    fn candidate() -> crate::ntfs::Candidate {
        crate::ntfs::Candidate {
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

    fn boot() -> crate::ntfs::Boot {
        crate::ntfs::Boot {
            offset: 0,
            sector_size: 512,
            cluster_size: 4096,
            record_size: 1024,
            volume_size: 2 * 1024 * 1024,
            mft_offset: 4096,
            serial: "fixture".into(),
        }
    }

    fn populated_case() -> rusqlite::Connection {
        let mut db = crate::database(PathBuf::from(":memory:")).unwrap();
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
        let source_sha256 = "b".repeat(64);
        db.execute(
            "INSERT INTO evidence_sources(id,case_id,original_path,name,size_bytes,filesystem,opened_at,sha256,status) VALUES (2,1,'evidence.img','evidence.img',4096,'NTFS','1',?1,'hashed')",
            [&source_sha256],
        )
        .unwrap();
        audit(
            &db,
            "image_opened",
            &serde_json::json!({"case_id":1,"evidence_record_id":2,"source_id":9,"path":"evidence.img","name":"evidence.img","size":4096,"filesystem":"NTFS","opened_at":"1"}).to_string(),
        )
        .unwrap();
        audit(
            &db,
            "hash_finished",
            &serde_json::json!({"case_id":1,"evidence_record_id":2,"source_id":9,"evidence_status":"hashed","persisted_sha256":source_sha256,"job":{"state":"completed"}}).to_string(),
        )
        .unwrap();
        let boot = boot();
        let candidates = [candidate()];
        crate::recovery_commands::persist_scan_snapshot(
            &mut db,
            &crate::recovery_commands::ScanSnapshot {
                evidence_id: 2,
                case_id: 1,
                source_id: 9,
                volume_offset: 0,
                source_sha256: &source_sha256,
                boot: &boot,
                records: 100,
                skipped: 3,
                limited: false,
                candidates: &candidates,
            },
        )
        .unwrap();
        db
    }

    #[test]
    fn report_scan_preflight_rejects_oversized_snapshot_payloads() {
        let db = populated_case();
        let error = check_report_scan_budget(&db, 1, 1).unwrap_err();
        assert!(error.contains("report preflight limit"));
    }

    #[test]
    fn report_scan_preflight_counts_all_scan_families_together() {
        let db = populated_case();
        let source_sha256 = "b".repeat(64);
        let snapshot_sha256 = "c".repeat(64);
        for id in 1..=MAX_REPORT_SCANS as i64 {
            db.execute(
                "INSERT INTO carve_scan_sessions(id,evidence_id,case_id,source_sha256,completed_at,scanned_bytes,candidates_json,snapshot_sha256,candidates_limited) VALUES (?1,2,1,?2,'12',4096,'[]',?3,0)",
                rusqlite::params![id, source_sha256, snapshot_sha256],
            )
            .unwrap();
        }
        let error = check_report_scan_budget(&db, 1, MAX_REPORT_BYTES as u64).unwrap_err();
        assert!(error.contains("200-scan report limit"));
    }

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
        let bytes = br#"{"format":"daemoncore-case-report-v4"}"#;
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
        let generated_at = report.generated_at_unix_ms.parse::<u128>().unwrap();
        let current_time = audit_timestamp(SystemTime::now())
            .unwrap()
            .parse::<u128>()
            .unwrap();
        assert!(generated_at <= current_time);
        assert!(current_time - generated_at < 10_000);
        assert!(report.evidence.is_empty());
        assert!(report.scans.is_empty());
        assert!(report.fat32_scans.is_empty());
        assert!(report.carve_scans.is_empty());
        assert!(report.imaging_and_raid_operations.is_empty());
        assert!(report.recovery_operations.is_empty());
        assert!(report.audit.chain_valid);
        assert!(!report.audit.externally_anchored);
        let bytes = encode_report(&report).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["format"], "daemoncore-case-report-v6");
        assert_eq!(report["audit"]["externally_anchored"], false);
        assert_eq!(report["case"]["title"], "Case 1");
        db.execute("UPDATE audit SET payload='tampered' WHERE id=1", [])
            .unwrap();
        assert!(case_report_from(&db, 1).is_err());
    }

    #[test]
    fn printable_html_report_escapes_case_data_and_keeps_full_json_appendix() {
        let db = crate::database(PathBuf::from(":memory:")).unwrap();
        let title = "<img src=x onerror=alert(1)> & \"case\"";
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,?1,'Examiner')",
            [title],
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
            &serde_json::json!({"id":1,"title":title,"examiner":"Examiner","selected":true})
                .to_string(),
        )
        .unwrap();
        let report = case_report_from(&db, 1).unwrap();
        let html = String::from_utf8(encode_html_report(&report).unwrap()).unwrap();

        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt; &amp; &quot;case&quot;"));
        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(html.contains("default-src 'none'; style-src 'unsafe-inline'"));
        assert!(html.contains("Complete machine-readable report data (JSON)"));
        assert!(html.contains("&quot;title&quot;: &quot;&lt;img src=x onerror=alert(1)&gt;"));
        assert!(encode_report_for_format(&report, ReportFormat::Html).is_ok());
        assert!(encode_report_for_format(&report, ReportFormat::Json).is_ok());
        assert_eq!(
            report_path_for_format(Path::new("case"), ReportFormat::Json).unwrap(),
            PathBuf::from("case.json")
        );
        assert_eq!(
            report_path_for_format(Path::new("case.HTML"), ReportFormat::Html).unwrap(),
            PathBuf::from("case.HTML")
        );
        assert!(report_path_for_format(Path::new("case.pdf"), ReportFormat::Json).is_err());
        assert!(matches!(
            serde_json::from_str::<ReportFormat>("\"html\""),
            Ok(ReportFormat::Html)
        ));
    }

    #[test]
    fn published_report_readback_rejects_changed_destination_bytes() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "daemoncore-case-report-readback-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir(&root).unwrap();
        let path = root.join("case-report.json");
        let expected = br#"{"format":"daemoncore-case-report-v6"}"#;
        let expected_sha256 = format!("{:x}", Sha256::digest(expected));

        fs::write(&path, expected).unwrap();
        verify_published_report(&path, expected.len() as u64, &expected_sha256).unwrap();

        let mut changed = expected.to_vec();
        changed[0] ^= 1;
        fs::write(&path, changed).unwrap();
        let error =
            verify_published_report(&path, expected.len() as u64, &expected_sha256).unwrap_err();
        assert!(error.contains("SHA-256 does not match"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn populated_case_report_exports_verified_scan_and_audits_published_hash() {
        let db = populated_case();
        let report = case_report_from(&db, 1).unwrap();
        let source_sha256 = "b".repeat(64);
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].sha256.as_deref(),
            Some(source_sha256.as_str())
        );
        assert_eq!(report.scans.len(), 1);
        assert_eq!(report.scans[0].candidates.len(), 1);
        assert_eq!(report.scans[0].candidates[0].name, "recovered.bin");
        assert_eq!(report.scans[0].source_sha256, source_sha256);
        assert!(report.scans[0].evidence_hash_matches_current_record);

        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "daemoncore-case-report-export-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir(&root).unwrap();
        let path = root.join("case-report.json");
        let bytes = encode_report(&report).unwrap();
        let expected_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let exported = publish_case_report(
            &db,
            1,
            &report,
            &bytes,
            &path,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(exported.case_id, 1);
        assert_eq!(exported.sha256, expected_sha256);
        assert_eq!(exported.scans, 1);
        assert_eq!(exported.candidates, 1);
        assert_eq!(exported.fat32_scans, 0);
        assert_eq!(exported.directory_entries, 0);
        assert_eq!(exported.carve_scans, 0);
        assert_eq!(exported.carved_candidates, 0);
        assert_eq!(exported.imaging_and_raid_operations, 0);
        assert_eq!(exported.recovery_operations, 0);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let (prepared, completed): (String, String) = db
            .query_row(
                "SELECT (SELECT payload FROM audit WHERE event='case_report_export_prepared'),(SELECT payload FROM audit WHERE event='case_report_exported')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let prepared: serde_json::Value = serde_json::from_str(&prepared).unwrap();
        let completed: serde_json::Value = serde_json::from_str(&completed).unwrap();
        assert_eq!(prepared["sha256"], expected_sha256);
        assert_eq!(completed["sha256"], expected_sha256);
        assert_eq!(prepared["export_format"], "json");
        assert_eq!(completed["export_format"], "json");
        assert_eq!(completed["scans"], 1);
        assert_eq!(completed["candidates"], 1);
        assert_eq!(completed["fat32_scans"], 0);
        assert_eq!(completed["carve_scans"], 0);
        assert_eq!(completed["carved_candidates"], 0);
        let collision = match publish_case_report(
            &db,
            1,
            &report,
            &bytes,
            &path,
            &std::sync::atomic::AtomicBool::new(false),
        ) {
            Ok(_) => panic!("existing report destination was replaced"),
            Err(error) => error,
        };
        assert!(collision.contains("could not be published"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let (prepared_count, completed_count): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*) FILTER (WHERE event='case_report_export_prepared'),COUNT(*) FILTER (WHERE event='case_report_exported') FROM audit",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(prepared_count, 2);
        assert_eq!(completed_count, 1);
        assert!(crate::verify_audit_chain(&db).unwrap().valid);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_report_export_records_the_selected_format_and_reason() {
        let db = populated_case();
        audit_report_export_failure(&db, 1, ReportFormat::Html, "extension mismatch").unwrap();

        let payload: String = db
            .query_row(
                "SELECT payload FROM audit WHERE event='case_report_export_failed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["case_id"], 1);
        assert_eq!(payload["export_format"], "html");
        assert_eq!(payload["reason"], "extension mismatch");
    }

    #[test]
    fn cancelled_case_report_is_not_staged_or_published() {
        let db = populated_case();
        let report = case_report_from(&db, 1).unwrap();
        let bytes = encode_report(&report).unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "daemoncore-case-report-cancel-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir(&root).unwrap();
        let path = root.join("case-report.json");
        let cancel = std::sync::atomic::AtomicBool::new(true);

        let error = publish_case_report(&db, 1, &report, &bytes, &path, &cancel)
            .err()
            .expect("cancelled report must not publish");

        assert!(error.contains("cancelled before staging"));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let prepared: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE event='case_report_export_prepared'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prepared, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn case_report_includes_integrity_checked_png_carving_snapshot() {
        let db = populated_case();
        let source_sha256 = "b".repeat(64);
        let candidate = crate::carving::CarvedCandidate {
            id: 128,
            offset: 128,
            length: 72,
            format: "PNG".into(),
            sha256: "c".repeat(64),
            validation: "PNG chunks and CRCs valid; image decoded".into(),
        };
        let candidates_json = serde_json::to_string(&[candidate]).unwrap();
        let snapshot_sha256 =
            crate::carving::snapshot_digest(&source_sha256, 4096, false, &candidates_json);
        db.execute(
            "INSERT INTO carve_scan_sessions(id,evidence_id,case_id,source_sha256,completed_at,scanned_bytes,candidates_json,snapshot_sha256,candidates_limited) VALUES (1,2,1,?1,'12',4096,?2,?3,0)",
            rusqlite::params![source_sha256,candidates_json,snapshot_sha256],
        )
        .unwrap();
        audit(
            &db,
            "carve_scan_persisted",
            &serde_json::json!({"case_id":1,"evidence_record_id":2,"source_id":9,"scan_session_id":1,"source_path":"evidence.img","source_sha256":source_sha256,"scanned_bytes":4096,"format":"PNG","candidates":1,"candidates_limited":false,"snapshot_sha256":snapshot_sha256}).to_string(),
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.carve_scans.len(), 1);
        assert_eq!(report.carve_scans[0].id, 1);
        assert!(report.carve_scans[0].evidence_hash_matches_current_record);
        assert_eq!(report.carve_scans[0].candidates.len(), 1);
        assert_eq!(report.carve_scans[0].candidates[0].offset, 128);
        let encoded: serde_json::Value =
            serde_json::from_slice(&encode_report(&report).unwrap()).unwrap();
        assert_eq!(encoded["format"], "daemoncore-case-report-v6");
        assert_eq!(encoded["carve_scans"][0]["candidates"][0]["format"], "PNG");
    }

    #[test]
    fn case_report_includes_audited_fat32_directory_snapshot() {
        let mut db = populated_case();
        let mut raw_record = [0; 32];
        raw_record[0] = 0xe5;
        raw_record[11] = 0x20;
        let entries = [daemoncore_ntfs_core::fat32::TreeEntry {
            path: vec!["?ILE.TXT".into()],
            entry: daemoncore_ntfs_core::fat32::DirectoryEntry {
                source_offset: 540_672,
                raw_record,
                short_name: *b"?ILE    TXT",
                long_name: None,
                deleted_long_name_lead: None,
                deleted: true,
                attributes: 0x20,
                first_cluster: 10,
                size: 512,
            },
        }];
        let boot = serde_json::json!({
            "primary_sector_hex": "00",
            "backup_sector_hex": null,
            "volume_offset": 0,
            "cluster_count": 65_525,
            "root_cluster": 2,
        });
        crate::fat32_commands::persist_scan_snapshot(
            &mut db,
            &crate::fat32_commands::ScanSnapshot {
                evidence_id: 2,
                case_id: 1,
                source_id: 9,
                volume_offset: 0,
                source_sha256: &"b".repeat(64),
                boot: &boot,
                entries: &entries,
            },
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.fat32_scans.len(), 1);
        assert_eq!(report.fat32_scans[0].deleted, 1);
        assert_eq!(
            report.fat32_scans[0].entries[0].entry.source_offset,
            540_672
        );
        assert!(report.fat32_scans[0].evidence_hash_matches_current_record);
        let encoded = encode_report(&report).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(json["format"], "daemoncore-case-report-v6");
        assert_eq!(
            json["fat32_scans"][0]["entries"][0]["entry"]["deleted"],
            true
        );
    }

    #[test]
    fn case_report_includes_audited_exfat_directory_inventory() {
        let db = populated_case();
        let entries = vec![daemoncore_ntfs_core::exfat::TreeEntry {
            path: vec!["ROOT.TXT".into()],
            entry: daemoncore_ntfs_core::exfat::DirectoryEntry {
                source_offset: 20_544,
                raw_entries: vec![[0x85; 32], [0xc0; 32], [0xc1; 32]],
                name: "ROOT.TXT".into(),
                deleted: false,
                attributes: 0x20,
                first_cluster: 0,
                valid_data_length: 0,
                data_length: 0,
                no_fat_chain: false,
                name_hash: 0x1234,
            },
        }];
        let boot = serde_json::json!({
            "volume_offset": 0,
            "bytes_per_sector": 512,
            "cluster_count": 2008,
            "root_cluster": 2,
            "source_path": "evidence.img"
        });
        let boot_json = serde_json::to_string(&boot).unwrap();
        let entries_json = serde_json::to_string(&entries).unwrap();
        let source_sha256 = "b".repeat(64);
        let snapshot_sha256 =
            crate::exfat_commands::snapshot_digest(&source_sha256, &boot_json, &entries_json);
        db.execute(
            "INSERT INTO exfat_scan_sessions(id,evidence_id,case_id,volume_offset,source_sha256,completed_at,boot_json,entries_json,snapshot_sha256) VALUES (1,2,1,'0',?1,'12',?2,?3,?4)",
            rusqlite::params![source_sha256, boot_json, entries_json, snapshot_sha256],
        )
        .unwrap();
        audit(
            &db,
            "exfat_scan_persisted",
            &serde_json::json!({"case_id":1,"evidence_id":2,"source_id":9,"scan_session_id":1,"volume_offset":0,"source_sha256":source_sha256,"records":1,"snapshot_sha256":snapshot_sha256}).to_string(),
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.exfat_scans.len(), 1);
        assert_eq!(report.exfat_scans[0].entries[0].entry.name, "ROOT.TXT");
        assert!(report.exfat_scans[0].evidence_hash_matches_current_record);
        let encoded: serde_json::Value =
            serde_json::from_slice(&encode_report(&report).unwrap()).unwrap();
        assert_eq!(encoded["format"], "daemoncore-case-report-v6");
        assert_eq!(
            encoded["exfat_scans"][0]["entries"][0]["entry"]["name"],
            "ROOT.TXT"
        );
    }

    #[test]
    fn case_report_includes_only_hash_chained_imaging_and_raid_events_for_its_case() {
        let db = populated_case();
        audit(
            &db,
            "physical_device_acquisition_published",
            &serde_json::json!({
                "case_id":1,
                "device_number":7,
                "image_sha256":"d".repeat(64),
                "outcome":"complete"
            })
            .to_string(),
        )
        .unwrap();
        audit(
            &db,
            "physical_device_acquisition_cancelled",
            &serde_json::json!({"case_id":1,"device_number":7}).to_string(),
        )
        .unwrap();
        audit(
            &db,
            "physical_device_acquisition_finalization_failed",
            &serde_json::json!({"case_id":1,"device_number":7,"stage":"case_registration"})
                .to_string(),
        )
        .unwrap();
        audit(
            &db,
            "raid_reconstruction_started",
            &serde_json::json!({
                "case_id":1,
                "level":"RAID 0",
                "member_order_is_operator_supplied":true
            })
            .to_string(),
        )
        .unwrap();
        audit(
            &db,
            "raid_package_verified",
            &serde_json::json!({"case_id":2,"package_type":"raid_reconstruction"}).to_string(),
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.imaging_and_raid_operations.len(), 4);
        assert_eq!(
            report.imaging_and_raid_operations[0].event,
            "physical_device_acquisition_published"
        );
        assert_eq!(
            report.imaging_and_raid_operations[1].event,
            "physical_device_acquisition_cancelled"
        );
        assert_eq!(
            report.imaging_and_raid_operations[2].event,
            "physical_device_acquisition_finalization_failed"
        );
        assert_eq!(
            report.imaging_and_raid_operations[3].event,
            "raid_reconstruction_started"
        );
        let json: serde_json::Value =
            serde_json::from_slice(&encode_report(&report).unwrap()).unwrap();
        assert_eq!(json["format"], "daemoncore-case-report-v6");
        assert_eq!(
            json["imaging_and_raid_operations"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            json["imaging_and_raid_operations"][0]["payload"]["image_sha256"],
            "d".repeat(64)
        );
    }

    #[test]
    fn case_report_includes_recovery_export_events_only_for_its_case() {
        let db = populated_case();
        audit(
            &db,
            "recovery_export_finished",
            &serde_json::json!({
                "case_id": 1,
                "source_sha256": "b".repeat(64),
                "job": {"state":"completed","output_directory":"D:/case/recovery"}
            })
            .to_string(),
        )
        .unwrap();
        audit(
            &db,
            "fat32_recovery_export_finished",
            &serde_json::json!({
                "case_id": 2,
                "source_sha256": "c".repeat(64),
                "job": {"state":"completed","output_directory":"D:/other/recovery"}
            })
            .to_string(),
        )
        .unwrap();
        audit(
            &db,
            "carve_export_finished",
            &serde_json::json!({
                "case_id": 1,
                "source_sha256": "b".repeat(64),
                "summary": {"state":"complete","directory":"D:/case/carved"}
            })
            .to_string(),
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(report.recovery_operations.len(), 2);
        assert_eq!(
            report.recovery_operations[0].event,
            "recovery_export_finished"
        );
        assert_eq!(report.recovery_operations[1].event, "carve_export_finished");
        let json: serde_json::Value =
            serde_json::from_slice(&encode_report(&report).unwrap()).unwrap();
        assert_eq!(json["format"], "daemoncore-case-report-v6");
        assert_eq!(json["recovery_operations"].as_array().unwrap().len(), 2);
        assert_eq!(
            json["recovery_operations"][0]["record_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn report_discloses_when_current_evidence_hash_differs_from_scan_source() {
        let db = populated_case();
        let changed_sha256 = "c".repeat(64);
        db.execute(
            "UPDATE evidence_sources SET sha256=?1,status='hashed' WHERE id=2 AND case_id=1",
            [&changed_sha256],
        )
        .unwrap();
        audit(
            &db,
            "hash_finished",
            &serde_json::json!({"case_id":1,"evidence_record_id":2,"source_id":9,"evidence_status":"hashed","persisted_sha256":changed_sha256,"job":{"state":"completed"}}).to_string(),
        )
        .unwrap();

        let report = case_report_from(&db, 1).unwrap();
        assert_eq!(
            report.evidence[0].sha256.as_deref(),
            Some(changed_sha256.as_str())
        );
        assert_eq!(report.scans[0].source_sha256, "b".repeat(64));
        assert!(!report.scans[0].evidence_hash_matches_current_record);
    }
}
