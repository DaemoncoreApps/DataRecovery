use daemoncore_ntfs_core::{ntfs, partition, storage::BlockSource};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tauri::{Manager, State};
mod acquisition;
mod audit_export;
mod carving;
mod case_report;
mod destination;
mod exfat_commands;
mod fat32_commands;
#[cfg(test)]
mod ntfs_tests;
mod raid;
mod recovery;
mod recovery_commands;
mod recovery_verify;
mod safe_file;
mod storage;

#[derive(Serialize, Clone)]
struct Source {
    id: u64,
    case_id: i64,
    evidence_record_id: i64,
    name: String,
    size: u64,
    filesystem: String,
    sha256: Option<String>,
}
struct Evidence {
    image: Arc<storage::Image>,
    info: Source,
    integrity_compromised: bool,
}
struct ScanSession {
    case_id: i64,
    evidence_record_id: i64,
    persistent_id: i64,
    source_id: u64,
    source_sha256: String,
    source: Arc<storage::Image>,
    result: ntfs::ScanResult,
}
struct CarveScanSession {
    case_id: i64,
    evidence_record_id: i64,
    persistent_id: i64,
    source_id: u64,
    source_sha256: String,
    scanned_bytes: u64,
    candidates_limited: bool,
    candidates: Vec<carving::CarvedCandidate>,
}
#[derive(Serialize, Clone)]
struct Job {
    state: String,
    kind: String,
    processed: u64,
    total: u64,
    discovered: usize,
    sha256: Option<String>,
    error: Option<String>,
    message: Option<String>,
    output_directory: Option<String>,
}
impl Default for Job {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            kind: "hash".into(),
            processed: 0,
            total: 0,
            discovered: 0,
            sha256: None,
            error: None,
            message: None,
            output_directory: None,
        }
    }
}
struct AppState {
    source: Mutex<Option<Evidence>>,
    db: Mutex<Connection>,
    job: Mutex<Job>,
    cancel: AtomicBool,
    scan: Mutex<Option<Arc<ScanSession>>>,
    carve_scan: Mutex<Option<Arc<CarveScanSession>>>,
    fat32_scan: Mutex<Option<Arc<fat32_commands::Fat32ScanCache>>>,
    exfat_scan: Mutex<Option<Arc<exfat_commands::ExfatScanCache>>>,
    generation: AtomicU64,
}
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn guarded<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or_else(|_| Err("The native operation failed unexpectedly. Partial outputs must not be treated as verified.".into()))
}
fn detect(bytes: &[u8]) -> String {
    match bytes.get(3..11) {
        Some(b"NTFS    ") => "NTFS volume (metadata scan available)",
        Some(b"EXFAT   ") => "exFAT volume (live directory analysis available)",
        Some(b"-FVE-FS-") => "BitLocker signature (locked)",
        _ if bytes.get(82..90) == Some(b"FAT32   ") => {
            "FAT32 boot signature (recovery unavailable)"
        }
        _ => "Unknown / partitioned image",
    }
    .into()
}
#[tauri::command]
async fn open_image(state: State<'_, AppState>) -> Result<Option<Source>> {
    let path = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Raw disk image", &["img", "dd", "raw", "bin"])
            .pick_file()
    })
    .await
    .map_err(err)?;
    let Some(path) = path else { return Ok(None) };
    let mut current = state.source.lock().map_err(err)?;
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Cancel the active operation before changing sources.".into());
    }
    let db = state.db.lock().map_err(err)?;
    let case_id = require_audited_active_case(&db)?;
    drop(db);
    let image = Arc::new(storage::Image::open(&path).map_err(err)?);
    let mut boot = vec![0; image.len().min(512) as usize];
    image.read_exact_at(0, &mut boot).map_err(err)?;
    let mut db = state.db.lock().map_err(err)?;
    let id = state.generation.fetch_add(1, Ordering::SeqCst);
    let size = image.len();
    let path_text = path.to_string_lossy().into_owned();
    let filesystem = detect(&boot);
    let opened_at = audit_timestamp(std::time::SystemTime::now())?;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let evidence_record_id = record_evidence_open(
        &mut db,
        &EvidenceRegistration {
            case_id,
            source_id: id,
            path: &path_text,
            name: &name,
            size,
            filesystem: &filesystem,
            opened_at: &opened_at,
        },
    )?;
    let info = Source {
        id,
        case_id,
        evidence_record_id,
        name,
        size,
        filesystem,
        sha256: None,
    };
    *current = Some(Evidence {
        image,
        info: info.clone(),
        integrity_compromised: false,
    });
    *state.scan.lock().map_err(err)? = None;
    *state.carve_scan.lock().map_err(err)? = None;
    *state.fat32_scan.lock().map_err(err)? = None;
    *state.exfat_scan.lock().map_err(err)? = None;
    *job = Job::default();
    Ok(Some(info))
}

fn persist_carve_scan(
    db: &mut Connection,
    case_id: i64,
    evidence_record_id: i64,
    source_id: u64,
    source_path: &str,
    source_sha256: &str,
    result: &carving::CarvingResult,
) -> Result<i64> {
    let candidates_json = serde_json::to_string(&result.candidates).map_err(err)?;
    if candidates_json.len() > 48 * 1024 * 1024 {
        return Err("Validated carving results exceed the 48 MiB case snapshot limit.".into());
    }
    let snapshot_sha256 = carving::snapshot_digest(
        source_sha256,
        result.scanned_bytes,
        result.candidates_limited,
        &candidates_json,
    );
    let completed_at = audit_timestamp(std::time::SystemTime::now())?;
    let tx = db.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO carve_scan_sessions(evidence_id,case_id,source_sha256,completed_at,scanned_bytes,candidates_json,snapshot_sha256,candidates_limited) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![evidence_record_id,case_id,source_sha256,completed_at,result.scanned_bytes,candidates_json,snapshot_sha256,if result.candidates_limited { 1i64 } else { 0i64 }],
    )
    .map_err(err)?;
    let persistent_id = tx.last_insert_rowid();
    audit(
        &tx,
        "carve_scan_persisted",
        &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"scan_session_id":persistent_id,"source_path":source_path,"source_sha256":source_sha256,"scanned_bytes":result.scanned_bytes,"formats":carving::SUPPORTED_FORMATS,"candidates":result.candidates.len(),"candidates_limited":result.candidates_limited,"snapshot_sha256":snapshot_sha256}).to_string(),
    )?;
    tx.commit().map_err(err)?;
    Ok(persistent_id)
}

#[tauri::command]
fn start_file_carving(app: tauri::AppHandle, state: State<AppState>) -> Result<()> {
    let (source, source_id, evidence_record_id, case_id, expected_sha256, source_path) = {
        let current = state.source.lock().map_err(err)?;
        let evidence = current.as_ref().ok_or("Open an evidence image first.")?;
        if evidence.integrity_compromised {
            return Err(
                "The source integrity is compromised. Reopen a verified working copy.".into(),
            );
        }
        let expected_sha256 = evidence
            .info
            .sha256
            .clone()
            .ok_or("Calculate and record the source SHA-256 before carving.")?;
        evidence.image.verify_unchanged().map_err(err)?;
        (
            evidence.image.clone(),
            evidence.info.id,
            evidence.info.evidence_record_id,
            evidence.info.case_id,
            expected_sha256,
            evidence.image.path.to_string_lossy().into_owned(),
        )
    };
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Wait for the active operation before starting file carving.".into());
    }
    {
        let db = state.db.lock().map_err(err)?;
        if require_audited_active_case(&db)? != case_id {
            return Err("Select the evidence image's audited case before carving.".into());
        }
        audit(
            &db,
            "carve_scan_started",
            &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"source_sha256":expected_sha256,"size":source.len(),"formats":carving::SUPPORTED_FORMATS}).to_string(),
        )?;
    }
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "carving_scan".into(),
        total: source.len(),
        message: Some(format!(
            "Scanning the complete hashed image for structurally valid {} files",
            carving::SUPPORTED_FORMATS.join(", ")
        )),
        ..Job::default()
    };
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = guarded(|| {
            let Some(scan) = carving::scan_supported_files(
                source.as_ref(),
                &state.cancel,
                |processed, found| {
                    if let Ok(mut job) = state.job.lock() {
                        job.processed = processed;
                        job.discovered = found;
                    }
                },
            )?
            else {
                return Ok(None);
            };
            if source.verify_unchanged().is_err() || scan.source_sha256 != expected_sha256 {
                if let Ok(mut current) = state.source.lock() {
                    if let Some(active) = current.as_mut().filter(|item| item.info.id == source_id)
                    {
                        active.integrity_compromised = true;
                        active.info.sha256 = None;
                    }
                }
                let mut db = state.db.lock().map_err(err)?;
                let tx = db.transaction().map_err(err)?;
                tx.execute(
                    "UPDATE evidence_sources SET sha256=NULL,status='compromised' WHERE id=?1 AND case_id=?2",
                    params![evidence_record_id, case_id],
                )
                .map_err(err)?;
                audit(
                    &tx,
                    "carve_source_integrity_failed",
                    &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"expected_sha256":expected_sha256,"observed_sha256":scan.source_sha256}).to_string(),
                )?;
                tx.commit().map_err(err)?;
                return Err("The source no longer matches its recorded SHA-256. It was marked compromised and carving results were discarded.".into());
            }
            let mut db = state.db.lock().map_err(err)?;
            let persistent_id = persist_carve_scan(
                &mut db,
                case_id,
                evidence_record_id,
                source_id,
                &source_path,
                &expected_sha256,
                &scan,
            )?;
            drop(db);
            *state.carve_scan.lock().map_err(err)? = Some(Arc::new(CarveScanSession {
                case_id,
                evidence_record_id,
                persistent_id,
                source_id,
                source_sha256: expected_sha256.clone(),
                scanned_bytes: scan.scanned_bytes,
                candidates_limited: scan.candidates_limited,
                candidates: scan.candidates,
            }));
            Ok(Some(persistent_id))
        });
        match result {
            Ok(Some(_)) => {
                if let Ok(mut job) = state.job.lock() {
                    job.state = "completed".into();
                    job.processed = job.total;
                    job.message = Some("File carve scan complete. PNG passed CRC and decode checks; BMP and JPEG candidates passed bounded pixel decoding. Original names and allocation are unknown.".into());
                }
            }
            Ok(None) => {
                let processed = state.job.lock().map(|job| job.processed).unwrap_or(0);
                if let Ok(db) = state.db.lock() {
                    let _ = audit(
                        &db,
                        "carve_scan_cancelled",
                        &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"processed":processed}).to_string(),
                    );
                }
                if let Ok(mut job) = state.job.lock() {
                    job.state = "cancelled".into();
                    job.message =
                        Some("Carving was cancelled. No partial candidate set was saved.".into());
                }
            }
            Err(error) => {
                if let Ok(db) = state.db.lock() {
                    let _ = audit(
                        &db,
                        "carve_scan_failed",
                        &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"error":error}).to_string(),
                    );
                }
                if let Ok(mut job) = state.job.lock() {
                    job.state = "failed".into();
                    job.error = Some(error);
                }
            }
        }
    });
    Ok(())
}

#[derive(Serialize)]
struct CarvePage {
    scan_session_id: i64,
    total: usize,
    scanned_bytes: u64,
    source_sha256: String,
    candidates_limited: bool,
    rows: Vec<carving::CarvedCandidate>,
}

#[tauri::command]
fn carve_results(
    source_id: u64,
    offset: usize,
    limit: usize,
    state: State<AppState>,
) -> Result<CarvePage> {
    if limit == 0 || limit > 200 {
        return Err("Invalid carving results page size.".into());
    }
    let session = state
        .carve_scan
        .lock()
        .map_err(err)?
        .as_ref()
        .ok_or("Run file carving on the current source first.")?
        .clone();
    if session.source_id != source_id {
        return Err("These carving results belong to another source.".into());
    }
    let mut current = state.source.lock().map_err(err)?;
    let evidence = current.as_mut().ok_or("Open the source image first.")?;
    if evidence.integrity_compromised
        || evidence.info.id != source_id
        || evidence.info.sha256.as_deref() != Some(session.source_sha256.as_str())
    {
        return Err("The active source no longer matches the completed carving scan.".into());
    }
    if let Err(error) = evidence.image.verify_unchanged() {
        evidence.integrity_compromised = true;
        evidence.info.sha256 = None;
        let mut db = state.db.lock().map_err(err)?;
        let tx = db.transaction().map_err(err)?;
        tx.execute(
            "UPDATE evidence_sources SET sha256=NULL,status='compromised' WHERE id=?1 AND case_id=?2",
            params![evidence.info.evidence_record_id,evidence.info.case_id],
        )
        .map_err(err)?;
        audit(
            &tx,
            "carve_results_source_integrity_failed",
            &serde_json::json!({"case_id":evidence.info.case_id,"evidence_record_id":evidence.info.evidence_record_id,"source_id":source_id,"error":error.to_string()}).to_string(),
        )?;
        tx.commit().map_err(err)?;
        return Err("The source changed after carving. Its evidence record was marked compromised; reopen a verified working copy.".into());
    }
    Ok(CarvePage {
        scan_session_id: session.persistent_id,
        total: session.candidates.len(),
        scanned_bytes: session.scanned_bytes,
        source_sha256: session.source_sha256.clone(),
        candidates_limited: session.candidates_limited,
        rows: session
            .candidates
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect(),
    })
}

#[tauri::command]
async fn export_carved_selected(
    source_id: u64,
    ids: Vec<u64>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool> {
    if ids.is_empty() || ids.len() > 1_000 {
        return Err("Select between 1 and 1,000 validated carved candidates.".into());
    }
    let session = state
        .carve_scan
        .lock()
        .map_err(err)?
        .as_ref()
        .ok_or("Run file carving on the current source first.")?
        .clone();
    if session.source_id != source_id {
        return Err("The carving scan belongs to another image.".into());
    }
    let unique = ids.into_iter().collect::<std::collections::BTreeSet<_>>();
    if unique.is_empty() || unique.len() > 1_000 {
        return Err("The carving selection is empty or too large.".into());
    }
    let selected = unique
        .into_iter()
        .map(|id| {
            session
                .candidates
                .iter()
                .find(|candidate| candidate.id == id)
                .cloned()
                .ok_or_else(|| "A selected carving candidate is not in this scan.".to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    let source = {
        let current = state.source.lock().map_err(err)?;
        let evidence = current.as_ref().ok_or("Open the source image first.")?;
        if evidence.integrity_compromised
            || evidence.info.id != source_id
            || evidence.info.sha256.as_deref() != Some(session.source_sha256.as_str())
        {
            return Err("The source no longer matches the completed carving scan.".into());
        }
        evidence.image.clone()
    };
    let required = selected
        .iter()
        .try_fold(1024 * 1024u64, |total, candidate| {
            total.checked_add(candidate.length.checked_mul(2)?)
        })
        .ok_or("Carving package size overflow.")?;
    if state.job.lock().map_err(err)?.state == "running" {
        return Err("Wait for the active operation before exporting carved files.".into());
    }
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Export carved files to a different physical disk")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(false);
    };
    let image_path = source.path.clone();
    let destination_result = tauri::async_runtime::spawn_blocking(move || {
        destination::check_destination(&image_path, &folder, required)
    })
    .await
    .map_err(err)?;
    let destination = match destination_result {
        Ok(path) => path,
        Err(reason) => {
            audit(
                &*state.db.lock().map_err(err)?,
                "carve_export_rejected",
                &serde_json::json!({"case_id":session.case_id,"source_id":source_id,"reason":reason}).to_string(),
            )?;
            return Err(reason);
        }
    };
    let current_source = state.source.lock().map_err(err)?;
    let evidence = current_source
        .as_ref()
        .ok_or("Open the source image first.")?;
    if evidence.integrity_compromised
        || evidence.info.id != source_id
        || evidence.info.evidence_record_id != session.evidence_record_id
        || evidence.info.sha256.as_deref() != Some(session.source_sha256.as_str())
    {
        return Err("The active evidence changed while choosing the export destination.".into());
    }
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("Another operation started while selecting an export destination.".into());
    }
    source.verify_unchanged().map_err(err)?;
    let selected_offsets = selected
        .iter()
        .map(|candidate| candidate.offset)
        .collect::<Vec<_>>();
    let db = state.db.lock().map_err(err)?;
    if require_audited_active_case(&db)? != session.case_id {
        return Err("The active case changed while choosing the export destination.".into());
    }
    audit(
        &db,
        "carve_export_started",
        &serde_json::json!({"case_id":session.case_id,"evidence_record_id":session.evidence_record_id,"scan_session_id":session.persistent_id,"source_id":source_id,"source_sha256":session.source_sha256,"selected_offsets":selected_offsets,"destination":destination}).to_string(),
    )?;
    drop(db);
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        kind: "carving_export".into(),
        total: source.len().saturating_mul(2).saturating_add(
            selected
                .iter()
                .map(|candidate| candidate.length.saturating_mul(2))
                .sum::<u64>(),
        ),
        message: Some(
            "Rechecking the source, extracting selected carved files, and verifying every output hash"
                .into(),
        ),
        ..Job::default()
    };
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let source_path = source.path.to_string_lossy().into_owned();
        let result = guarded(|| {
            carving::export_selected(
                source.as_ref(),
                &selected,
                &destination,
                carving::ExportIdentity {
                    case_id: session.case_id,
                    evidence_record_id: session.evidence_record_id,
                    scan_session_id: session.persistent_id,
                    source_id,
                    source_path: &source_path,
                    source_sha256: &session.source_sha256,
                },
                &state.cancel,
                |processed, total| {
                    if let Ok(mut job) = state.job.lock() {
                        job.processed = processed;
                        job.total = total;
                    }
                },
            )
        });
        match result {
            Ok(summary) => {
                let persisted = state.db.lock().map_err(err).and_then(|db| {
                    audit(
                        &db,
                        "carve_export_finished",
                        &serde_json::json!({"case_id":session.case_id,"evidence_record_id":session.evidence_record_id,"scan_session_id":session.persistent_id,"source_id":source_id,"source_sha256":session.source_sha256,"summary":summary}).to_string(),
                    )
                });
                if let Ok(mut job) = state.job.lock() {
                    job.state = if persisted.is_err() {
                        "failed"
                    } else if summary.cancelled {
                        "cancelled"
                    } else {
                        "completed"
                    }
                    .into();
                    if let Err(error) = persisted {
                        job.error = Some(error);
                    }
                    job.processed = job.total;
                    job.discovered = summary.exported;
                    job.output_directory = Some(summary.directory);
                    job.message = Some(format!(
                        "{} files exported; {} failed{}",
                        summary.exported,
                        summary.failed,
                        if summary.cancelled {
                            "; export cancelled"
                        } else {
                            ""
                        }
                    ));
                }
            }
            Err(error) => {
                if let Ok(db) = state.db.lock() {
                    let _ = audit(&db, "carve_export_failed", &serde_json::json!({"case_id":session.case_id,"evidence_record_id":session.evidence_record_id,"scan_session_id":session.persistent_id,"source_id":source_id,"error":error}).to_string());
                }
                if let Ok(mut job) = state.job.lock() {
                    job.state = if state.cancel.load(Ordering::SeqCst) {
                        "cancelled"
                    } else {
                        "failed"
                    }
                    .into();
                    job.error = Some(error);
                }
            }
        }
    });
    Ok(true)
}
#[tauri::command]
fn read_hex(offset: u64, length: usize, state: State<AppState>) -> Result<Vec<u8>> {
    if length == 0 || length > 4096 {
        return Err("Read size must be 1–4096 bytes.".into());
    }
    let source = state
        .source
        .lock()
        .map_err(err)?
        .as_ref()
        .ok_or("Open an image first.")?
        .image
        .clone();
    if offset >= source.len() {
        return Err("Offset is beyond the image.".into());
    }
    let mut bytes = vec![0; (source.len() - offset).min(length as u64) as usize];
    source.read_exact_at(offset, &mut bytes).map_err(err)?;
    Ok(bytes)
}
#[tauri::command]
async fn search_hex(
    pattern_hex: String,
    start_offset: u64,
    scan_length: u64,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<u64>> {
    let pattern = decode_hex_pattern(&pattern_hex)?;
    if scan_length == 0 || scan_length > 1024 * 1024 * 1024 {
        return Err("Search range must be between 1 byte and 1 GiB.".into());
    }
    let (source, source_id, evidence_record_id, case_id) = {
        let source = state.source.lock().map_err(err)?;
        let evidence = source.as_ref().ok_or("Open an image first.")?;
        if evidence.integrity_compromised {
            return Err(
                "The source changed during examination. Reopen a verified working copy.".into(),
            );
        }
        if evidence.info.sha256.is_none() {
            return Err(
                "Calculate and record the source SHA-256 before searching evidence bytes.".into(),
            );
        }
        let end = start_offset
            .checked_add(scan_length)
            .ok_or("Search range overflows the image address space.")?;
        if end > evidence.image.len() {
            return Err("Search range extends beyond the evidence image.".into());
        }
        (
            evidence.image.clone(),
            evidence.info.id,
            evidence.info.evidence_record_id,
            evidence.info.case_id,
        )
    };
    source.verify_unchanged().map_err(err)?;
    audit(
        &*state.db.lock().map_err(err)?,
        "hex_search_started",
        &serde_json::json!({"case_id":case_id,"source_id":source_id,"start_offset":start_offset,"scan_length":scan_length,"pattern_sha256":format!("{:x}", Sha256::digest(&pattern))}).to_string(),
    )?;

    let search_source = source.clone();
    let found = tauri::async_runtime::spawn_blocking(move || {
        search_hex_range(search_source.as_ref(), &pattern, start_offset, scan_length)
    })
    .await
    .map_err(err)?;

    let state = app.state::<AppState>();
    if source.verify_unchanged().is_err() {
        if let Ok(mut current) = state.source.lock() {
            if let Some(evidence) = current.as_mut().filter(|item| item.info.id == source_id) {
                evidence.integrity_compromised = true;
                evidence.info.sha256 = None;
            }
        }
        if let Ok(db) = state.db.lock() {
            let _ = db.execute(
                "UPDATE evidence_sources SET sha256=NULL,status='compromised' WHERE id=?1 AND case_id=?2",
                params![evidence_record_id, case_id],
            );
        }
    }
    let audit_event = match &found {
        Ok(_) => "hex_search_completed",
        Err(_) => "hex_search_failed",
    };
    let audit_payload = match &found {
        Ok(offsets) => {
            let mut match_digest = Sha256::new();
            for offset in offsets {
                match_digest.update(offset.to_le_bytes());
            }
            serde_json::json!({"case_id":case_id,"source_id":source_id,"start_offset":start_offset,"scan_length":scan_length,"matches":offsets.len(),"matches_sha256":format!("{:x}", match_digest.finalize()),"first_offsets":offsets.iter().take(100).collect::<Vec<_>>() })
        }
        Err(error) => {
            serde_json::json!({"case_id":case_id,"source_id":source_id,"start_offset":start_offset,"scan_length":scan_length,"error":error})
        }
    };
    audit(
        &*state.db.lock().map_err(err)?,
        audit_event,
        &audit_payload.to_string(),
    )?;
    found
}

fn search_hex_range(
    source: &dyn BlockSource,
    pattern: &[u8],
    start_offset: u64,
    scan_length: u64,
) -> Result<Vec<u64>> {
    let end = start_offset
        .checked_add(scan_length)
        .filter(|end| *end <= source.len())
        .ok_or("Search range extends beyond the evidence image.")?;
    if pattern.is_empty() {
        return Err("Search pattern cannot be empty.".into());
    }
    let mut cursor = start_offset;
    let prefix = hex_prefix_table(pattern);
    let mut matched = 0usize;
    let mut matches = Vec::new();
    while cursor < end {
        let count = (end - cursor).min(1024 * 1024) as usize;
        let mut chunk = vec![0; count];
        source.read_exact_at(cursor, &mut chunk).map_err(err)?;
        for (index, byte) in chunk.iter().enumerate() {
            while matched > 0 && pattern[matched] != *byte {
                matched = prefix[matched - 1];
            }
            if pattern[matched] == *byte {
                matched += 1;
            }
            if matched == pattern.len() {
                if matches.len() == 10_000 {
                    return Err("Search stopped at 10,000 matches. Narrow the range for a complete result set.".into());
                }
                matches.push(cursor + index as u64 + 1 - pattern.len() as u64);
                matched = prefix[matched - 1];
            }
        }
        cursor += count as u64;
    }
    Ok(matches)
}

fn hex_prefix_table(pattern: &[u8]) -> Vec<usize> {
    let mut prefix = vec![0; pattern.len()];
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index] != pattern[matched] {
            matched = prefix[matched - 1];
        }
        if pattern[index] == pattern[matched] {
            matched += 1;
        }
        prefix[index] = matched;
    }
    prefix
}

fn decode_hex_pattern(input: &str) -> Result<Vec<u8>> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    if compact.is_empty()
        || compact.len() > 512
        || !compact.len().is_multiple_of(2)
        || !compact.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Enter a byte pattern with 1–256 complete hexadecimal bytes.".into());
    }
    (0..compact.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).map_err(err))
        .collect()
}
#[tauri::command]
fn analyze_partitions(state: State<AppState>) -> Result<partition::PartitionReport> {
    let source = state
        .source
        .lock()
        .map_err(err)?
        .as_ref()
        .ok_or("Open an image first.")?
        .image
        .clone();
    partition::analyze(
        &mut storage::SourceCursor::new(source.as_ref()),
        source.len(),
    )
}
pub(crate) fn hash_source(
    source: &dyn BlockSource,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<Option<String>> {
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
            .map_err(err)?;
        digest.update(&buffer[..count]);
        position += count as u64;
        progress(position);
    }
    Ok(Some(format!("{:x}", digest.finalize())))
}
#[tauri::command]
fn start_hash(app: tauri::AppHandle, state: State<AppState>) -> Result<()> {
    let source = state.source.lock().map_err(err)?;
    let evidence = source.as_ref().ok_or("Open an image first.")?;
    if evidence.integrity_compromised {
        return Err(
            "The source hash changed during examination. Reopen a verified working copy.".into(),
        );
    }
    let source_id = evidence.info.id;
    let case_id = evidence.info.case_id;
    let evidence_record_id = evidence.info.evidence_record_id;
    let source = evidence.image.clone();
    let mut job = state.job.lock().map_err(err)?;
    if job.state == "running" {
        return Err("An operation is already running.".into());
    }
    source.verify_unchanged().map_err(err)?;
    audit(
        &*state.db.lock().map_err(err)?,
        "hash_started",
        &serde_json::json!({"case_id":case_id,"source_id":source_id,"size":source.len()})
            .to_string(),
    )
    .map_err(err)?;
    state.cancel.store(false, Ordering::SeqCst);
    *job = Job {
        state: "running".into(),
        total: source.len(),
        ..Job::default()
    };
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = guarded(|| {
            hash_source(source.as_ref(), &state.cancel, |processed| {
                if let Ok(mut job) = state.job.lock() {
                    job.processed = processed;
                }
            })
        })
        .and_then(|hash| {
            source.verify_unchanged().map_err(err)?;
            Ok(hash)
        });
        let result = result.and_then(|hash| {
            if let Some(digest) = hash.as_ref() {
                let mut current = state.source.lock().map_err(err)?;
                let evidence = current
                    .as_mut()
                    .filter(|evidence| evidence.info.id == source_id)
                    .ok_or("The source changed while hashing.")?;
                if evidence.integrity_compromised {
                    return Err("The source integrity was previously compromised.".into());
                }
                if evidence
                    .info
                    .sha256
                    .as_ref()
                    .is_some_and(|previous| previous != digest)
                {
                    evidence.info.sha256 = None;
                    evidence.integrity_compromised = true;
                    return Err("Source SHA-256 changed between examinations. Reopen a verified working copy and investigate this image.".into());
                }
            }
            Ok(hash)
        });
        let mut finished = state.job.lock().map(|job| job.clone()).unwrap_or_default();
        match result {
            Ok(Some(hash)) => {
                finished.state = "completed".into();
                finished.sha256 = Some(hash);
            }
            Ok(None) => finished.state = "cancelled".into(),
            Err(error) => {
                finished.state = "failed".into();
                finished.error = Some(error);
            }
        }
        let compromised = state
            .source
            .lock()
            .map(|current| {
                current.as_ref().is_some_and(|evidence| {
                    evidence.info.id == source_id && evidence.integrity_compromised
                })
            })
            .unwrap_or(false);
        let persisted = (|| -> Result<()> {
            let mut db = state.db.lock().map_err(err)?;
            let tx = db.transaction().map_err(err)?;
            if compromised {
                tx.execute(
                    "UPDATE evidence_sources SET sha256=NULL,status='compromised' WHERE id=?1 AND case_id=?2",
                    params![evidence_record_id, case_id],
                )
                .map_err(err)?;
            } else if let Some(hash) = finished.sha256.as_deref() {
                let changed = tx.execute(
                    "UPDATE evidence_sources SET sha256=?1,status='hashed' WHERE id=?2 AND case_id=?3 AND status!='compromised'",
                    params![hash, evidence_record_id, case_id],
                ).map_err(err)?;
                if changed != 1 {
                    return Err("The persistent evidence record could not be updated.".into());
                }
            }
            let (persisted_sha256, persisted_status): (Option<String>, String) = tx
                .query_row(
                    "SELECT sha256,status FROM evidence_sources WHERE id=?1 AND case_id=?2",
                    params![evidence_record_id, case_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(err)?;
            audit(
                &tx,
                "hash_finished",
                &serde_json::json!({"case_id":case_id,"evidence_record_id":evidence_record_id,"source_id":source_id,"evidence_status":persisted_status,"persisted_sha256":persisted_sha256,"job":&finished}).to_string(),
            )?;
            tx.commit().map_err(err)
        })();
        if let Err(error) = persisted {
            finished.state = "failed".into();
            finished.sha256 = None;
            finished.error = Some(format!(
                "Hash result was not committed to the case record and audit log: {error}"
            ));
            if let Ok(mut current) = state.source.lock() {
                if let Some(evidence) = current
                    .as_mut()
                    .filter(|evidence| evidence.info.id == source_id)
                {
                    evidence.info.sha256 = None;
                }
            }
        } else if let Some(hash) = finished.sha256.as_ref() {
            if let Ok(mut current) = state.source.lock() {
                if let Some(evidence) = current
                    .as_mut()
                    .filter(|evidence| evidence.info.id == source_id)
                {
                    evidence.info.sha256 = Some(hash.clone());
                }
            }
        }
        if let Ok(mut job) = state.job.lock() {
            *job = finished;
        };
    });
    Ok(())
}
#[tauri::command]
fn job_status(state: State<AppState>) -> Result<Job> {
    Ok(state.job.lock().map_err(err)?.clone())
}
#[tauri::command]
fn source_status(state: State<AppState>) -> Result<Option<Source>> {
    Ok(state
        .source
        .lock()
        .map_err(err)?
        .as_ref()
        .map(|e| e.info.clone()))
}
#[tauri::command]
fn cancel_job(state: State<AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}
#[derive(Serialize, Debug)]
struct Case {
    id: i64,
    title: String,
    examiner: String,
    integrity: String,
}
#[derive(Serialize)]
struct ActiveCaseState {
    case_id: Option<i64>,
    audit_matched: bool,
}
#[derive(Serialize)]
struct EvidenceRecord {
    id: i64,
    case_id: i64,
    path: String,
    name: String,
    size_bytes: u64,
    filesystem: String,
    opened_at: String,
    sha256: Option<String>,
    status: String,
}
#[tauri::command]
fn list_case_evidence(case_id: i64, state: State<AppState>) -> Result<Vec<EvidenceRecord>> {
    let db = state.db.lock().map_err(err)?;
    list_case_evidence_from(&db, case_id)
}

fn list_case_evidence_from(db: &Connection, case_id: i64) -> Result<Vec<EvidenceRecord>> {
    let mut statement = db.prepare("SELECT id,case_id,original_path,name,size_bytes,filesystem,opened_at,sha256,status FROM evidence_sources WHERE case_id=?1 ORDER BY id DESC").map_err(err)?;
    let rows = statement
        .query_map([case_id], |row| {
            let size: i64 = row.get(4)?;
            Ok(EvidenceRecord {
                id: row.get(0)?,
                case_id: row.get(1)?,
                path: row.get(2)?,
                name: row.get(3)?,
                size_bytes: u64::try_from(size)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, size))?,
                filesystem: row.get(5)?,
                opened_at: row.get(6)?,
                sha256: row.get(7)?,
                status: row.get(8)?,
            })
        })
        .map_err(err)?;
    let records = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)?;
    verify_evidence_record_integrity(db, &records)?;
    Ok(records)
}

fn verify_evidence_record_integrity(db: &Connection, records: &[EvidenceRecord]) -> Result<()> {
    let chain = verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let mut audit_statement = db
        .prepare("SELECT event,payload FROM audit ORDER BY id")
        .map_err(err)?;
    let audit_rows = audit_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(err)?;
    let mut opened_records = std::collections::HashMap::new();
    let mut audited_hash_state = std::collections::HashMap::new();
    for row in audit_rows {
        let (event, payload) = row.map_err(err)?;
        let payload: serde_json::Value = serde_json::from_str(&payload).map_err(err)?;
        let Some(id) = payload
            .get("evidence_record_id")
            .and_then(serde_json::Value::as_i64)
        else {
            continue;
        };
        if event == "image_opened" {
            opened_records.insert(id, payload);
        } else if event == "hash_finished" {
            if let (Some(status), Some(sha)) = (
                payload
                    .get("evidence_status")
                    .and_then(serde_json::Value::as_str),
                payload.get("persisted_sha256"),
            ) {
                let sha = sha.as_str().map(str::to_owned);
                audited_hash_state.insert(id, (status.to_owned(), sha));
            }
        }
    }
    for record in records {
        let opened = opened_records
            .get(&record.id)
            .ok_or("An evidence record has no matching image-open audit event.")?;
        if opened["case_id"].as_i64() != Some(record.case_id)
            || opened["path"].as_str() != Some(record.path.as_str())
            || opened["name"].as_str() != Some(record.name.as_str())
            || opened["size"].as_u64() != Some(record.size_bytes)
            || opened["filesystem"].as_str() != Some(record.filesystem.as_str())
            || opened["opened_at"].as_str() != Some(record.opened_at.as_str())
        {
            return Err(format!(
                "Evidence record {} does not match its image-open audit event.",
                record.id
            ));
        }
        let (expected_status, expected_sha) = audited_hash_state
            .get(&record.id)
            .cloned()
            .unwrap_or_else(|| ("open".to_owned(), None));
        if record.status != expected_status || record.sha256 != expected_sha {
            return Err(format!(
                "Evidence record {} hash state does not match its audit history.",
                record.id
            ));
        }
    }
    Ok(())
}
#[tauri::command]
fn list_cases(state: State<AppState>) -> Result<Vec<Case>> {
    let db = state.db.lock().map_err(err)?;
    list_cases_from(&db)
}

fn list_cases_from(db: &Connection) -> Result<Vec<Case>> {
    let chain = verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let mut audited_cases = std::collections::HashMap::new();
    let mut audit_statement = db
        .prepare("SELECT payload FROM audit WHERE event='case_created' ORDER BY id")
        .map_err(err)?;
    let audit_rows = audit_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(err)?;
    for row in audit_rows {
        let payload: serde_json::Value = serde_json::from_str(&row.map_err(err)?).map_err(err)?;
        let id = payload
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .filter(|id| *id > 0)
            .ok_or("Case creation audit event has an invalid ID.")?;
        let title = payload
            .get("title")
            .and_then(serde_json::Value::as_str)
            .ok_or("Case creation audit event has no title.")?;
        let examiner = payload
            .get("examiner")
            .and_then(serde_json::Value::as_str)
            .ok_or("Case creation audit event has no examiner.")?;
        if audited_cases
            .insert(id, (title.to_owned(), examiner.to_owned()))
            .is_some()
        {
            return Err(format!("Case {id} has duplicate creation audit events."));
        }
    }
    let mut query = db
        .prepare("SELECT id,title,examiner FROM cases ORDER BY id DESC")
        .map_err(err)?;
    let rows = query
        .query_map([], |r| {
            Ok(Case {
                id: r.get(0)?,
                title: r.get(1)?,
                examiner: r.get(2)?,
                integrity: String::new(),
            })
        })
        .map_err(err)?;
    let mut cases = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)?;
    for case in &mut cases {
        if let Some((title, examiner)) = audited_cases.remove(&case.id) {
            if title != case.title || examiner != case.examiner {
                return Err(format!(
                    "Case {} does not match its creation audit event.",
                    case.id
                ));
            }
            case.integrity = "audit_matched".into();
        } else {
            case.integrity = "legacy_unverified".into();
        }
    }
    if let Some(orphaned_id) = audited_cases.keys().next() {
        return Err(format!(
            "Case {orphaned_id} has a creation audit event but no register entry."
        ));
    }
    Ok(cases)
}
fn active_case_id(db: &Connection) -> Result<Option<i64>> {
    Ok(active_case_setting_value(db)?
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0))
}
fn active_case_setting_value(db: &Connection) -> Result<Option<String>> {
    db.query_row(
        "SELECT value FROM app_settings WHERE key='active_case_id'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(err)
}
fn audited_active_case_id(db: &Connection) -> Result<Option<Option<i64>>> {
    let mut statement = db
        .prepare("SELECT event,payload FROM audit WHERE event IN ('case_created','active_case_changed') ORDER BY id")
        .map_err(err)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(err)?;
    let mut audited = None;
    for row in rows {
        let (event, payload) = row.map_err(err)?;
        let payload: serde_json::Value = serde_json::from_str(&payload).map_err(err)?;
        if event == "case_created" {
            if payload.get("selected").and_then(serde_json::Value::as_bool) == Some(true) {
                let id = payload
                    .get("id")
                    .and_then(serde_json::Value::as_i64)
                    .filter(|id| *id > 0)
                    .ok_or("Selected case-creation audit event has an invalid ID.")?;
                audited = Some(Some(id));
            }
        } else {
            let value = payload
                .get("case_id")
                .ok_or("Active-case audit event has no case_id.")?;
            let id = if value.is_null() {
                None
            } else {
                Some(
                    value
                        .as_i64()
                        .filter(|id| *id > 0)
                        .ok_or("Active-case audit event has an invalid case_id.")?,
                )
            };
            audited = Some(id);
        }
    }
    Ok(audited)
}
fn active_case_state_from(db: &Connection) -> Result<ActiveCaseState> {
    let chain = verify_audit_chain(db)?;
    if !chain.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}.",
            chain.first_invalid_record.unwrap_or_default()
        ));
    }
    let raw_case_id = active_case_setting_value(db)?;
    let case_id = raw_case_id
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0);
    let pointer_is_valid = raw_case_id.is_none() || case_id.is_some();
    let audited_case_id = audited_active_case_id(db)?;
    let audit_matched = pointer_is_valid
        && match audited_case_id {
            Some(audited_case_id) => audited_case_id == case_id,
            None => case_id.is_none(),
        };
    let audit_matched = if audit_matched {
        match case_id {
            Some(id) => db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
                    [id],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(err)?,
            None => true,
        }
    } else {
        false
    };
    Ok(ActiveCaseState {
        case_id,
        audit_matched,
    })
}
fn require_audited_active_case(db: &Connection) -> Result<i64> {
    let state = active_case_state_from(db)?;
    if !state.audit_matched {
        return Err("The saved active case does not match its audit history. Re-select the intended case to record a correction before opening evidence.".into());
    }
    state
        .case_id
        .ok_or_else(|| "Select or create a case before opening evidence.".into())
}
fn ensure_case_change_allowed(job: &Job) -> Result<()> {
    if job.state == "running" {
        Err("Wait for the active evidence operation to finish before changing cases.".into())
    } else {
        Ok(())
    }
}
fn case_context_changed(previous: Option<i64>, next: Option<i64>) -> bool {
    previous != next || next.is_none()
}
fn persist_active_case(db: &mut Connection, case_id: Option<i64>) -> Result<(Option<i64>, bool)> {
    let previous = active_case_id(db)?;
    let previous_raw = active_case_setting_value(db)?;
    let previous_audit_matched = active_case_state_from(db)?.audit_matched;
    let tx = db.transaction().map_err(err)?;
    if let Some(id) = case_id {
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("The selected case does not exist.".into());
        }
        tx.execute("INSERT INTO app_settings(key,value) VALUES ('active_case_id',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [id.to_string()]).map_err(err)?;
    } else {
        tx.execute("DELETE FROM app_settings WHERE key='active_case_id'", [])
            .map_err(err)?;
    }
    audit(
        &tx,
        "active_case_changed",
        &serde_json::json!({"previous_case_id":previous,"previous_active_case_value":previous_raw,"previous_audit_matched":previous_audit_matched,"case_id":case_id}).to_string(),
    )
    .map_err(err)?;
    tx.commit().map_err(err)?;
    Ok((previous, previous_audit_matched))
}
#[tauri::command]
fn get_active_case_state(state: State<AppState>) -> Result<ActiveCaseState> {
    let db = state.db.lock().map_err(err)?;
    active_case_state_from(&db)
}
#[tauri::command]
fn set_active_case(case_id: Option<i64>, state: State<AppState>) -> Result<()> {
    let mut current_source = state.source.lock().map_err(err)?;
    let mut job = state.job.lock().map_err(err)?;
    ensure_case_change_allowed(&job)?;
    let mut scan = state.scan.lock().map_err(err)?;
    let mut fat32_scan = state.fat32_scan.lock().map_err(err)?;
    let mut exfat_scan = state.exfat_scan.lock().map_err(err)?;
    let mut carve_scan = state.carve_scan.lock().map_err(err)?;
    let mut db = state.db.lock().map_err(err)?;
    let (previous, previous_audit_matched) = persist_active_case(&mut db, case_id)?;
    if case_context_changed(previous, case_id) || !previous_audit_matched {
        *current_source = None;
        *scan = None;
        *fat32_scan = None;
        *exfat_scan = None;
        *carve_scan = None;
        *job = Job::default();
        state.cancel.store(false, Ordering::SeqCst);
    }
    Ok(())
}
#[tauri::command]
fn create_case(title: String, examiner: String, state: State<AppState>) -> Result<()> {
    if title.trim().is_empty()
        || examiner.trim().is_empty()
        || title.len() > 200
        || examiner.len() > 200
    {
        return Err("Title and examiner are required (maximum 200 characters).".into());
    }
    let mut current_source = state.source.lock().map_err(err)?;
    let mut job = state.job.lock().map_err(err)?;
    ensure_case_change_allowed(&job)?;
    let mut scan = state.scan.lock().map_err(err)?;
    let mut fat32_scan = state.fat32_scan.lock().map_err(err)?;
    let mut exfat_scan = state.exfat_scan.lock().map_err(err)?;
    let mut carve_scan = state.carve_scan.lock().map_err(err)?;
    let mut db = state.db.lock().map_err(err)?;
    let previous_active_case_value = active_case_setting_value(&db)?;
    let previous_active_case_audit_matched = active_case_state_from(&db)?.audit_matched;
    let tx = db.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO cases(title,examiner) VALUES (?1,?2)",
        params![title.trim(), examiner.trim()],
    )
    .map_err(err)?;
    let id = tx.last_insert_rowid();
    tx.execute("INSERT INTO app_settings(key,value) VALUES ('active_case_id',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [id.to_string()]).map_err(err)?;
    audit(
        &tx,
        "case_created",
        &serde_json::json!({"id":id,"title":title.trim(),"examiner":examiner.trim(),"selected":true,"previous_active_case_value":previous_active_case_value,"previous_active_case_audit_matched":previous_active_case_audit_matched})
            .to_string(),
    )
    .map_err(err)?;
    tx.commit().map_err(err)?;
    *current_source = None;
    *scan = None;
    *fat32_scan = None;
    *exfat_scan = None;
    *carve_scan = None;
    *job = Job::default();
    state.cancel.store(false, Ordering::SeqCst);
    Ok(())
}

#[derive(Serialize)]
struct AuditVerification {
    valid: bool,
    records_checked: u64,
    first_invalid_record: Option<i64>,
    head_sha256: String,
    anchor_match: Option<bool>,
}

#[tauri::command]
fn verify_audit(
    expected_head_sha256: Option<String>,
    state: State<AppState>,
) -> Result<AuditVerification> {
    let db = state.db.lock().map_err(err)?;
    let expected_head_sha256 = expected_head_sha256
        .map(|expected| expected.trim().to_owned())
        .filter(|expected| !expected.is_empty());
    verify_audit_with_anchor(&db, expected_head_sha256.as_deref())
}

fn verify_audit_chain(db: &Connection) -> Result<AuditVerification> {
    let mut statement = db
        .prepare("SELECT id,timestamp,event,payload,previous,hash FROM audit ORDER BY id")
        .map_err(err)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(err)?;
    let mut expected_previous = String::new();
    let mut expected_id = Some(1i64);
    let mut checked = 0;
    let mut first_invalid = None;
    for row in rows {
        let (id, timestamp, event, payload, previous, stored_hash) = row.map_err(err)?;
        let encoded =
            serde_json::to_vec(&(&previous, &timestamp, &event, &payload)).map_err(err)?;
        let expected_hash = format!("{:x}", Sha256::digest(encoded));
        checked += 1;
        if first_invalid.is_none()
            && (expected_id != Some(id)
                || previous != expected_previous
                || stored_hash != expected_hash)
        {
            first_invalid = Some(id);
        }
        expected_previous = stored_hash;
        expected_id = id.checked_add(1);
    }
    Ok(AuditVerification {
        valid: first_invalid.is_none(),
        records_checked: checked,
        first_invalid_record: first_invalid,
        head_sha256: expected_previous,
        anchor_match: None,
    })
}
fn verify_audit_with_anchor(
    db: &Connection,
    expected_head_sha256: Option<&str>,
) -> Result<AuditVerification> {
    let mut verification = verify_audit_chain(db)?;
    if let Some(expected) = expected_head_sha256 {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Expected audit head must be exactly 64 hexadecimal characters.".into());
        }
        verification.anchor_match =
            Some(verification.valid && verification.head_sha256.eq_ignore_ascii_case(expected));
    }
    Ok(verification)
}
fn audit(db: &Connection, event: &str, payload: &str) -> Result<()> {
    let verification = verify_audit_chain(db)?;
    if !verification.valid {
        return Err(format!(
            "Audit chain integrity check failed at record {}. Evidence-changing operations are blocked; preserve the database and investigate the discrepancy.",
            verification.first_invalid_record.unwrap_or_default()
        ));
    }
    let previous: String = db
        .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(err)?
        .unwrap_or_default();
    let timestamp = audit_timestamp(std::time::SystemTime::now())?;
    let encoded = serde_json::to_vec(&(&previous, &timestamp, event, payload))
        .expect("string tuple serialization");
    let hash = format!("{:x}", Sha256::digest(encoded));
    db.execute(
        "INSERT INTO audit(timestamp,event,payload,previous,hash) VALUES (?1,?2,?3,?4,?5)",
        params![timestamp, event, payload, previous, hash],
    )
    .map_err(err)?;
    Ok(())
}
fn audit_timestamp(time: std::time::SystemTime) -> Result<String> {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().to_string())
        .map_err(|error| format!("System clock predates the Unix epoch: {error}"))
}
struct EvidenceRegistration<'a> {
    case_id: i64,
    source_id: u64,
    path: &'a str,
    name: &'a str,
    size: u64,
    filesystem: &'a str,
    opened_at: &'a str,
}
fn record_evidence_open(
    db: &mut Connection,
    registration: &EvidenceRegistration<'_>,
) -> Result<i64> {
    let size = i64::try_from(registration.size).map_err(err)?;
    let tx = db.transaction().map_err(err)?;
    tx.execute(
        "INSERT INTO evidence_sources(case_id,original_path,name,size_bytes,filesystem,opened_at,status) VALUES (?1,?2,?3,?4,?5,?6,'open')",
        params![registration.case_id,registration.path,registration.name,size,registration.filesystem,registration.opened_at],
    )
    .map_err(err)?;
    let evidence_record_id = tx.last_insert_rowid();
    audit(
        &tx,
        "image_opened",
        &serde_json::json!({"case_id":registration.case_id,"evidence_record_id":evidence_record_id,"source_id":registration.source_id,"path":registration.path,"name":registration.name,"size":size,"filesystem":registration.filesystem,"opened_at":registration.opened_at}).to_string(),
    )?;
    tx.commit().map_err(err)?;
    Ok(evidence_record_id)
}
fn database(path: PathBuf) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    // UI and background operations share one evidence database; tolerate brief
    // transaction overlap instead of failing immediately with SQLITE_BUSY.
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let integrity: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SQLite quick_check failed: {integrity}"),
            ),
        )));
    }
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,title TEXT NOT NULL,examiner TEXT NOT NULL); CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS evidence_sources(id INTEGER PRIMARY KEY,case_id INTEGER NOT NULL REFERENCES cases(id),original_path TEXT NOT NULL,name TEXT NOT NULL,size_bytes INTEGER NOT NULL CHECK(size_bytes>=0),filesystem TEXT NOT NULL,opened_at TEXT NOT NULL,sha256 TEXT,status TEXT NOT NULL CHECK(status IN ('open','hashed','compromised')),UNIQUE(id,case_id)); CREATE INDEX IF NOT EXISTS evidence_sources_by_case ON evidence_sources(case_id,id); CREATE TABLE IF NOT EXISTS scan_sessions(id INTEGER PRIMARY KEY,evidence_id INTEGER NOT NULL,case_id INTEGER NOT NULL REFERENCES cases(id),volume_offset TEXT NOT NULL,source_sha256 TEXT NOT NULL,completed_at TEXT NOT NULL,boot_json TEXT NOT NULL,records INTEGER NOT NULL,skipped INTEGER NOT NULL,found INTEGER NOT NULL,limited INTEGER NOT NULL,candidates_json TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL,FOREIGN KEY(evidence_id,case_id) REFERENCES evidence_sources(id,case_id)); CREATE INDEX IF NOT EXISTS scan_sessions_by_case ON scan_sessions(case_id,id); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,event TEXT NOT NULL,payload TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS fat32_scan_sessions(id INTEGER PRIMARY KEY,evidence_id INTEGER NOT NULL,case_id INTEGER NOT NULL REFERENCES cases(id),volume_offset TEXT NOT NULL,source_sha256 TEXT NOT NULL,completed_at TEXT NOT NULL,boot_json TEXT NOT NULL,records INTEGER NOT NULL,found INTEGER NOT NULL,deleted INTEGER NOT NULL,entries_json TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL,FOREIGN KEY(evidence_id,case_id) REFERENCES evidence_sources(id,case_id)); CREATE INDEX IF NOT EXISTS fat32_scan_sessions_by_case ON fat32_scan_sessions(case_id,id);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS exfat_scan_sessions(id INTEGER PRIMARY KEY,evidence_id INTEGER NOT NULL,case_id INTEGER NOT NULL REFERENCES cases(id),volume_offset TEXT NOT NULL,source_sha256 TEXT NOT NULL,completed_at TEXT NOT NULL,boot_json TEXT NOT NULL,entries_json TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL,FOREIGN KEY(evidence_id,case_id) REFERENCES evidence_sources(id,case_id)); CREATE INDEX IF NOT EXISTS exfat_scan_sessions_by_case ON exfat_scan_sessions(case_id,id);")?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS carve_scan_sessions(id INTEGER PRIMARY KEY,evidence_id INTEGER NOT NULL,case_id INTEGER NOT NULL REFERENCES cases(id),source_sha256 TEXT NOT NULL,completed_at TEXT NOT NULL,scanned_bytes INTEGER NOT NULL,candidates_json TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL,candidates_limited INTEGER NOT NULL CHECK(candidates_limited IN (0,1)),FOREIGN KEY(evidence_id,case_id) REFERENCES evidence_sources(id,case_id)); CREATE INDEX IF NOT EXISTS carve_scan_sessions_by_case ON carve_scan_sessions(case_id,id);")?;
    Ok(db)
}
fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let directory = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&directory)?;
            app.manage(AppState {
                source: Mutex::new(None),
                scan: Mutex::new(None),
                carve_scan: Mutex::new(None),
                fat32_scan: Mutex::new(None),
                exfat_scan: Mutex::new(None),
                generation: AtomicU64::new(1),
                db: Mutex::new(database(directory.join("cases.db"))?),
                job: Mutex::new(Job::default()),
                cancel: AtomicBool::new(false),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            acquisition::list_physical_devices,
            acquisition::acquire_physical_device,
            raid::pick_raid_members,
            raid::reconstruct_raid,
            open_image,
            start_file_carving,
            carve_results,
            export_carved_selected,
            read_hex,
            search_hex,
            analyze_partitions,
            start_hash,
            job_status,
            source_status,
            cancel_job,
            list_cases,
            list_case_evidence,
            create_case,
            get_active_case_state,
            set_active_case,
            verify_audit,
            audit_export::export_audit_checkpoint,
            audit_export::verify_audit_checkpoint,
            recovery_commands::start_ntfs_scan,
            fat32_commands::start_fat32_scan,
            exfat_commands::start_exfat_scan,
            exfat_commands::export_exfat_deleted,
            exfat_commands::exfat_scan_summary,
            exfat_commands::exfat_scan_results,
            exfat_commands::list_case_exfat_scan_sessions,
            exfat_commands::archived_exfat_scan_results,
            fat32_commands::export_fat32_deleted,
            fat32_commands::fat32_scan_summary,
            fat32_commands::fat32_scan_results,
            fat32_commands::list_case_fat32_scan_sessions,
            fat32_commands::archived_fat32_scan_results,
            recovery_commands::scan_summary,
            recovery_commands::list_case_scan_sessions,
            recovery_commands::archived_scan_results,
            recovery_commands::reopen_archived_source,
            case_report::export_case_report,
            recovery_commands::scan_results,
            recovery_commands::export_selected,
            recovery_verify::verify_recovery_export
        ])
        .run(tauri::generate_context!())
        .expect("Failed to start DaemonCore");
}
#[cfg(test)]
mod tests {
    use super::*;
    use storage::MemorySource;

    #[test]
    fn hex_search_finds_overlapping_and_cross_block_matches() {
        let mut image = vec![0; 1024 * 1024 + 16];
        image[4..8].copy_from_slice(&[0xaa, 0xaa, 0xaa, 0xaa]);
        image[1024 * 1024 - 1..1024 * 1024 + 2].copy_from_slice(&[0xde, 0xad, 0xbe]);
        let source = MemorySource(image);

        assert_eq!(
            search_hex_range(&source, &[0xaa, 0xaa], 0, 32).unwrap(),
            [4, 5, 6]
        );
        assert_eq!(
            search_hex_range(&source, &[0xde, 0xad, 0xbe], 0, source.len()).unwrap(),
            [1024 * 1024 - 1]
        );
    }

    #[test]
    fn hex_search_rejects_out_of_bounds_ranges_and_bad_patterns() {
        let source = MemorySource(vec![0; 8]);
        assert!(search_hex_range(&source, &[0xaa], 7, 2).is_err());
        assert!(decode_hex_pattern("").is_err());
        assert!(decode_hex_pattern("0").is_err());
        assert!(decode_hex_pattern("gg").is_err());
        assert_eq!(decode_hex_pattern("4d 5A").unwrap(), [0x4d, 0x5a]);
    }

    #[test]
    fn detect_short_and_ntfs() {
        assert!(detect(&[]).starts_with("Unknown"));
        let mut b = vec![0; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        assert!(detect(&b).starts_with("NTFS"));
    }
    #[test]
    fn cases_and_audit_persist() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(&db, "one", "{}").unwrap();
        audit(&db, "two", "{}").unwrap();
        let first: String = db
            .query_row("SELECT hash FROM audit WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let previous: String = db
            .query_row("SELECT previous FROM audit WHERE id=2", [], |r| r.get(0))
            .unwrap();
        assert_eq!(first, previous);
    }

    #[test]
    fn audit_timestamp_rejects_pre_epoch_clock() {
        let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_millis(1);
        assert!(audit_timestamp(before_epoch)
            .unwrap_err()
            .contains("predates the Unix epoch"));
        assert_eq!(audit_timestamp(std::time::UNIX_EPOCH).unwrap(), "0");
    }

    #[test]
    fn database_uses_full_sqlite_synchronous_mode() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        let synchronous: i64 = db
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 2);
        let busy_timeout: i64 = db
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5_000);
    }

    #[test]
    fn database_rejects_corrupt_sqlite_before_writing_schema() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("daemoncore-corrupt-db-{nonce}.db"));
        let original = b"not a sqlite database";
        std::fs::write(&path, original).unwrap();

        let result = database(path.clone());
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_case_database_migrates_without_losing_cases_or_audit() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("daemoncore-case-migration-{nonce}.db"));
        let legacy = Connection::open(&path).unwrap();
        legacy.execute_batch(
            "CREATE TABLE cases(id INTEGER PRIMARY KEY,title TEXT NOT NULL,examiner TEXT NOT NULL); CREATE TABLE audit(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,event TEXT NOT NULL,payload TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL); INSERT INTO cases(id,title,examiner) VALUES (9,'legacy case','examiner');",
        ).unwrap();
        drop(legacy);

        let db = database(path.clone()).unwrap();
        let title: String = db
            .query_row("SELECT title FROM cases WHERE id=9", [], |row| row.get(0))
            .unwrap();
        assert_eq!(title, "legacy case");
        for table in [
            "app_settings",
            "evidence_sources",
            "scan_sessions",
            "fat32_scan_sessions",
        ] {
            let count: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "migration did not create {table}");
        }
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn active_case_setting_is_read_from_persistent_schema() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (7,'Case 7','Examiner')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO app_settings(key,value) VALUES ('active_case_id','7')",
            [],
        )
        .unwrap();
        assert_eq!(active_case_id(&db).unwrap(), Some(7));
        db.execute("DELETE FROM app_settings", []).unwrap();
        assert_eq!(active_case_id(&db).unwrap(), None);
    }

    #[test]
    fn active_case_change_is_atomic_and_resets_context_only_for_a_change() {
        let mut db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Case 1','Examiner'),(2,'Case 2','Examiner')",
            [],
        )
        .unwrap();
        assert_eq!(persist_active_case(&mut db, Some(1)).unwrap(), (None, true));
        assert_eq!(
            persist_active_case(&mut db, Some(2)).unwrap(),
            (Some(1), true)
        );
        assert_eq!(active_case_id(&db).unwrap(), Some(2));
        assert!(case_context_changed(Some(1), Some(2)));
        assert!(!case_context_changed(Some(2), Some(2)));
        assert!(case_context_changed(Some(2), None));
        assert!(case_context_changed(None, None));
        let audit_count: i64 = db
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(audit_count, 2);
        assert!(persist_active_case(&mut db, Some(99)).is_err());
        assert_eq!(active_case_id(&db).unwrap(), Some(2));
        assert!(verify_audit_chain(&db).unwrap().valid);
    }

    #[test]
    fn active_case_change_is_rejected_during_an_operation() {
        assert!(ensure_case_change_allowed(&Job {
            state: "running".into(),
            ..Job::default()
        })
        .is_err());
        assert!(ensure_case_change_allowed(&Job::default()).is_ok());
    }

    #[test]
    fn active_case_pointer_mismatch_blocks_evidence_until_audited_correction() {
        let mut db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Case 1','Examiner'),(2,'Case 2','Examiner')",
            [],
        )
        .unwrap();
        persist_active_case(&mut db, Some(1)).unwrap();
        assert_eq!(require_audited_active_case(&db).unwrap(), 1);

        db.execute(
            "UPDATE app_settings SET value='2' WHERE key='active_case_id'",
            [],
        )
        .unwrap();
        let mismatched = active_case_state_from(&db).unwrap();
        assert_eq!(mismatched.case_id, Some(2));
        assert!(!mismatched.audit_matched);
        assert!(require_audited_active_case(&db)
            .unwrap_err()
            .contains("does not match its audit history"));

        assert_eq!(
            persist_active_case(&mut db, Some(2)).unwrap(),
            (Some(2), false)
        );
        assert_eq!(require_audited_active_case(&db).unwrap(), 2);
        let correction: serde_json::Value = db
            .query_row(
                "SELECT payload FROM audit WHERE event='active_case_changed' ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|payload| serde_json::from_str(&payload).unwrap())
            .unwrap();
        assert_eq!(correction["previous_case_id"], 2);
        assert_eq!(correction["previous_audit_matched"], false);
        assert_eq!(correction["case_id"], 2);

        db.execute(
            "UPDATE app_settings SET value='not-an-id' WHERE key='active_case_id'",
            [],
        )
        .unwrap();
        let malformed = active_case_state_from(&db).unwrap();
        assert_eq!(malformed.case_id, None);
        assert!(!malformed.audit_matched);
        assert_eq!(
            persist_active_case(&mut db, Some(1)).unwrap(),
            (None, false)
        );
        assert_eq!(require_audited_active_case(&db).unwrap(), 1);
        let correction: serde_json::Value = db
            .query_row(
                "SELECT payload FROM audit WHERE event='active_case_changed' ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|payload| serde_json::from_str(&payload).unwrap())
            .unwrap();
        assert_eq!(correction["previous_active_case_value"], "not-an-id");
        assert_eq!(correction["previous_audit_matched"], false);
    }

    #[test]
    fn case_register_reconciles_audit_and_marks_legacy_rows() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'Verified case','Examiner'),(2,'Legacy case','Examiner')",
            [],
        )
        .unwrap();
        audit(
            &db,
            "case_created",
            &serde_json::json!({"id":1,"title":"Verified case","examiner":"Examiner","selected":true}).to_string(),
        )
        .unwrap();

        let cases = list_cases_from(&db).unwrap();
        assert_eq!(cases[0].id, 2);
        assert_eq!(cases[0].integrity, "legacy_unverified");
        assert_eq!(cases[1].id, 1);
        assert_eq!(cases[1].integrity, "audit_matched");

        db.execute(
            "UPDATE cases SET title='Changed after audit' WHERE id=1",
            [],
        )
        .unwrap();
        assert!(list_cases_from(&db)
            .unwrap_err()
            .contains("does not match its creation audit event"));
    }

    #[test]
    fn case_register_rejects_missing_audited_case_rows() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(
            &db,
            "case_created",
            &serde_json::json!({"id":7,"title":"Removed case","examiner":"Examiner"}).to_string(),
        )
        .unwrap();
        assert!(list_cases_from(&db)
            .unwrap_err()
            .contains("creation audit event but no register entry"));
    }

    #[test]
    fn evidence_open_record_and_audit_commit_atomically() {
        let mut db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'case','examiner')",
            [],
        )
        .unwrap();
        let id = record_evidence_open(
            &mut db,
            &EvidenceRegistration {
                case_id: 1,
                source_id: 5,
                path: "C:/evidence.img",
                name: "evidence.img",
                size: 4096,
                filesystem: "NTFS",
                opened_at: "1000",
            },
        )
        .unwrap();
        let path: String = db
            .query_row(
                "SELECT original_path FROM evidence_sources WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(path, "C:/evidence.img");
        assert!(verify_audit_chain(&db).unwrap().valid);

        db.execute("UPDATE audit SET payload='changed' WHERE id=1", [])
            .unwrap();
        assert!(record_evidence_open(
            &mut db,
            &EvidenceRegistration {
                case_id: 1,
                source_id: 6,
                path: "C:/second.img",
                name: "second.img",
                size: 8192,
                filesystem: "Unknown",
                opened_at: "2000",
            },
        )
        .is_err());
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM evidence_sources", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn case_evidence_view_reconciles_rows_with_audit_history() {
        let mut db = database(PathBuf::from(":memory:")).unwrap();
        db.execute(
            "INSERT INTO cases(id,title,examiner) VALUES (1,'case','examiner')",
            [],
        )
        .unwrap();
        let id = record_evidence_open(
            &mut db,
            &EvidenceRegistration {
                case_id: 1,
                source_id: 5,
                path: "C:/evidence.img",
                name: "evidence.img",
                size: 4096,
                filesystem: "NTFS",
                opened_at: "1000",
            },
        )
        .unwrap();
        let mut record = EvidenceRecord {
            id,
            case_id: 1,
            path: "C:/evidence.img".into(),
            name: "evidence.img".into(),
            size_bytes: 4096,
            filesystem: "NTFS".into(),
            opened_at: "1000".into(),
            sha256: None,
            status: "open".into(),
        };
        verify_evidence_record_integrity(&db, std::slice::from_ref(&record)).unwrap();
        db.execute(
            "UPDATE evidence_sources SET original_path='C:/substituted.img' WHERE id=?1",
            [id],
        )
        .unwrap();
        record.path = "C:/substituted.img".into();
        assert!(verify_evidence_record_integrity(&db, &[record]).is_err());
    }

    #[test]
    fn audit_chain_verification_finds_modified_entries() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(&db, "case_created", "{\"id\":1}").unwrap();
        audit(&db, "image_opened", "{\"name\":\"disk.img\"}").unwrap();
        assert!(verify_audit_chain(&db).unwrap().valid);
        db.execute("UPDATE audit SET payload='{}' WHERE id=1", [])
            .unwrap();
        let result = verify_audit_chain(&db).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_invalid_record, Some(1));
    }
    #[test]
    fn live_audit_head_compares_against_an_independent_anchor() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(&db, "case_created", "{\"id\":1}").unwrap();
        audit(&db, "image_opened", "{\"name\":\"disk.img\"}").unwrap();
        let head = verify_audit_chain(&db).unwrap().head_sha256;

        let matched = verify_audit_with_anchor(&db, Some(&head.to_uppercase())).unwrap();
        assert!(matched.valid);
        assert_eq!(matched.anchor_match, Some(true));
        assert_eq!(matched.head_sha256, head);

        let mismatch = verify_audit_with_anchor(&db, Some(&"0".repeat(64))).unwrap();
        assert!(mismatch.valid);
        assert_eq!(mismatch.anchor_match, Some(false));
        assert!(verify_audit_with_anchor(&db, Some("bad hash")).is_err());

        db.execute("UPDATE audit SET payload='{}' WHERE id=1", [])
            .unwrap();
        let tampered = verify_audit_with_anchor(&db, Some(&head)).unwrap();
        assert!(!tampered.valid);
        assert_eq!(tampered.anchor_match, Some(false));
    }
    #[test]
    fn audit_writes_fail_closed_after_chain_tampering() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(&db, "case_created", "{\"id\":1}").unwrap();
        db.execute("UPDATE audit SET payload='{}' WHERE id=1", [])
            .unwrap();

        let error = audit(&db, "image_opened", "{\"name\":\"disk.img\"}").unwrap_err();
        assert!(error.contains("integrity check failed at record 1"));
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn audit_chain_verification_detects_altered_record_ids() {
        let db = database(PathBuf::from(":memory:")).unwrap();
        audit(&db, "first", "{}").unwrap();
        audit(&db, "second", "{}").unwrap();
        db.execute("UPDATE audit SET id=3 WHERE id=2", []).unwrap();

        let result = verify_audit_chain(&db).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_invalid_record, Some(3));
    }
    #[test]
    fn hash_known_answer_and_cancel() {
        let source = storage::MemorySource(b"abc".to_vec());
        assert_eq!(
            hash_source(&source, &AtomicBool::new(false), |_| {})
                .unwrap()
                .unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hash_source(&source, &AtomicBool::new(true), |_| {})
            .unwrap()
            .is_none());
        assert_eq!(&source.0, b"abc");
    }
    #[test]
    fn evidence_open_denies_concurrent_write_handles() {
        let path = std::env::temp_dir().join(format!("daemoncore-lock-{}.img", std::process::id()));
        let renamed_path = path.with_extension("renamed.img");
        std::fs::write(&path, b"evidence").unwrap();
        let source = storage::Image::open(&path).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, &renamed_path).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        source.verify_unchanged().unwrap();
        drop(source);
        std::fs::remove_file(path).unwrap();
    }
}
