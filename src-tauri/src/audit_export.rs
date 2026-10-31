use crate::{audit, destination, err, verify_audit_chain, AppState, Result};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

const MAX_EVENT_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const ANCHOR_GUIDANCE: &str = "Preserve this checkpoint and its head hash in independently controlled immutable storage. This bundle alone is not an external trust anchor.";
const MAX_ESCAPED_BYTES_PER_INPUT_BYTE: u64 = 6;
const MAX_EVENT_JSON_OVERHEAD: u64 = 256;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEvent {
    id: i64,
    timestamp: String,
    event: String,
    payload: String,
    previous: String,
    hash: String,
}

#[derive(Serialize, Clone)]
pub struct AuditCheckpoint {
    pub directory: String,
    pub records: usize,
    pub head_sha256: String,
    pub checksums_sha256: String,
    pub anchor_status: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct CheckpointVerification {
    pub records: usize,
    pub head_sha256: String,
    pub anchor_match: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointMetadata {
    format: String,
    chain_verified_before_export: bool,
    record_count: usize,
    first_record_id: Option<i64>,
    last_record_id: Option<i64>,
    head_sha256: String,
    hash_algorithm: String,
    export_started_unix_ns: String,
    export_finished_unix_ns: String,
    anchor_guidance: String,
    signature: Option<serde_json::Value>,
    externally_anchored: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionMetadata {
    state: String,
    checksums_sha256: String,
    head_sha256: String,
    externally_anchored: bool,
}

fn load_events(db: &Connection) -> Result<Vec<AuditEvent>> {
    let mut statement = db
        .prepare("SELECT id,timestamp,event,payload,previous,hash FROM audit ORDER BY id")
        .map_err(err)?;
    let rows = statement
        .query_map([], |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event: row.get(2)?,
                payload: row.get(3)?,
                previous: row.get(4)?,
                hash: row.get(5)?,
            })
        })
        .map_err(err)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(err)
}

fn bounded_event_stream_size(records: u64, text_bytes: u64) -> Result<u64> {
    let escaped_bytes = text_bytes
        .checked_mul(MAX_ESCAPED_BYTES_PER_INPUT_BYTE)
        .ok_or("Audit checkpoint size overflow")?;
    let structural_bytes = records
        .checked_mul(MAX_EVENT_JSON_OVERHEAD)
        .ok_or("Audit checkpoint size overflow")?;
    let bound = escaped_bytes
        .checked_add(structural_bytes)
        .ok_or("Audit checkpoint size overflow")?;
    if bound > MAX_EVENT_STREAM_BYTES {
        return Err(format!(
            "The audit history is too large to export safely: its conservative JSONL bound exceeds the {} MiB checkpoint-verification limit.",
            MAX_EVENT_STREAM_BYTES / (1024 * 1024)
        ));
    }
    Ok(bound)
}

fn checkpoint_event_stream_bound(db: &Connection) -> Result<u64> {
    let (records, text_bytes): (i64, i64) = db
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(timestamp AS BLOB)) + length(CAST(event AS BLOB)) + length(CAST(payload AS BLOB)) + length(CAST(previous AS BLOB)) + length(CAST(hash AS BLOB))), 0) FROM audit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(err)?;
    bounded_event_stream_size(
        u64::try_from(records).map_err(err)?,
        u64::try_from(text_bytes).map_err(err)?,
    )
}

fn encode_events_bounded(events: &[AuditEvent], maximum_bytes: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for event in events {
        let mut line = serde_json::to_vec(event).map_err(err)?;
        line.push(b'\n');
        let next_length = (bytes.len() as u64)
            .checked_add(line.len() as u64)
            .ok_or("Audit checkpoint event stream size overflow")?;
        if next_length > maximum_bytes {
            return Err(format!(
                "Audit checkpoint event stream exceeds its {maximum_bytes}-byte verification limit."
            ));
        }
        bytes.extend_from_slice(&line);
    }
    Ok(bytes)
}

fn encode_events(events: &[AuditEvent]) -> Result<Vec<u8>> {
    encode_events_bounded(events, MAX_EVENT_STREAM_BYTES)
}

fn create_new_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)
}

struct StagedDirectory {
    path: std::path::PathBuf,
    published: bool,
}

impl StagedDirectory {
    fn create(path: std::path::PathBuf) -> Result<Self> {
        fs::create_dir(&path).map_err(err)?;
        Ok(Self {
            path,
            published: false,
        })
    }

    fn publish(mut self, destination: &Path) -> Result<()> {
        destination::publish_new(&self.path, destination).map_err(err)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedDirectory {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn read_bundle_file(directory: &Path, name: &str, maximum_bytes: u64) -> Result<Vec<u8>> {
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(err)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("Checkpoint entry {name} is not a regular file."));
    }
    let file = fs::File::open(path).map_err(err)?;
    let opened_metadata = file.metadata().map_err(err)?;
    if !opened_metadata.is_file() || opened_metadata.len() > maximum_bytes {
        return Err(format!(
            "Checkpoint entry {name} exceeds the {maximum_bytes}-byte verification limit."
        ));
    }
    let initial_length = opened_metadata.len();
    let mut limited = file.take(maximum_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes).map_err(err)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!(
            "Checkpoint entry {name} exceeds the {maximum_bytes}-byte verification limit."
        ));
    }
    if limited.get_ref().metadata().map_err(err)?.len() != initial_length
        || bytes.len() as u64 != initial_length
    {
        return Err(format!("Checkpoint entry {name} changed while being read."));
    }
    Ok(bytes)
}

fn validate_bundle_entries(directory: &Path) -> Result<()> {
    let expected = BTreeSet::from([
        "checkpoint.json".to_owned(),
        "checksums.sha256".to_owned(),
        "completion.json".to_owned(),
        "events.jsonl".to_owned(),
    ]);
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(err)? {
        let entry = entry.map_err(err)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Checkpoint contains a non-UTF-8 entry name.")?;
        if !expected.contains(&name) || !found.insert(name.clone()) {
            return Err(format!("Unexpected checkpoint entry: {name}"));
        }
    }
    if found != expected {
        return Err("Checkpoint folder is missing one or more required files.".into());
    }
    Ok(())
}

fn verify_bundle(
    directory: &Path,
    expected_head_sha256: Option<&str>,
) -> Result<CheckpointVerification> {
    if let Some(expected) = expected_head_sha256 {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(
                "Expected checkpoint head must be exactly 64 hexadecimal characters.".into(),
            );
        }
    }
    validate_bundle_entries(directory)?;
    let event_bytes = read_bundle_file(directory, "events.jsonl", MAX_EVENT_STREAM_BYTES)?;
    let checkpoint_bytes = read_bundle_file(directory, "checkpoint.json", MAX_METADATA_BYTES)?;
    let checksums_bytes = read_bundle_file(directory, "checksums.sha256", MAX_METADATA_BYTES)?;
    let completion_bytes = read_bundle_file(directory, "completion.json", MAX_METADATA_BYTES)?;

    let checkpoint: CheckpointMetadata = serde_json::from_slice(&checkpoint_bytes)
        .map_err(|e| format!("Invalid checkpoint metadata: {e}"))?;
    let completion: CompletionMetadata = serde_json::from_slice(&completion_bytes)
        .map_err(|e| format!("Invalid checkpoint completion marker: {e}"))?;
    let started = checkpoint
        .export_started_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid checkpoint export start timestamp.")?;
    let finished = checkpoint
        .export_finished_unix_ns
        .parse::<u128>()
        .map_err(|_| "Invalid checkpoint export finish timestamp.")?;
    if checkpoint.format != "daemoncore-audit-checkpoint-v1"
        || checkpoint.hash_algorithm != "SHA-256"
        || !checkpoint.chain_verified_before_export
        || checkpoint.signature.is_some()
        || checkpoint.externally_anchored
        || checkpoint.anchor_guidance != ANCHOR_GUIDANCE
        || finished < started
    {
        return Err("Unsupported or inconsistent audit checkpoint metadata.".into());
    }

    let mut checksums = BTreeMap::new();
    for line in std::str::from_utf8(&checksums_bytes)
        .map_err(|e| format!("Checksum manifest is not UTF-8: {e}"))?
        .lines()
    {
        let mut fields = line.split_whitespace();
        let digest = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !matches!(name, "checkpoint.json" | "events.jsonl")
            || checksums
                .insert(name.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err("Malformed or duplicate checkpoint checksum entry.".into());
        }
    }
    if checksums.len() != 2
        || checksums.get("checkpoint.json")
            != Some(&format!("{:x}", Sha256::digest(&checkpoint_bytes)))
        || checksums.get("events.jsonl") != Some(&format!("{:x}", Sha256::digest(&event_bytes)))
    {
        return Err("Checkpoint file checksum mismatch.".into());
    }
    let checksums_hash = format!("{:x}", Sha256::digest(&checksums_bytes));
    if completion.state != "complete"
        || completion.checksums_sha256 != checksums_hash
        || completion.head_sha256 != checkpoint.head_sha256
        || completion.externally_anchored
    {
        return Err("Checkpoint completion marker does not match the package.".into());
    }

    let mut count = 0usize;
    let mut first_id = None;
    let mut last_id: Option<i64> = None;
    let mut expected_id = Some(1i64);
    let mut expected_previous = String::new();
    for line in event_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let event: AuditEvent = serde_json::from_slice(line)
            .map_err(|e| format!("Invalid audit event {}: {e}", count + 1))?;
        if expected_id != Some(event.id) || event.previous != expected_previous {
            return Err(format!(
                "Audit chain link or record order is invalid at record {}.",
                event.id
            ));
        }
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .map_err(err)?;
        let expected_hash = format!("{:x}", Sha256::digest(encoded));
        if event.hash != expected_hash {
            return Err(format!(
                "Audit event hash is invalid at record {}.",
                event.id
            ));
        }
        if first_id.is_none() {
            first_id = Some(event.id);
        }
        last_id = Some(event.id);
        expected_id = event.id.checked_add(1);
        expected_previous = event.hash;
        count = count.checked_add(1).ok_or("Audit record count overflow")?;
    }
    if count != checkpoint.record_count
        || first_id != checkpoint.first_record_id
        || last_id != checkpoint.last_record_id
        || expected_previous != checkpoint.head_sha256
    {
        return Err(
            "Audit event stream does not match the checkpoint head or record count.".into(),
        );
    }

    let anchor_match = if let Some(expected) = expected_head_sha256 {
        if expected_previous.is_empty() {
            return Err(
                "An empty audit log has no chain head to compare with an external anchor.".into(),
            );
        }
        if !expected_previous.eq_ignore_ascii_case(expected) {
            return Err(
                "Checkpoint chain head does not match the independently retained anchor.".into(),
            );
        }
        Some(true)
    } else {
        None
    };

    Ok(CheckpointVerification {
        records: count,
        head_sha256: expected_previous,
        anchor_match,
    })
}

#[tauri::command]
pub async fn verify_audit_checkpoint(
    expected_head_sha256: Option<String>,
) -> Result<Option<CheckpointVerification>> {
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Select an audit checkpoint folder to verify")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(None);
    };
    let expected_head_sha256 = expected_head_sha256
        .map(|expected| expected.trim().to_owned())
        .filter(|expected| !expected.is_empty());
    tauri::async_runtime::spawn_blocking(move || {
        verify_bundle(&folder, expected_head_sha256.as_deref())
    })
    .await
    .map_err(err)?
    .map(Some)
}

#[cfg(test)]
fn write_bundle(
    directory: &Path,
    events: &[AuditEvent],
    started_unix_ns: &str,
    ended_unix_ns: &str,
) -> Result<(String, String)> {
    fs::create_dir(directory).map_err(err)?;
    write_bundle_contents(directory, events, started_unix_ns, ended_unix_ns)
}

fn write_bundle_contents(
    directory: &Path,
    events: &[AuditEvent],
    started_unix_ns: &str,
    ended_unix_ns: &str,
) -> Result<(String, String)> {
    let event_bytes = encode_events(events)?;
    let head = events.last().map(|event| event.hash.as_str()).unwrap_or("");
    let checkpoint = serde_json::json!({
        "format": "daemoncore-audit-checkpoint-v1",
        "chain_verified_before_export": true,
        "record_count": events.len(),
        "first_record_id": events.first().map(|event| event.id),
        "last_record_id": events.last().map(|event| event.id),
        "head_sha256": head,
        "hash_algorithm": "SHA-256",
        "export_started_unix_ns": started_unix_ns,
        "export_finished_unix_ns": ended_unix_ns,
        "signature": null,
        "externally_anchored": false,
        "anchor_guidance": ANCHOR_GUIDANCE
    });
    let checkpoint_bytes = serde_json::to_vec_pretty(&checkpoint).map_err(err)?;
    create_new_file(directory, "events.jsonl", &event_bytes)?;
    create_new_file(directory, "checkpoint.json", &checkpoint_bytes)?;
    let sums = format!(
        "{:x}  checkpoint.json\n{:x}  events.jsonl\n",
        Sha256::digest(&checkpoint_bytes),
        Sha256::digest(&event_bytes)
    );
    create_new_file(directory, "checksums.sha256", sums.as_bytes())?;
    let checksums_hash = format!("{:x}", Sha256::digest(sums.as_bytes()));
    let completion = serde_json::json!({
        "state": "complete",
        "checksums_sha256": checksums_hash,
        "head_sha256": head,
        "externally_anchored": false
    });
    create_new_file(
        directory,
        "completion.json",
        &serde_json::to_vec_pretty(&completion).map_err(err)?,
    )?;
    Ok((head.to_owned(), checksums_hash))
}

#[tauri::command]
pub async fn export_audit_checkpoint(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<AuditCheckpoint>> {
    let application_data = app.path().app_local_data_dir().map_err(err)?;
    let folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Export audit checkpoint to a separately controlled disk")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(folder) = folder else {
        return Ok(None);
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_nanos();
    let (events, starting_head, estimated_size) = {
        let db = state.db.lock().map_err(err)?;
        let check = verify_audit_chain(&db)?;
        if !check.valid {
            return Err(
                "The local audit chain is invalid. Do not export it as a verified checkpoint."
                    .into(),
            );
        }
        let estimated_size = checkpoint_event_stream_bound(&db)?;
        let events = load_events(&db)?;
        let head = events
            .last()
            .map(|event| event.hash.clone())
            .unwrap_or_default();
        (events, head, estimated_size)
    };
    let canonical_folder = tauri::async_runtime::spawn_blocking({
        let source = application_data.clone();
        let folder = folder.clone();
        move || destination::check_destination(&source, &folder, estimated_size)
    })
    .await
    .map_err(err)??;
    let directory = canonical_folder.join(format!("DaemonCore-Audit-{timestamp}"));
    let staging_directory = canonical_folder.join(format!("DaemonCore-Audit-{timestamp}.partial"));

    let started_unix_ns = timestamp.to_string();
    let end_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_nanos()
        .to_string();
    let staged = StagedDirectory::create(staging_directory.clone()).map_err(|error| {
        format!(
            "Checkpoint staging folder could not be created at {}: {error}",
            staging_directory.display()
        )
    })?;
    let (head_sha256, checksums_sha256) =
        write_bundle_contents(&staging_directory, &events, &started_unix_ns, &end_time).map_err(
            |error| {
                format!(
                    "Checkpoint export could not be staged at {}: {error}",
                    staging_directory.display()
                )
            },
        )?;
    verify_bundle(&staging_directory, Some(&head_sha256))
        .map_err(|error| format!("Staged audit checkpoint failed verification: {error}"))?;
    staged.publish(&directory).map_err(|error| {
        format!(
            "Verified checkpoint could not be published to {}: {error}",
            directory.display()
        )
    })?;
    let result = AuditCheckpoint {
        directory: directory.to_string_lossy().into_owned(),
        records: events.len(),
        head_sha256: head_sha256.clone(),
        checksums_sha256: checksums_sha256.clone(),
        anchor_status: "unanchored",
    };
    let db = state.db.lock().map_err(err)?;
    audit(
        &db,
        "audit_checkpoint_exported",
        &serde_json::json!({
            "directory": directory,
            "records": result.records,
            "checkpoint_head_sha256": result.head_sha256,
            "starting_head_sha256": starting_head,
            "checksums_sha256": result.checksums_sha256,
            "externally_anchored": false
        })
        .to_string(),
    )
    .map_err(|error| {
        format!(
            "Checkpoint files were written to {}, but the completion event could not be added to the local audit log: {error}",
            directory.display()
        )
    })?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_export_bound_matches_verifier_limit() {
        assert_eq!(bounded_event_stream_size(0, 0).unwrap(), 0);
        let largest_text =
            (MAX_EVENT_STREAM_BYTES - MAX_EVENT_JSON_OVERHEAD) / MAX_ESCAPED_BYTES_PER_INPUT_BYTE;
        assert!(bounded_event_stream_size(1, largest_text).is_ok());
        assert!(bounded_event_stream_size(1, largest_text + 1).is_err());
        assert!(bounded_event_stream_size(u64::MAX, 1).is_err());
    }

    #[test]
    fn checkpoint_event_encoder_enforces_exact_byte_limit() {
        let event = AuditEvent {
            id: 1,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: "a".repeat(64),
        };
        let encoded = encode_events_bounded(std::slice::from_ref(&event), 1024).unwrap();
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(
            encode_events_bounded(std::slice::from_ref(&event), encoded.len() as u64 - 1).is_err()
        );
    }

    #[test]
    fn checkpoint_schema_rejects_unknown_fields() {
        let event = r#"{"id":1,"timestamp":"1","event":"opened","payload":"{}","previous":"","hash":"0","unexpected":true}"#;
        assert!(serde_json::from_str::<AuditEvent>(event).is_err());

        let metadata = r#"{"format":"daemoncore-audit-checkpoint-v1","chain_verified_before_export":true,"record_count":0,"first_record_id":null,"last_record_id":null,"head_sha256":"","hash_algorithm":"SHA-256","export_started_unix_ns":"1","export_finished_unix_ns":"2","anchor_guidance":"Preserve this checkpoint and its head hash in independently controlled immutable storage. This bundle alone is not an external trust anchor.","signature":null,"externally_anchored":false,"unexpected":true}"#;
        assert!(serde_json::from_str::<CheckpointMetadata>(metadata).is_err());
    }

    #[test]
    fn checkpoint_bundle_records_head_and_checksums() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-export-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let directory = root.join("checkpoint");
        let mut event = AuditEvent {
            id: 1,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: String::new(),
        };
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .unwrap();
        event.hash = format!("{:x}", Sha256::digest(encoded));
        let events = vec![event];
        let (head, checksums_hash) = write_bundle(&directory, &events, "2", "3").unwrap();
        assert_eq!(head, events[0].hash);
        let checkpoint: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("checkpoint.json")).unwrap()).unwrap();
        assert_eq!(checkpoint["record_count"], 1);
        assert_eq!(checkpoint["head_sha256"], head);
        assert_eq!(checkpoint["externally_anchored"], false);
        let checksums = fs::read(directory.join("checksums.sha256")).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(checksums)), checksums_hash);
        let completion: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("completion.json")).unwrap()).unwrap();
        assert_eq!(completion["state"], "complete");
        let verified = verify_bundle(&directory, None).unwrap();
        assert_eq!(verified.records, 1);
        assert_eq!(verified.head_sha256, head);
        assert_eq!(verified.anchor_match, None);
        assert_eq!(
            verify_bundle(&directory, Some(&head)).unwrap().anchor_match,
            Some(true)
        );
        let error = verify_bundle(&directory, Some(&"0".repeat(64))).unwrap_err();
        assert!(error.contains("does not match the independently retained anchor"));
        let error = verify_bundle(&directory, Some("not-a-hash")).unwrap_err();
        assert!(error.contains("64 hexadecimal characters"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_checkpoint_is_verified_before_no_replace_publish() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-staged-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let staging = root.join("checkpoint.partial");
        let published = root.join("checkpoint");
        let mut event = AuditEvent {
            id: 1,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: String::new(),
        };
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .unwrap();
        event.hash = format!("{:x}", Sha256::digest(encoded));
        let events = [event];
        let staged = StagedDirectory::create(staging.clone()).unwrap();
        let (head, _) = write_bundle_contents(&staging, &events, "2", "3").unwrap();
        assert_eq!(verify_bundle(&staging, Some(&head)).unwrap().records, 1);
        staged.publish(&published).unwrap();
        assert!(!staging.exists());
        assert_eq!(verify_bundle(&published, Some(&head)).unwrap().records, 1);

        let collision_staging = root.join("collision.partial");
        let collision_target = root.join("collision");
        fs::create_dir(&collision_target).unwrap();
        fs::write(collision_target.join("preserve.txt"), b"original").unwrap();
        let staged_collision = StagedDirectory::create(collision_staging.clone()).unwrap();
        write_bundle_contents(&collision_staging, &events, "2", "3").unwrap();
        assert!(staged_collision.publish(&collision_target).is_err());
        assert!(!collision_staging.exists());
        assert_eq!(
            fs::read(collision_target.join("preserve.txt")).unwrap(),
            b"original"
        );

        let occupied_staging = root.join("occupied.partial");
        fs::create_dir(&occupied_staging).unwrap();
        fs::write(occupied_staging.join("preserve.txt"), b"other export").unwrap();
        assert!(StagedDirectory::create(occupied_staging.clone()).is_err());
        assert_eq!(
            fs::read(occupied_staging.join("preserve.txt")).unwrap(),
            b"other export"
        );

        let invalid_staging = root.join("invalid.partial");
        let invalid_guard = StagedDirectory::create(invalid_staging.clone()).unwrap();
        let (invalid_head, _) = write_bundle_contents(&invalid_staging, &events, "2", "3").unwrap();
        fs::write(invalid_staging.join("events.jsonl"), b"changed after write").unwrap();
        assert!(verify_bundle(&invalid_staging, Some(&invalid_head)).is_err());
        drop(invalid_guard);
        assert!(!invalid_staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_verifier_detects_rehashed_event_tampering() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-tamper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let directory = root.join("checkpoint");
        let mut event = AuditEvent {
            id: 1,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: String::new(),
        };
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .unwrap();
        event.hash = format!("{:x}", Sha256::digest(encoded));
        write_bundle(&directory, &[event], "2", "3").unwrap();
        let original = fs::read_to_string(directory.join("events.jsonl")).unwrap();
        let mut modified: serde_json::Value = serde_json::from_str(original.trim()).unwrap();
        modified["payload"] = serde_json::Value::String("tampered".into());
        let tampered_events = format!("{}\n", serde_json::to_string(&modified).unwrap());
        fs::write(directory.join("events.jsonl"), &tampered_events).unwrap();

        let checkpoint_bytes = fs::read(directory.join("checkpoint.json")).unwrap();
        let checksums = format!(
            "{:x}  checkpoint.json\n{:x}  events.jsonl\n",
            Sha256::digest(&checkpoint_bytes),
            Sha256::digest(tampered_events.as_bytes())
        );
        fs::write(directory.join("checksums.sha256"), &checksums).unwrap();
        let mut completion: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("completion.json")).unwrap()).unwrap();
        completion["checksums_sha256"] =
            serde_json::Value::String(format!("{:x}", Sha256::digest(checksums.as_bytes())));
        fs::write(
            directory.join("completion.json"),
            serde_json::to_vec_pretty(&completion).unwrap(),
        )
        .unwrap();

        let error = verify_bundle(&directory, None).unwrap_err();
        assert!(error.contains("Audit event hash is invalid at record 1"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_verifier_bounds_file_reads() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-size-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("oversized.bin"), b"1234").unwrap();

        let error = read_bundle_file(&root, "oversized.bin", 3).unwrap_err();
        assert!(error.contains("verification limit"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_verifier_rejects_unlisted_folder_entries() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-extra-entry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let directory = root.join("checkpoint");
        let mut event = AuditEvent {
            id: 1,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: String::new(),
        };
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .unwrap();
        event.hash = format!("{:x}", Sha256::digest(encoded));
        write_bundle(&directory, &[event], "2", "3").unwrap();
        fs::write(directory.join("notes.txt"), b"unverified content").unwrap();

        let error = verify_bundle(&directory, None).unwrap_err();
        assert!(error.contains("Unexpected checkpoint entry: notes.txt"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_verifier_rejects_chain_with_missing_prefix() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("audit-missing-prefix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let directory = root.join("checkpoint");
        let mut event = AuditEvent {
            id: 2,
            timestamp: "1".into(),
            event: "opened".into(),
            payload: "{}".into(),
            previous: String::new(),
            hash: String::new(),
        };
        let encoded = serde_json::to_vec(&(
            &event.previous,
            &event.timestamp,
            &event.event,
            &event.payload,
        ))
        .unwrap();
        event.hash = format!("{:x}", Sha256::digest(encoded));
        write_bundle(&directory, &[event], "2", "3").unwrap();

        let error = verify_bundle(&directory, None).unwrap_err();
        assert!(error.contains("Audit chain link or record order is invalid at record 2"));
        fs::remove_dir_all(root).unwrap();
    }
}
