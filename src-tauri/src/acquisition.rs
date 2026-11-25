use crate::{
    audit, audit_timestamp, err, require_audited_active_case, AppState, Evidence,
    EvidenceRegistration, Job, Result,
};
use daemoncore_ntfs_core::storage::BlockSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::windows::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

const MAX_PHYSICAL_DEVICES: u32 = 32;
const READ_CHUNK: usize = 1024 * 1024;
const MAX_RETRIES: u8 = 3;
const MAX_ERROR_RANGES: usize = 100_000;
const MAX_ERROR_MAP_BYTES: u64 = 128 * 1024 * 1024;
const ACQUISITION_CHECKPOINT_INTERVAL: u64 = 16 * 1024 * 1024;
const MAX_CHECKPOINT_LOG_BYTES: u64 = 64 * 1024 * 1024;
const INCOMPLETE_MARKER: &str = "UNPUBLISHED ACQUISITION: this staged image was not published as a completed, verified package. Do not treat it as verified evidence or use the recovery package verifier as proof of completeness.\n";
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00a0;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405c;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PhysicalDevice {
    pub number: u32,
    pub size_bytes: u64,
    pub bytes_per_sector: u32,
    #[serde(flatten)]
    pub identity: DeviceIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub serial_number: Option<String>,
    pub bus_type: Option<u32>,
    pub identity_error: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceProbeFailure {
    pub number: u32,
    pub message: String,
}

#[derive(Serialize)]
pub struct PhysicalDeviceInventory {
    pub devices: Vec<PhysicalDevice>,
    pub failures: Vec<DeviceProbeFailure>,
}

enum DeviceProbeError {
    Unavailable,
    Failed(String),
}

impl DeviceProbeError {
    fn message(self) -> String {
        match self {
            Self::Unavailable => "The selected physical device is no longer available.".into(),
            Self::Failed(message) => message,
        }
    }
}

struct DeviceSource {
    file: Mutex<File>,
    info: PhysicalDevice,
}

impl DeviceSource {
    fn open(number: u32) -> std::result::Result<Self, DeviceProbeError> {
        if number >= MAX_PHYSICAL_DEVICES {
            return Err(DeviceProbeError::Failed(
                "Physical device number is outside the supported range.".into(),
            ));
        }
        let path = PathBuf::from(format!(r"\\.\PhysicalDrive{number}"));
        let file = open_device_read_only(&path)
            .map_err(|error| classify_device_open_error(number, error))?;
        let mut geometry = [0u8; 64];
        let geometry_bytes =
            device_io_control(&file, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &mut geometry)
                .map_err(DeviceProbeError::Failed)?;
        let mut length_info = [0u8; 8];
        let length_bytes = device_io_control(&file, IOCTL_DISK_GET_LENGTH_INFO, &mut length_info)
            .map_err(DeviceProbeError::Failed)?;
        let (bytes_per_sector, size_bytes) =
            parse_device_geometry(&geometry, geometry_bytes, &length_info, length_bytes)
                .map_err(DeviceProbeError::Failed)?;
        let identity = query_device_identity(&file);
        Ok(Self {
            file: Mutex::new(file),
            info: PhysicalDevice {
                number,
                size_bytes,
                bytes_per_sector,
                identity,
            },
        })
    }
}

fn open_device_read_only(path: &Path) -> std::io::Result<File> {
    // Deny new write handles while acquisition runs. This cannot revoke an existing writer,
    // so the operator must still use a validated hardware write blocker.
    OpenOptions::new().read(true).share_mode(1).open(path)
}

fn classify_device_open_error(number: u32, error: std::io::Error) -> DeviceProbeError {
    match error.raw_os_error() {
        // An absent PhysicalDrive path is normal while probing the bounded device-number range.
        Some(2 | 3) => DeviceProbeError::Unavailable,
        _ => DeviceProbeError::Failed(format!(
            "Could not open PhysicalDrive{number} read-only: {error}"
        )),
    }
}

fn parse_device_geometry(
    geometry: &[u8],
    geometry_bytes: usize,
    length_info: &[u8],
    length_bytes: usize,
) -> Result<(u32, u64)> {
    if geometry_bytes < 32 || geometry_bytes > geometry.len() {
        return Err("The device returned a truncated disk geometry record.".into());
    }
    if length_bytes != 8 || length_bytes > length_info.len() {
        return Err("The device returned a truncated length record.".into());
    }
    let bytes_per_sector = u32::from_le_bytes(
        geometry[20..24]
            .try_into()
            .expect("validated geometry response length"),
    );
    let geometry_size = i64::from_le_bytes(
        geometry[24..32]
            .try_into()
            .expect("validated geometry response length"),
    );
    let size_bytes = i64::from_le_bytes(
        length_info[..8]
            .try_into()
            .expect("validated device length response"),
    );
    if !(512..=65_536).contains(&bytes_per_sector)
        || !bytes_per_sector.is_power_of_two()
        || size_bytes <= 0
        || geometry_size != size_bytes
        || !(size_bytes as u64).is_multiple_of(u64::from(bytes_per_sector))
    {
        return Err("The device reported invalid or inconsistent sector geometry.".into());
    }
    Ok((bytes_per_sector, size_bytes as u64))
}

fn validate_selected_device(expected: &PhysicalDevice, actual: &PhysicalDevice) -> Result<()> {
    if expected != actual {
        return Err(
            "The selected physical device identity or geometry changed. Refresh the device list and confirm the source before acquiring.".into(),
        );
    }
    Ok(())
}

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;
const MAX_STORAGE_DESCRIPTOR_BYTES: usize = 64 * 1024;

fn query_device_identity(file: &File) -> DeviceIdentity {
    // STORAGE_PROPERTY_QUERY { StorageDeviceProperty, PropertyStandardQuery }.
    let query = [0u8; 12];
    let mut header = [0u8; 8];
    let first =
        device_io_control_with_input(file, IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut header);
    let size = match first {
        Ok(8) => u32::from_le_bytes(header[4..8].try_into().expect("fixed-size field")) as usize,
        Ok(_) => return empty_identity(Some("Storage descriptor header was truncated.".into())),
        Err(error) => {
            return empty_identity(Some(error));
        }
    };
    if !(36..=MAX_STORAGE_DESCRIPTOR_BYTES).contains(&size) {
        return empty_identity(Some(
            "Storage descriptor size is invalid or exceeds the 64 KiB bound.".into(),
        ));
    }
    let mut descriptor = vec![0; size];
    let returned = match device_io_control_with_input(
        file,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        &mut descriptor,
    ) {
        Ok(returned) if returned >= 36 && returned <= descriptor.len() => returned,
        Ok(_) => {
            return empty_identity(Some(
                "Storage descriptor response length is invalid.".into(),
            ))
        }
        Err(error) => return empty_identity(Some(error)),
    };
    match parse_device_descriptor(&descriptor[..returned]) {
        Ok(identity) => identity,
        Err(error) => empty_identity(Some(error)),
    }
}

fn empty_identity(identity_error: Option<String>) -> DeviceIdentity {
    DeviceIdentity {
        vendor: None,
        product: None,
        revision: None,
        serial_number: None,
        bus_type: None,
        identity_error,
    }
}

fn device_io_control_with_input(
    file: &File,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    use std::os::windows::io::AsRawHandle;
    unsafe extern "system" {
        fn DeviceIoControl(
            device: *mut std::ffi::c_void,
            code: u32,
            input: *mut std::ffi::c_void,
            input_length: u32,
            output: *mut std::ffi::c_void,
            output_length: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut returned = 0u32;
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input.as_ptr().cast_mut().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if returned as usize > output.len() {
        return Err("The device returned an invalid storage descriptor length.".into());
    }
    Ok(returned as usize)
}

fn parse_device_descriptor(bytes: &[u8]) -> std::result::Result<DeviceIdentity, String> {
    if bytes.len() < 36 {
        return Err("Storage device descriptor is truncated.".into());
    }
    let declared_size =
        u32::from_le_bytes(bytes[4..8].try_into().expect("fixed-size field")) as usize;
    if declared_size < 36 || declared_size > bytes.len() {
        return Err("Storage device descriptor declares an invalid size.".into());
    }
    let field = |offset: usize| -> std::result::Result<Option<String>, String> {
        let position = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("fixed-size field"),
        ) as usize;
        if position == 0 {
            return Ok(None);
        }
        if position < 36 || position >= declared_size {
            return Err("Storage device descriptor contains an invalid string offset.".into());
        }
        let remaining = &bytes[position..declared_size];
        let end = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("Storage device descriptor string is not terminated.")?;
        if end > 256 {
            return Err("Storage device descriptor string exceeds the 256-byte limit.".into());
        }
        let value = String::from_utf8_lossy(&remaining[..end]).trim().to_owned();
        Ok((!value.is_empty()).then_some(value))
    };
    Ok(DeviceIdentity {
        vendor: field(12)?,
        product: field(16)?,
        revision: field(20)?,
        serial_number: field(24)?,
        bus_type: Some(u32::from_le_bytes(
            bytes[28..32].try_into().expect("fixed-size field"),
        )),
        identity_error: None,
    })
}

impl BlockSource for DeviceSource {
    fn len(&self) -> u64 {
        self.info.size_bytes
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
        crate::storage::checked_range(self.len(), offset, buffer.len())?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("Physical device handle lock failed"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buffer)
    }
}

fn device_io_control(file: &File, code: u32, output: &mut [u8]) -> Result<usize> {
    use std::os::windows::io::AsRawHandle;
    unsafe extern "system" {
        fn DeviceIoControl(
            device: *mut std::ffi::c_void,
            code: u32,
            input: *mut std::ffi::c_void,
            input_length: u32,
            output: *mut std::ffi::c_void,
            output_length: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut returned = 0u32;
    // The handle is opened with read access only; these IOCTLs query geometry.
    let succeeded = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            std::ptr::null_mut(),
            0,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if returned as usize > output.len() {
        return Err("The device returned an invalid geometry response length.".into());
    }
    Ok(returned as usize)
}

#[tauri::command]
pub fn list_physical_devices() -> PhysicalDeviceInventory {
    collect_physical_device_inventory(|number| DeviceSource::open(number).map(|device| device.info))
}

fn collect_physical_device_inventory(
    mut probe: impl FnMut(u32) -> std::result::Result<PhysicalDevice, DeviceProbeError>,
) -> PhysicalDeviceInventory {
    let mut inventory = PhysicalDeviceInventory {
        devices: Vec::new(),
        failures: Vec::new(),
    };
    for number in 0..MAX_PHYSICAL_DEVICES {
        match probe(number) {
            Ok(device) => inventory.devices.push(device),
            Err(DeviceProbeError::Unavailable) => {}
            Err(DeviceProbeError::Failed(message)) => {
                inventory
                    .failures
                    .push(DeviceProbeFailure { number, message });
            }
        }
    }
    inventory
}

#[derive(Deserialize, Serialize)]
struct ReadErrorRange {
    offset: u64,
    length: u64,
    attempts: u8,
    error: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AcquisitionCheckpointState {
    schema_version: u32,
    case_id: i64,
    created_unix_ns: String,
    device: PhysicalDevice,
    committed_bytes: u64,
    read_error_bytes: u64,
    read_error_ranges: usize,
    read_error_sha256: String,
}

#[derive(Deserialize, Serialize)]
struct AcquisitionCheckpointRecord {
    state: AcquisitionCheckpointState,
    previous_sha256: Option<String>,
    record_sha256: String,
}

struct ValidatedAcquisitionResume {
    state: AcquisitionCheckpointState,
    previous_sha256: String,
    valid_log_bytes: u64,
    errors: Vec<ReadErrorRange>,
    error_digest: Sha256,
}

fn source_is_unavailable(error: &std::io::Error) -> bool {
    // Do not turn a changed or removed source into zero-filled sectors. ERROR_IO_DEVICE
    // is deliberately excluded because it can describe a recoverable bad sector.
    matches!(
        error.raw_os_error(),
        Some(21 | 55 | 321 | 1110 | 1112 | 1164 | 1167)
    )
}

fn append_read_error(errors: &mut Vec<ReadErrorRange>, offset: u64, length: u64, error: String) {
    if let Some(previous) = errors.last_mut() {
        if previous.offset.checked_add(previous.length) == Some(offset)
            && previous.attempts == MAX_RETRIES
            && previous.error == error
        {
            previous.length = previous.length.saturating_add(length);
            return;
        }
    }
    errors.push(ReadErrorRange {
        offset,
        length,
        attempts: MAX_RETRIES,
        error,
    });
}

fn read_range_with_recovery(
    source: &dyn BlockSource,
    offset: u64,
    buffer: &mut [u8],
    sector_bytes: usize,
    cancel: &AtomicBool,
    errors: &mut Vec<ReadErrorRange>,
) -> Result<bool> {
    let mut last_error = None;
    for _ in 0..MAX_RETRIES {
        if cancel.load(Ordering::SeqCst) {
            return Ok(false);
        }
        match source.read_exact_at(offset, buffer) {
            Ok(()) => return Ok(true),
            Err(error) if source_is_unavailable(&error) => {
                return Err(format!(
                    "Physical source became unavailable at byte offset {offset}; acquisition stopped without publishing the partial image: {error}"
                ));
            }
            Err(error) => last_error = Some(error.to_string().chars().take(1000).collect()),
        }
    }

    if buffer.len() > sector_bytes {
        let sector_count = buffer.len() / sector_bytes;
        let left_bytes = (sector_count / 2) * sector_bytes;
        if left_bytes == 0 || left_bytes >= buffer.len() {
            return Err("Acquisition recovery could not split an aligned source range.".into());
        }
        let (left, right) = buffer.split_at_mut(left_bytes);
        if !read_range_with_recovery(source, offset, left, sector_bytes, cancel, errors)? {
            return Ok(false);
        }
        return read_range_with_recovery(
            source,
            offset + left_bytes as u64,
            right,
            sector_bytes,
            cancel,
            errors,
        );
    }

    if buffer.len() != sector_bytes {
        return Err(
            "Acquisition reached an unreadable range smaller than one device sector.".into(),
        );
    }
    buffer.fill(0);
    append_read_error(
        errors,
        offset,
        buffer.len() as u64,
        last_error.unwrap_or_else(|| "Unspecified read error".into()),
    );
    Ok(true)
}

#[derive(Serialize)]
struct AcquisitionManifest<'a> {
    tool: &'static str,
    version: &'static str,
    package_type: &'static str,
    case_id: i64,
    created_unix_ns: String,
    device_number: u32,
    device_identity: &'a PhysicalDevice,
    source_size_bytes: u64,
    bytes_per_sector: u32,
    retries_per_range: u8,
    hardware_write_blocker_attested: bool,
    acquisition_method: &'static str,
    image_name: &'static str,
    image_sha256: &'a str,
    read_error_ranges: usize,
    limitations: &'static str,
}

#[derive(Serialize)]
struct AcquisitionCompletion<'a> {
    state: &'static str,
    image_sha256: &'a str,
    checksums_sha256: String,
    read_error_ranges: usize,
}

#[derive(Debug)]
struct PublishedAcquisition {
    directory: PathBuf,
    image_path: PathBuf,
    image_sha256: String,
    size_bytes: u64,
    read_error_ranges: usize,
}

struct AcquisitionTarget<'a> {
    final_directory: &'a Path,
    staging_path: &'a Path,
    created_unix_ns: u128,
}

struct AcquisitionOptions {
    case_id: i64,
    write_blocker_attested: bool,
}

struct StagingDirectory(Option<PathBuf>);

impl StagingDirectory {
    fn discard(&mut self) -> Result<()> {
        if let Some(path) = self.0.as_ref() {
            fs::remove_dir_all(path).map_err(err)?;
        }
        self.0 = None;
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let image_path = path.join("image.raw");
            if image_path.is_file() {
                // Keep work from a failed long-running acquisition, but make it
                // impossible to mistake the unverified image for a package.
                if let Ok(image) = File::open(&image_path) {
                    let _ = image.sync_all();
                }
                let _ = write_incomplete_marker(&path);
            } else {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn write_incomplete_marker(directory: &Path) -> Result<()> {
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("INCOMPLETE.txt"))
        .map_err(err)?;
    marker
        .write_all(INCOMPLETE_MARKER.as_bytes())
        .map_err(err)?;
    marker.sync_all().map_err(err)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(err)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(err)?;
    file.sync_all().map_err(err)
}

fn checkpoint_digest(
    state: &AcquisitionCheckpointState,
    previous_sha256: Option<&str>,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(state, previous_sha256)).map_err(err)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn append_checkpoint(
    file: &mut File,
    state: AcquisitionCheckpointState,
    previous_sha256: Option<&str>,
) -> Result<String> {
    let record_sha256 = checkpoint_digest(&state, previous_sha256)?;
    let record = AcquisitionCheckpointRecord {
        state,
        previous_sha256: previous_sha256.map(str::to_owned),
        record_sha256: record_sha256.clone(),
    };
    let mut bytes = serde_json::to_vec(&record).map_err(err)?;
    bytes.push(b'\n');
    let next_len = file
        .metadata()
        .map_err(err)?
        .len()
        .checked_add(bytes.len() as u64)
        .ok_or("Acquisition checkpoint log size overflow")?;
    if next_len > MAX_CHECKPOINT_LOG_BYTES {
        return Err(
            "Acquisition stopped because the checkpoint log exceeded its 64 MiB limit.".into(),
        );
    }
    file.write_all(&bytes).map_err(err)?;
    file.sync_all().map_err(err)?;
    Ok(record_sha256)
}

fn read_error_prefix(
    path: &Path,
    length: u64,
    expected_sha256: &str,
) -> Result<(Vec<ReadErrorRange>, Sha256)> {
    let metadata = fs::metadata(path).map_err(err)?;
    if length > MAX_ERROR_MAP_BYTES || length > metadata.len() {
        return Err(
            "The interrupted acquisition error map is truncated or exceeds its safety limit."
                .into(),
        );
    }
    let mut file = File::open(path).map_err(err)?;
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes).map_err(err)?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_sha256 {
        return Err("The interrupted acquisition error map does not match its checkpoint.".into());
    }
    if bytes.last().is_some_and(|byte| *byte != b'\n') {
        return Err("The interrupted acquisition error map ends with a partial record.".into());
    }
    let mut ranges: Vec<ReadErrorRange> = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let range: ReadErrorRange = serde_json::from_slice(line).map_err(err)?;
        if range.length == 0 || range.attempts != MAX_RETRIES {
            return Err("The interrupted acquisition error map contains an invalid range.".into());
        }
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or("The interrupted acquisition error map contains an overflowing range.")?;
        if let Some(previous) = ranges.last() {
            if previous.offset + previous.length > range.offset {
                return Err("The interrupted acquisition error map contains overlapping or unordered ranges.".into());
            }
        }
        ranges.push(range);
        let _ = end;
    }
    let mut digest = Sha256::new();
    digest.update(&bytes);
    Ok((ranges, digest))
}

fn load_acquisition_resume(
    directory: &Path,
    expected_device: &PhysicalDevice,
    expected_case_id: i64,
) -> Result<ValidatedAcquisitionResume> {
    let directory_metadata = fs::symlink_metadata(directory).map_err(err)?;
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        return Err("Select a real incomplete acquisition folder.".into());
    }
    let expected_entries = [
        "INCOMPLETE.txt",
        "image.raw",
        "read-errors.jsonl",
        "resume.jsonl",
    ];
    for name in expected_entries {
        let metadata = fs::symlink_metadata(directory.join(name)).map_err(err)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(
                "The interrupted acquisition folder contains a non-regular or linked file.".into(),
            );
        }
    }
    let mut actual_entries: Vec<String> = fs::read_dir(directory)
        .map_err(err)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(err)
        })
        .collect::<Result<_>>()?;
    actual_entries.sort();
    let mut sorted_expected = expected_entries.map(str::to_owned);
    sorted_expected.sort();
    if actual_entries != sorted_expected {
        return Err(
            "The selected folder is not a supported interrupted acquisition staging folder.".into(),
        );
    }
    let marker = fs::read_to_string(directory.join("INCOMPLETE.txt")).map_err(err)?;
    if !marker.contains("UNPUBLISHED ACQUISITION") {
        return Err(
            "The selected folder does not contain a valid incomplete-acquisition marker.".into(),
        );
    }

    let log_path = directory.join("resume.jsonl");
    let log_metadata = fs::metadata(&log_path).map_err(err)?;
    if log_metadata.len() == 0 || log_metadata.len() > MAX_CHECKPOINT_LOG_BYTES {
        return Err(
            "The interrupted acquisition checkpoint log is empty or exceeds its 64 MiB limit."
                .into(),
        );
    }
    let log = fs::read(&log_path).map_err(err)?;
    let valid_log_bytes = log
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .ok_or("The interrupted acquisition checkpoint log has no complete record.")?;
    let mut previous_sha256: Option<String> = None;
    let mut previous_state: Option<AcquisitionCheckpointState> = None;
    for line in log[..valid_log_bytes]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: AcquisitionCheckpointRecord = serde_json::from_slice(line).map_err(err)?;
        if record.previous_sha256 != previous_sha256
            || checkpoint_digest(&record.state, previous_sha256.as_deref())? != record.record_sha256
        {
            return Err("The interrupted acquisition checkpoint chain is invalid.".into());
        }
        if let Some(previous) = previous_state.as_ref() {
            if record.state.schema_version != previous.schema_version
                || record.state.case_id != previous.case_id
                || record.state.created_unix_ns != previous.created_unix_ns
                || record.state.device != previous.device
                || record.state.committed_bytes < previous.committed_bytes
                || record.state.read_error_bytes < previous.read_error_bytes
                || record.state.read_error_ranges < previous.read_error_ranges
            {
                return Err(
                    "The interrupted acquisition checkpoint sequence is inconsistent.".into(),
                );
            }
        } else if record.state.committed_bytes != 0
            || record.state.read_error_bytes != 0
            || record.state.read_error_ranges != 0
        {
            return Err(
                "The interrupted acquisition checkpoint log has no initial checkpoint.".into(),
            );
        }
        previous_sha256 = Some(record.record_sha256);
        previous_state = Some(record.state);
    }
    let state = previous_state.ok_or("The interrupted acquisition checkpoint log is empty.")?;
    if state.schema_version != 1
        || state.case_id != expected_case_id
        || state.device != *expected_device
        || state.committed_bytes > expected_device.size_bytes
        || state.committed_bytes % u64::from(expected_device.bytes_per_sector) != 0
    {
        return Err("The incomplete acquisition belongs to a different case or source device, or has invalid geometry.".into());
    }
    let image_metadata = fs::metadata(directory.join("image.raw")).map_err(err)?;
    if image_metadata.len() < state.committed_bytes {
        return Err(
            "The interrupted acquisition image is shorter than its last committed checkpoint."
                .into(),
        );
    }
    let (errors, error_digest) = read_error_prefix(
        &directory.join("read-errors.jsonl"),
        state.read_error_bytes,
        &state.read_error_sha256,
    )?;
    if errors.len() != state.read_error_ranges
        || errors.iter().any(|range| {
            range.offset + range.length > state.committed_bytes
                || !range
                    .offset
                    .is_multiple_of(u64::from(expected_device.bytes_per_sector))
                || !range
                    .length
                    .is_multiple_of(u64::from(expected_device.bytes_per_sector))
        })
    {
        return Err(
            "The interrupted acquisition error map does not match the committed image range."
                .into(),
        );
    }
    Ok(ValidatedAcquisitionResume {
        state,
        previous_sha256: previous_sha256.expect("a valid log contains an initial record"),
        valid_log_bytes: valid_log_bytes as u64,
        errors,
        error_digest,
    })
}

fn verify_acquisition_prefix(
    source: &dyn BlockSource,
    directory: &Path,
    resume: &ValidatedAcquisitionResume,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, usize),
) -> Result<Option<Sha256>> {
    let mut image = File::open(directory.join("image.raw")).map_err(err)?;
    let mut source_buffer = vec![0; READ_CHUNK];
    let mut image_buffer = vec![0; READ_CHUNK];
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    let mut range_index = 0usize;
    while offset < resume.state.committed_bytes {
        if cancel.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let count = (resume.state.committed_bytes - offset).min(READ_CHUNK as u64) as usize;
        image.read_exact(&mut image_buffer[..count]).map_err(err)?;
        let end = offset + count as u64;
        while range_index < resume.errors.len()
            && resume.errors[range_index].offset + resume.errors[range_index].length <= offset
        {
            range_index += 1;
        }
        let mut cursor = offset;
        while cursor < end {
            if let Some(range) = resume.errors.get(range_index) {
                let range_end = range.offset + range.length;
                if range.offset <= cursor && cursor < range_end {
                    let segment_end = end.min(range_end);
                    let start = (cursor - offset) as usize;
                    let finish = (segment_end - offset) as usize;
                    if image_buffer[start..finish].iter().any(|byte| *byte != 0) {
                        return Err(format!(
                            "The staged image does not contain zero-filled bytes for its recorded unreadable range at offset {cursor}."
                        ));
                    }
                    source
                        .read_exact_at(cursor, &mut source_buffer[start..finish])
                        .map_err(|error| {
                            format!(
                                "A previously unreadable source range could not be revalidated at byte offset {cursor}: {error}"
                            )
                        })?;
                    if source_buffer[start..finish].iter().any(|byte| *byte != 0) {
                        return Err(format!(
                            "The source now returns different bytes for a range recorded as unreadable at offset {cursor}; resuming would mix acquisition states."
                        ));
                    }
                    cursor = segment_end;
                    if cursor == range_end {
                        range_index += 1;
                    }
                    continue;
                }
                if range.offset < cursor {
                    return Err("The interrupted acquisition error ranges are inconsistent.".into());
                }
            }
            let segment_end = resume
                .errors
                .get(range_index)
                .map_or(end, |range| end.min(range.offset));
            if segment_end <= cursor {
                return Err("The interrupted acquisition error ranges are inconsistent.".into());
            }
            let start = (cursor - offset) as usize;
            let finish = (segment_end - offset) as usize;
            source
                .read_exact_at(cursor, &mut source_buffer[start..finish])
                .map_err(|error| {
                    format!(
                        "Could not revalidate the interrupted image against the selected source at byte offset {cursor}: {error}"
                    )
                })?;
            if source_buffer[start..finish] != image_buffer[start..finish] {
                return Err(format!(
                    "The selected source no longer matches the committed staged image at byte offset {cursor}; resuming would mix different source contents."
                ));
            }
            cursor = segment_end;
        }
        digest.update(&image_buffer[..count]);
        offset = end;
        progress(
            offset.saturating_mul(2),
            source
                .len()
                .checked_mul(2)
                .and_then(|total| total.checked_add(resume.state.committed_bytes))
                .ok_or("Acquisition size overflow")?,
            resume.errors.len(),
        );
    }
    Ok(Some(digest))
}

fn hash_file(path: &Path, mut progress: impl FnMut(u64)) -> Result<String> {
    let mut file = File::open(path).map_err(err)?;
    let length = file.metadata().map_err(err)?.len();
    let mut buffer = vec![0; READ_CHUNK];
    let mut read = 0u64;
    let mut digest = Sha256::new();
    loop {
        let count = file.read(&mut buffer).map_err(err)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        read = read
            .checked_add(count as u64)
            .ok_or("Image size overflow")?;
        progress(count as u64);
    }
    if read != length {
        return Err("The staged image changed during destination verification.".into());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn checksum_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(err)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    loop {
        let count = file.read(&mut buffer).map_err(err)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn write_checksums(directory: &Path, image_name: &str) -> Result<Vec<u8>> {
    let names = ["manifest.json", "read-errors.jsonl", image_name];
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("checksums.sha256"))
        .map_err(err)?;
    for name in names {
        writeln!(file, "{}  {name}", checksum_file(&directory.join(name))?).map_err(err)?;
    }
    file.sync_all().map_err(err)?;
    fs::read(directory.join("checksums.sha256")).map_err(err)
}

fn capture(
    source: &dyn BlockSource,
    device: &PhysicalDevice,
    case_id: i64,
    destination: &Path,
    write_blocker_attested: bool,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64, usize),
) -> Result<Option<PublishedAcquisition>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_nanos();
    let final_directory = destination.join(format!("DaemonCore-Acquisition-{now}"));
    let staging_path = destination.join(format!(".DaemonCore-Acquisition-{now}.partial"));
    let result = capture_into(
        source,
        device,
        AcquisitionTarget {
            final_directory: &final_directory,
            staging_path: &staging_path,
            created_unix_ns: now,
        },
        AcquisitionOptions {
            case_id,
            write_blocker_attested,
        },
        cancel,
        &mut progress,
    );
    match result {
        Err(error) if staging_path.exists() => {
            let marker_warning = match fs::read_to_string(staging_path.join("INCOMPLETE.txt")) {
                Ok(marker) if marker.contains("UNPUBLISHED ACQUISITION") => String::new(),
                Ok(_) => " The incomplete marker is missing or invalid; the package verifier must reject this folder before use.".into(),
                Err(marker_error) => format!(
                    " Could not verify the incomplete marker ({marker_error}); the package verifier must reject this folder before use."
                ),
            };
            Err(format!(
                "{error} Unpublished acquisition data may remain at {}. Preserve this folder. If it has a valid checkpoint, choose Resume interrupted image; the app will compare saved bytes with the selected source before continuing. The package verifier will reject this staging folder until acquisition completes. If source validation fails, keep this folder and start a new acquisition in a new folder.{marker_warning}",
                staging_path.display()
            ))
        }
        result => result,
    }
}

fn capture_into(
    source: &dyn BlockSource,
    device: &PhysicalDevice,
    target: AcquisitionTarget<'_>,
    options: AcquisitionOptions,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, usize),
) -> Result<Option<PublishedAcquisition>> {
    if !options.write_blocker_attested {
        return Err(
            "Attest to a validated hardware write blocker before acquiring a device.".into(),
        );
    }
    if device.size_bytes != source.len()
        || device.bytes_per_sector == 0
        || !source
            .len()
            .is_multiple_of(u64::from(device.bytes_per_sector))
    {
        return Err("The selected device geometry changed or is invalid.".into());
    }
    fs::create_dir(target.staging_path).map_err(err)?;
    let mut staging = StagingDirectory(Some(target.staging_path.to_path_buf()));
    // Flush an unmistakable warning before touching the source so abrupt process
    // termination leaves a discoverable, explicitly unverified staging folder.
    write_incomplete_marker(target.staging_path)?;
    let errors = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.staging_path.join("read-errors.jsonl"))
        .map_err(err)?;
    let mut checkpoint_log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.staging_path.join("resume.jsonl"))
        .map_err(err)?;
    let error_digest = Sha256::new();
    let previous_checkpoint_sha256 = append_checkpoint(
        &mut checkpoint_log,
        AcquisitionCheckpointState {
            schema_version: 1,
            case_id: options.case_id,
            created_unix_ns: target.created_unix_ns.to_string(),
            device: device.clone(),
            committed_bytes: 0,
            read_error_bytes: 0,
            read_error_ranges: 0,
            read_error_sha256: format!("{:x}", error_digest.clone().finalize()),
        },
        None,
    )?;
    let image_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target.staging_path.join("image.raw"))
        .map_err(err)?;

    capture_from_offset(
        source,
        device,
        target,
        options,
        cancel,
        progress,
        &mut staging,
        image_file,
        errors,
        checkpoint_log,
        0,
        0,
        0,
        error_digest,
        Sha256::new(),
        previous_checkpoint_sha256,
        true,
    )
}

fn resume_capture(
    source: &dyn BlockSource,
    device: &PhysicalDevice,
    staging_path: &Path,
    options: AcquisitionOptions,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, usize),
) -> Result<Option<PublishedAcquisition>> {
    match resume_capture_inner(source, device, staging_path, options, cancel, progress) {
        Err(error) => Err(format!(
            "{error} Preserve the interrupted acquisition folder at {}; it remains unverified.",
            staging_path.display()
        )),
        result => result,
    }
}

fn resume_capture_inner(
    source: &dyn BlockSource,
    device: &PhysicalDevice,
    staging_path: &Path,
    options: AcquisitionOptions,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, usize),
) -> Result<Option<PublishedAcquisition>> {
    if !options.write_blocker_attested {
        return Err(
            "Attest to a validated hardware write blocker before resuming acquisition.".into(),
        );
    }
    if device.size_bytes != source.len()
        || device.bytes_per_sector == 0
        || !source
            .len()
            .is_multiple_of(u64::from(device.bytes_per_sector))
    {
        return Err("The selected device geometry changed or is invalid.".into());
    }
    let resume = load_acquisition_resume(staging_path, device, options.case_id)?;
    let created_unix_ns = resume
        .state
        .created_unix_ns
        .parse::<u128>()
        .map_err(|_| "The acquisition checkpoint has an invalid creation timestamp.")?;
    let parent = staging_path
        .parent()
        .ok_or("The interrupted acquisition folder has no destination parent.")?;
    let expected_name = format!(".DaemonCore-Acquisition-{created_unix_ns}.partial");
    if staging_path.file_name().and_then(|name| name.to_str()) != Some(&expected_name) {
        return Err(
            "The interrupted acquisition folder name does not match its checkpoint.".into(),
        );
    }
    let final_directory = parent.join(format!("DaemonCore-Acquisition-{created_unix_ns}"));
    let target = AcquisitionTarget {
        final_directory: &final_directory,
        staging_path,
        created_unix_ns,
    };
    let Some(image_digest) =
        verify_acquisition_prefix(source, staging_path, &resume, cancel, progress)?
    else {
        return Ok(None);
    };

    let mut image_file = OpenOptions::new()
        .write(true)
        .open(staging_path.join("image.raw"))
        .map_err(err)?;
    image_file
        .set_len(resume.state.committed_bytes)
        .map_err(err)?;
    image_file
        .seek(SeekFrom::Start(resume.state.committed_bytes))
        .map_err(err)?;
    let mut errors = OpenOptions::new()
        .write(true)
        .open(staging_path.join("read-errors.jsonl"))
        .map_err(err)?;
    errors.set_len(resume.state.read_error_bytes).map_err(err)?;
    errors
        .seek(SeekFrom::Start(resume.state.read_error_bytes))
        .map_err(err)?;
    let mut checkpoint_log = OpenOptions::new()
        .write(true)
        .open(staging_path.join("resume.jsonl"))
        .map_err(err)?;
    checkpoint_log
        .set_len(resume.valid_log_bytes)
        .map_err(err)?;
    checkpoint_log.seek(SeekFrom::End(0)).map_err(err)?;

    let mut staging = StagingDirectory(Some(staging_path.to_path_buf()));
    capture_from_offset(
        source,
        device,
        target,
        options,
        cancel,
        progress,
        &mut staging,
        image_file,
        errors,
        checkpoint_log,
        resume.state.committed_bytes,
        resume.state.read_error_bytes,
        resume.state.read_error_ranges,
        resume.error_digest,
        image_digest,
        resume.previous_sha256,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn capture_from_offset(
    source: &dyn BlockSource,
    device: &PhysicalDevice,
    target: AcquisitionTarget<'_>,
    options: AcquisitionOptions,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64, usize),
    staging: &mut StagingDirectory,
    mut image_file: File,
    mut errors: File,
    mut checkpoint_log: File,
    mut offset: u64,
    mut error_map_bytes: u64,
    mut error_ranges: usize,
    mut error_digest: Sha256,
    mut image_digest: Sha256,
    mut previous_checkpoint_sha256: String,
    discard_on_cancel: bool,
) -> Result<Option<PublishedAcquisition>> {
    let mut buffer = vec![0; READ_CHUNK];
    let mut last_checkpoint_offset = offset;
    let validation_bytes = offset;
    let total = source
        .len()
        .checked_mul(2)
        .and_then(|total| total.checked_add(validation_bytes))
        .ok_or("Acquisition size overflow")?;
    progress(validation_bytes.saturating_mul(2), total, error_ranges);

    while offset < source.len() {
        if cancel.load(Ordering::SeqCst) {
            if discard_on_cancel {
                staging.discard()?;
            } else {
                image_file.sync_all().map_err(err)?;
                errors.sync_all().map_err(err)?;
                checkpoint_log.sync_all().map_err(err)?;
            }
            return Ok(None);
        }
        let count = (source.len() - offset).min(buffer.len() as u64) as usize;
        let mut chunk_errors = Vec::new();
        if !read_range_with_recovery(
            source,
            offset,
            &mut buffer[..count],
            device.bytes_per_sector as usize,
            cancel,
            &mut chunk_errors,
        )? {
            staging.discard()?;
            return Ok(None);
        }
        if error_ranges
            .checked_add(chunk_errors.len())
            .is_none_or(|count| count > MAX_ERROR_RANGES)
        {
            return Err("Acquisition stopped because the unreadable-range map exceeded its 100,000-range limit.".into());
        }
        for record in chunk_errors {
            let mut line = serde_json::to_vec(&record).map_err(err)?;
            line.push(b'\n');
            error_map_bytes = error_map_bytes
                .checked_add(line.len() as u64)
                .ok_or("Acquisition error-map size overflow")?;
            if error_map_bytes > MAX_ERROR_MAP_BYTES {
                return Err("Acquisition stopped because the unreadable-range map exceeded its 128 MiB limit.".into());
            }
            errors.write_all(&line).map_err(err)?;
            error_digest.update(&line);
            error_ranges += 1;
        }
        image_file.write_all(&buffer[..count]).map_err(err)?;
        image_digest.update(&buffer[..count]);
        offset += count as u64;
        progress(validation_bytes.saturating_add(offset), total, error_ranges);
        if offset.saturating_sub(last_checkpoint_offset) >= ACQUISITION_CHECKPOINT_INTERVAL {
            image_file.sync_all().map_err(err)?;
            errors.sync_all().map_err(err)?;
            previous_checkpoint_sha256 = append_checkpoint(
                &mut checkpoint_log,
                AcquisitionCheckpointState {
                    schema_version: 1,
                    case_id: options.case_id,
                    created_unix_ns: target.created_unix_ns.to_string(),
                    device: device.clone(),
                    committed_bytes: offset,
                    read_error_bytes: error_map_bytes,
                    read_error_ranges: error_ranges,
                    read_error_sha256: format!("{:x}", error_digest.clone().finalize()),
                },
                Some(&previous_checkpoint_sha256),
            )?;
            last_checkpoint_offset = offset;
        }
    }
    image_file.sync_all().map_err(err)?;
    drop(image_file);
    errors.sync_all().map_err(err)?;
    drop(errors);

    if offset != last_checkpoint_offset || offset == 0 {
        let _ = append_checkpoint(
            &mut checkpoint_log,
            AcquisitionCheckpointState {
                schema_version: 1,
                case_id: options.case_id,
                created_unix_ns: target.created_unix_ns.to_string(),
                device: device.clone(),
                committed_bytes: offset,
                read_error_bytes: error_map_bytes,
                read_error_ranges: error_ranges,
                read_error_sha256: format!("{:x}", error_digest.clone().finalize()),
            },
            Some(&previous_checkpoint_sha256),
        )?;
    }
    checkpoint_log.sync_all().map_err(err)?;
    drop(checkpoint_log);

    // Completion metadata distinguishes partial images; keeping one stable
    // filename also avoids a rename after the potentially large image is flushed.
    let image_name = "image.raw";
    let observed_digest = format!("{:x}", image_digest.finalize());
    let verified_digest = hash_file(&target.staging_path.join(image_name), |count| {
        progress(
            validation_bytes
                .saturating_add(source.len())
                .saturating_add(count),
            total,
            error_ranges,
        );
    })?;
    if observed_digest != verified_digest {
        return Err("Acquired image bytes failed destination SHA-256 verification.".into());
    }
    if cancel.load(Ordering::SeqCst) {
        if discard_on_cancel {
            staging.discard()?;
        }
        return Ok(None);
    }
    // From here onward the image has been flushed and read back against the
    // acquisition digest. A crash still cannot make it a package: completion.json
    // is written last and the verifier rejects its absence.
    fs::remove_file(target.staging_path.join("resume.jsonl")).map_err(err)?;
    fs::remove_file(target.staging_path.join("INCOMPLETE.txt")).map_err(err)?;

    let manifest = AcquisitionManifest {
        tool: "DaemonCore Data Recovery",
        version: env!("CARGO_PKG_VERSION"),
        package_type: "physical_device_acquisition",
        case_id: options.case_id,
        created_unix_ns: target.created_unix_ns.to_string(),
        device_number: device.number,
        device_identity: device,
        source_size_bytes: source.len(),
        bytes_per_sector: device.bytes_per_sector,
        retries_per_range: MAX_RETRIES,
        hardware_write_blocker_attested: options.write_blocker_attested,
        acquisition_method: "Windows raw physical-drive read through a handle opened without write access; failed ranges are retried with binary subdivision through the reported sector size",
        image_name,
        image_sha256: &verified_digest,
        read_error_ranges: error_ranges,
        limitations: "The image digest covers bytes written to the output, including zero-filled read-error ranges. read-errors.jsonl identifies ranges that could not be read after retries. Software read-only access does not prove a point-in-time source state; use a validated hardware write blocker and an offline source.",
    };
    write_json(&target.staging_path.join("manifest.json"), &manifest)?;
    let checksums = write_checksums(target.staging_path, image_name)?;
    let state = if error_ranges == 0 {
        "complete"
    } else {
        "partial"
    };
    write_json(
        &target.staging_path.join("completion.json"),
        &AcquisitionCompletion {
            state,
            image_sha256: &verified_digest,
            checksums_sha256: format!("{:x}", Sha256::digest(&checksums)),
            read_error_ranges: error_ranges,
        },
    )?;
    crate::destination::publish_new(target.staging_path, target.final_directory).map_err(
        |error| {
            format!(
                "Could not publish the staged acquisition package from {} to {}: {error}",
                target.staging_path.display(),
                target.final_directory.display()
            )
        },
    )?;
    staging.0 = None;
    Ok(Some(PublishedAcquisition {
        directory: target.final_directory.to_path_buf(),
        image_path: target.final_directory.join(image_name),
        image_sha256: verified_digest,
        size_bytes: source.len(),
        read_error_ranges: error_ranges,
    }))
}

fn activate_acquired_image(
    state: &AppState,
    device_number: u32,
    case_id: i64,
    package: &PublishedAcquisition,
) -> Result<()> {
    let image = std::sync::Arc::new(crate::storage::Image::open(&package.image_path).map_err(err)?);
    let mut prefix = vec![0; image.len().min(512) as usize];
    image.read_exact_at(0, &mut prefix).map_err(err)?;
    let mut db = state.db.lock().map_err(err)?;
    let source_id = state.generation.fetch_add(1, Ordering::SeqCst);
    let path = package.image_path.to_string_lossy().into_owned();
    let name = package
        .image_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let filesystem = crate::detect(&prefix);
    let opened_at = audit_timestamp(SystemTime::now())?;
    let evidence_record_id = crate::record_evidence_open(
        &mut db,
        &EvidenceRegistration {
            case_id,
            source_id,
            path: &path,
            name: &name,
            size: package.size_bytes,
            filesystem: &filesystem,
            opened_at: &opened_at,
        },
    )?;
    let tx = db.transaction().map_err(err)?;
    let changed = tx
        .execute(
            "UPDATE evidence_sources SET sha256=?1,status='hashed' WHERE id=?2 AND case_id=?3 AND status='open'",
            rusqlite::params![package.image_sha256, evidence_record_id, case_id],
        )
        .map_err(err)?;
    if changed != 1 {
        return Err("The acquired image evidence record could not be marked hashed.".into());
    }
    audit(
        &tx,
        "acquired_image_hash_recorded",
        &serde_json::json!({
            "case_id": case_id,
            "evidence_record_id": evidence_record_id,
            "source_device_number": device_number,
            "sha256": package.image_sha256,
            "size_bytes": package.size_bytes,
            "acquisition_directory": package.directory,
        })
        .to_string(),
    )?;
    tx.commit().map_err(err)?;
    drop(db);
    *state.source.lock().map_err(err)? = Some(Evidence {
        image,
        info: crate::Source {
            id: source_id,
            case_id,
            evidence_record_id,
            name,
            size: package.size_bytes,
            filesystem,
            sha256: Some(package.image_sha256.clone()),
        },
        integrity_compromised: false,
    });
    *state.scan.lock().map_err(err)? = None;
    *state.carve_scan.lock().map_err(err)? = None;
    *state.fat32_scan.lock().map_err(err)? = None;
    Ok(())
}

fn record_acquisition_event(
    db: &rusqlite::Connection,
    event: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    crate::audit(db, event, &payload.to_string())
}

#[tauri::command]
pub async fn acquire_physical_device(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    expected_device: PhysicalDevice,
    hardware_write_blocker_attested: bool,
) -> Result<bool> {
    if !hardware_write_blocker_attested {
        return Err(
            "Confirm the source is offline and protected by a validated hardware write blocker."
                .into(),
        );
    }
    let case_id = {
        let db = state.db.lock().map_err(err)?;
        require_audited_active_case(&db)?
    };
    let selected_folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Choose an acquisition destination on a different physical disk")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(selected_folder) = selected_folder else {
        return Ok(false);
    };
    let device = DeviceSource::open(expected_device.number).map_err(DeviceProbeError::message)?;
    validate_selected_device(&expected_device, &device.info)?;
    let destination = crate::destination::check_device_destination(
        expected_device.number,
        &selected_folder,
        device.info.size_bytes,
    )?;
    run_acquisition_operation(
        app,
        state,
        expected_device,
        device,
        case_id,
        destination,
        None,
        hardware_write_blocker_attested,
    )
    .await
}

#[tauri::command]
pub async fn resume_physical_device_acquisition(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    expected_device: PhysicalDevice,
    hardware_write_blocker_attested: bool,
) -> Result<bool> {
    if !hardware_write_blocker_attested {
        return Err(
            "Confirm the source is offline and protected by a validated hardware write blocker."
                .into(),
        );
    }
    let case_id = {
        let db = state.db.lock().map_err(err)?;
        require_audited_active_case(&db)?
    };
    let selected_folder = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Select this source's interrupted acquisition folder")
            .pick_folder()
    })
    .await
    .map_err(err)?;
    let Some(staging_path) = selected_folder else {
        return Ok(false);
    };
    let device = DeviceSource::open(expected_device.number).map_err(DeviceProbeError::message)?;
    validate_selected_device(&expected_device, &device.info)?;
    let checkpoint = load_acquisition_resume(&staging_path, &device.info, case_id)?;
    let destination_path = staging_path
        .parent()
        .ok_or("The interrupted acquisition folder has no destination parent.")?;
    let remaining_bytes = device
        .info
        .size_bytes
        .saturating_sub(checkpoint.state.committed_bytes);
    let destination = crate::destination::check_device_destination(
        expected_device.number,
        destination_path,
        remaining_bytes,
    )?;
    run_acquisition_operation(
        app,
        state,
        expected_device,
        device,
        case_id,
        destination,
        Some(staging_path),
        hardware_write_blocker_attested,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_acquisition_operation(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    expected_device: PhysicalDevice,
    device: DeviceSource,
    case_id: i64,
    destination: PathBuf,
    resume_directory: Option<PathBuf>,
    hardware_write_blocker_attested: bool,
) -> Result<bool> {
    let resumed = resume_directory.is_some();
    let start_event = if resumed {
        "physical_device_acquisition_resume_started"
    } else {
        "physical_device_acquisition_started"
    };
    {
        let mut job = state.job.lock().map_err(err)?;
        if job.state == "running" {
            return Err("Wait for or cancel the active operation before imaging a device.".into());
        }
        let db = state.db.lock().map_err(err)?;
        let current_case = require_audited_active_case(&db)?;
        if current_case != case_id {
            return Err("The active case changed before imaging started.".into());
        }
        if let Err(error) = audit(
            &db,
            start_event,
            &serde_json::json!({
                "case_id": case_id,
                "device_number": expected_device.number,
                "device_identity": device.info,
                "size_bytes": device.info.size_bytes,
                "bytes_per_sector": device.info.bytes_per_sector,
                "destination": destination,
                "hardware_write_blocker_attested": hardware_write_blocker_attested,
                "resume_directory": resume_directory,
            })
            .to_string(),
        ) {
            job.state = "failed".into();
            job.error = Some(error.clone());
            return Err(error);
        }
        state.cancel.store(false, Ordering::SeqCst);
        *job = Job {
            state: "running".into(),
            kind: "disk_acquisition".into(),
            total: device.info.size_bytes.saturating_mul(2),
            message: Some(if resumed {
                "Revalidating the committed image bytes against the selected source".into()
            } else {
                "Reading the physical source and writing a staged image".into()
            }),
            ..Job::default()
        };
    }
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let acquired = {
            let mut progress = |processed: u64, total: u64, errors: usize| {
                if let Ok(mut job) = state.job.lock() {
                    job.processed = processed.min(total);
                    job.total = total;
                    job.discovered = errors;
                    job.message = Some(if errors == 0 {
                        if resumed {
                            "Revalidating staged data and continuing source acquisition".into()
                        } else {
                            "Acquiring source bytes and verifying the staged image digest".into()
                        }
                    } else {
                        format!("Acquisition continues with {errors} mapped read-error ranges")
                    });
                }
            };
            if let Some(staging_path) = resume_directory.as_deref() {
                resume_capture(
                    &device,
                    &device.info,
                    staging_path,
                    AcquisitionOptions {
                        case_id,
                        write_blocker_attested: hardware_write_blocker_attested,
                    },
                    &state.cancel,
                    &mut progress,
                )
            } else {
                capture(
                    &device,
                    &device.info,
                    case_id,
                    &destination,
                    hardware_write_blocker_attested,
                    &state.cancel,
                    &mut progress,
                )
            }
        };
        match acquired {
            Ok(Some(package)) => {
                let outcome = if package.read_error_ranges == 0 { "complete" } else { "partial" };
                let audit_result = (|| -> Result<()> {
                    let db = state.db.lock().map_err(err)?;
                    if require_audited_active_case(&db)? != case_id {
                        return Err("The active case changed during acquisition. Preserve the published package and inspect the audit log.".into());
                    }
                    audit(
                        &db,
                        "physical_device_acquisition_published",
                        &serde_json::json!({
                            "case_id": case_id,
                            "device_number": expected_device.number,
                            "device_identity": device.info,
                            "size_bytes": package.size_bytes,
                            "bytes_per_sector": expected_device.bytes_per_sector,
                            "read_error_ranges": package.read_error_ranges,
                            "image_sha256": package.image_sha256,
                            "output_directory": package.directory,
                            "outcome": outcome,
                        })
                        .to_string(),
                    )
                })();
                let publication_audited = audit_result.is_ok();
                let mut finalization = audit_result;
                if finalization.is_ok() && package.read_error_ranges == 0 {
                    finalization = activate_acquired_image(&state, expected_device.number, case_id, &package);
                }
                if let Err(error) = &finalization {
                    let safe_error = error.chars().take(2048).collect::<String>();
                    let stage = if publication_audited {
                        "case_registration"
                    } else {
                        "publication_audit"
                    };
                    let failure_audit = (|| -> Result<()> {
                        let db = state.db.lock().map_err(err)?;
                        record_acquisition_event(
                            &db,
                            "physical_device_acquisition_finalization_failed",
                            &serde_json::json!({
                                "case_id": case_id,
                                "device_number": expected_device.number,
                                "image_sha256": package.image_sha256,
                                "output_directory": package.directory,
                                "read_error_ranges": package.read_error_ranges,
                                "publication_event_recorded": publication_audited,
                                "stage": stage,
                                "error": safe_error,
                            }),
                        )
                    })();
                    if let Err(audit_error) = failure_audit {
                        finalization = Err(format!(
                            "{error}; finalization failure could not be audited: {audit_error}"
                        ));
                    }
                }
                if let Ok(mut job) = state.job.lock() {
                    job.state = if finalization.is_ok() { "completed" } else { "failed" }.into();
                    job.message = Some(if package.read_error_ranges == 0 {
                        "Acquisition package published; image digest verified".into()
                    } else {
                        format!("Partial image published with {} mapped read-error ranges; it was not activated for analysis", package.read_error_ranges)
                    });
                    job.error = finalization.err();
                    job.sha256 = Some(package.image_sha256.clone());
                    job.output_directory = Some(package.directory.to_string_lossy().into_owned());
                    job.processed = job.total;
                }
                Ok(true)
            }
            Ok(None) => {
                let audit_result = (|| -> Result<()> {
                    let db = state.db.lock().map_err(err)?;
                    record_acquisition_event(
                        &db,
                        "physical_device_acquisition_cancelled",
                        &serde_json::json!({
                            "case_id":case_id,
                            "device_number":expected_device.number,
                            "device_identity":device.info,
                            "resumed": resumed,
                            "resume_directory": resume_directory,
                        }),
                    )
                })();
                if let Ok(mut job) = state.job.lock() {
                    job.state = if audit_result.is_ok() { "cancelled" } else { "failed" }.into();
                    job.message = Some(if audit_result.is_ok() {
                        if resumed {
                            "Resume cancelled; the incomplete acquisition was preserved".into()
                        } else {
                            "Acquisition cancelled; unpublished staging data removed".into()
                        }
                    } else {
                        "Acquisition stopped, but cancellation could not be recorded in the audit log.".into()
                    });
                    job.error = audit_result.as_ref().err().cloned();
                }
                audit_result.map(|()| false)
            }
            Err(error) => {
                let safe_error = error.chars().take(2048).collect::<String>();
                let audit_result = (|| -> Result<()> {
                    let db = state.db.lock().map_err(err)?;
                    record_acquisition_event(
                        &db,
                        "physical_device_acquisition_failed",
                        &serde_json::json!({
                            "case_id":case_id,
                            "device_number":expected_device.number,
                            "device_identity":device.info,
                            "error":safe_error,
                        }),
                    )
                })();
                let error = match audit_result {
                    Ok(()) => error,
                    Err(audit_error) => format!(
                        "{error}; acquisition failure could not be recorded in the audit log: {audit_error}"
                    ),
                };
                if let Ok(mut job) = state.job.lock() {
                    job.state = "failed".into();
                    job.error = Some(error.clone());
                }
                Err(error)
            }
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(error) => {
            let failure = format!("Acquisition worker stopped unexpectedly: {error}");
            let audit_result = (|| -> Result<()> {
                let db = state.db.lock().map_err(err)?;
                record_acquisition_event(
                    &db,
                    "physical_device_acquisition_failed",
                    &serde_json::json!({
                        "case_id":case_id,
                        "device_number":expected_device.number,
                        "failure_kind":"worker_join",
                        "publication_state":"unknown_after_worker_termination",
                        "error":failure.chars().take(2048).collect::<String>(),
                    }),
                )
            })();
            let failure = match audit_result {
                Ok(()) => failure,
                Err(audit_error) => format!(
                    "{failure}; worker failure could not be recorded in the audit log: {audit_error}"
                ),
            };
            if let Ok(mut job) = state.job.lock() {
                job.state = "failed".into();
                job.error = Some(failure.clone());
            }
            Err(failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn device_enumeration_ignores_absent_paths_but_reports_access_failures() {
        assert!(matches!(
            classify_device_open_error(7, std::io::Error::from_raw_os_error(2)),
            DeviceProbeError::Unavailable
        ));
        assert!(matches!(
            classify_device_open_error(7, std::io::Error::from_raw_os_error(3)),
            DeviceProbeError::Unavailable
        ));
        match classify_device_open_error(7, std::io::Error::from_raw_os_error(5)) {
            DeviceProbeError::Failed(message) => {
                assert!(message.contains("PhysicalDrive7"));
                assert!(message.contains("read-only"));
            }
            DeviceProbeError::Unavailable => panic!("access denied must be visible"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn acquisition_read_handle_blocks_new_writers_until_released() {
        let root = test_directory();
        let path = root.join("source.raw");
        fs::write(&path, b"controlled source").unwrap();

        let source = open_device_read_only(&path).unwrap();
        let write_attempt = OpenOptions::new().write(true).open(&path);
        assert!(write_attempt.is_err());

        drop(source);
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"updated").unwrap();
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn device_inventory_keeps_probe_errors_alongside_readable_devices() {
        let inventory = collect_physical_device_inventory(|number| match number {
            0 => Err(DeviceProbeError::Unavailable),
            1 => Err(DeviceProbeError::Failed("access denied".into())),
            2 => Ok(PhysicalDevice {
                number,
                size_bytes: 4096,
                bytes_per_sector: 512,
                identity: DeviceIdentity {
                    vendor: Some("Fixture".into()),
                    product: Some("Readable disk".into()),
                    revision: None,
                    serial_number: Some("TEST-02".into()),
                    bus_type: Some(7),
                    identity_error: None,
                },
            }),
            _ => Err(DeviceProbeError::Unavailable),
        });
        assert_eq!(inventory.devices.len(), 1);
        assert_eq!(inventory.devices[0].number, 2);
        assert_eq!(inventory.failures.len(), 1);
        assert_eq!(inventory.failures[0].number, 1);
        assert_eq!(inventory.failures[0].message, "access denied");
    }

    struct TestSource {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
    }

    struct SectorFailureSource {
        bytes: Vec<u8>,
        unreadable: std::ops::Range<usize>,
    }

    struct DisconnectedSource {
        size: u64,
    }

    struct DisconnectAfterOffsetSource {
        bytes: Vec<u8>,
        cutoff: usize,
    }

    impl BlockSource for TestSource {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            crate::storage::checked_range(self.len(), offset, buffer.len())?;
            let start = offset as usize;
            if self.fail_after.is_some_and(|limit| start >= limit) {
                return Err(std::io::Error::other("fixture read failure"));
            }
            buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
            Ok(())
        }
    }

    struct MarkerBlockedSource {
        destination: PathBuf,
        size: u64,
    }

    impl BlockSource for MarkerBlockedSource {
        fn len(&self) -> u64 {
            self.size
        }

        fn read_exact_at(&self, _offset: u64, _buffer: &mut [u8]) -> std::io::Result<()> {
            let staging = fs::read_dir(&self.destination)?
                .next()
                .ok_or_else(|| std::io::Error::other("staging directory was not created"))??
                .path();
            let marker = fs::read_to_string(staging.join("INCOMPLETE.txt"))?;
            if !marker.contains("UNPUBLISHED ACQUISITION") {
                return Err(std::io::Error::other(
                    "incomplete marker was not durable before source reads",
                ));
            }
            Err(std::io::Error::from_raw_os_error(1167))
        }
    }

    impl BlockSource for SectorFailureSource {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            crate::storage::checked_range(self.len(), offset, buffer.len())?;
            let start = offset as usize;
            let end = start + buffer.len();
            if start < self.unreadable.end && end > self.unreadable.start {
                return Err(std::io::Error::other("fixture sector CRC error"));
            }
            buffer.copy_from_slice(&self.bytes[start..end]);
            Ok(())
        }
    }

    impl BlockSource for DisconnectedSource {
        fn len(&self) -> u64 {
            self.size
        }

        fn read_exact_at(&self, _offset: u64, _buffer: &mut [u8]) -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(1167))
        }
    }

    impl BlockSource for DisconnectAfterOffsetSource {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            crate::storage::checked_range(self.len(), offset, buffer.len())?;
            let start = offset as usize;
            if start >= self.cutoff {
                return Err(std::io::Error::from_raw_os_error(1167));
            }
            buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
            Ok(())
        }
    }

    fn test_directory() -> PathBuf {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .expect("project directory")
            .join(format!(".acquisition-test-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    fn test_device() -> PhysicalDevice {
        PhysicalDevice {
            number: 7,
            size_bytes: 2048,
            bytes_per_sector: 512,
            identity: DeviceIdentity {
                vendor: Some("Fixture".into()),
                product: Some("Test disk".into()),
                revision: Some("1.0".into()),
                serial_number: Some("TEST-0001".into()),
                bus_type: Some(7),
                identity_error: None,
            },
        }
    }

    #[test]
    fn physical_device_selection_rejects_identity_and_geometry_changes() {
        let expected = test_device();
        assert!(validate_selected_device(&expected, &expected).is_ok());

        let mut replacement = test_device();
        replacement.identity.serial_number = Some("REPLACEMENT-0002".into());
        assert!(validate_selected_device(&expected, &replacement)
            .unwrap_err()
            .contains("identity or geometry changed"));

        let mut changed_geometry = test_device();
        changed_geometry.size_bytes += 512;
        assert!(validate_selected_device(&expected, &changed_geometry).is_err());
    }

    #[test]
    fn source_changes_and_hardware_reinitialization_errors_abort_acquisition() {
        for code in [21, 55, 321, 1110, 1112, 1164, 1167] {
            assert!(
                source_is_unavailable(&std::io::Error::from_raw_os_error(code)),
                "Windows error {code} must stop acquisition"
            );
        }
        // A generic I/O device error can be a localized unreadable sector; the
        // imager should retry and map it rather than assume the whole source vanished.
        assert!(!source_is_unavailable(&std::io::Error::from_raw_os_error(
            1117
        )));
    }

    fn geometry_fixture() -> ([u8; 64], [u8; 8]) {
        let mut geometry = [0; 64];
        let size = 1024_i64 * 1024;
        geometry[20..24].copy_from_slice(&512_u32.to_le_bytes());
        geometry[24..32].copy_from_slice(&size.to_le_bytes());
        (geometry, size.to_le_bytes())
    }

    #[test]
    fn device_geometry_requires_the_complete_disk_size_field() {
        let (geometry, length) = geometry_fixture();
        assert!(parse_device_geometry(&geometry, 31, &length, 8).is_err());
        assert_eq!(
            parse_device_geometry(&geometry, 32, &length, 8).unwrap(),
            (512, 1024 * 1024)
        );
        assert!(parse_device_geometry(&geometry, 32, &length, 7).is_err());
    }

    #[test]
    fn device_geometry_rejects_inconsistent_size_and_sector_values() {
        let (mut geometry, length) = geometry_fixture();
        geometry[24..32].copy_from_slice(&(2048_i64).to_le_bytes());
        assert!(parse_device_geometry(&geometry, 32, &length, 8).is_err());

        let (mut geometry, length) = geometry_fixture();
        geometry[20..24].copy_from_slice(&1000_u32.to_le_bytes());
        assert!(parse_device_geometry(&geometry, 32, &length, 8).is_err());
    }

    #[test]
    fn parses_storage_device_identity_with_bounded_strings() {
        let mut descriptor = vec![0u8; 52];
        descriptor[4..8].copy_from_slice(&52u32.to_le_bytes());
        descriptor[12..16].copy_from_slice(&36u32.to_le_bytes());
        descriptor[16..20].copy_from_slice(&43u32.to_le_bytes());
        descriptor[20..24].copy_from_slice(&0u32.to_le_bytes());
        descriptor[24..28].copy_from_slice(&47u32.to_le_bytes());
        descriptor[28..32].copy_from_slice(&7u32.to_le_bytes());
        descriptor[36..43].copy_from_slice(b"VENDOR\0");
        descriptor[43..47].copy_from_slice(b"SSD\0");
        descriptor[47..52].copy_from_slice(b"S123\0");

        let identity = parse_device_descriptor(&descriptor).unwrap();
        assert_eq!(identity.vendor.as_deref(), Some("VENDOR"));
        assert_eq!(identity.product.as_deref(), Some("SSD"));
        assert_eq!(identity.revision, None);
        assert_eq!(identity.serial_number.as_deref(), Some("S123"));
        assert_eq!(identity.bus_type, Some(7));
    }

    #[test]
    fn rejects_storage_identity_offsets_outside_the_descriptor() {
        let mut descriptor = vec![0u8; 36];
        descriptor[4..8].copy_from_slice(&36u32.to_le_bytes());
        descriptor[12..16].copy_from_slice(&36u32.to_le_bytes());
        assert!(parse_device_descriptor(&descriptor).is_err());
    }

    #[test]
    fn acquisition_terminal_outcomes_are_hash_chained() {
        let db = crate::database(PathBuf::from(":memory:")).unwrap();
        record_acquisition_event(
            &db,
            "physical_device_acquisition_cancelled",
            &serde_json::json!({"case_id":1,"device_number":4}),
        )
        .unwrap();
        record_acquisition_event(
            &db,
            "physical_device_acquisition_failed",
            &serde_json::json!({"case_id":1,"device_number":4,"error":"read failed"}),
        )
        .unwrap();
        record_acquisition_event(
            &db,
            "physical_device_acquisition_finalization_failed",
            &serde_json::json!({"case_id":1,"device_number":4,"image_sha256":"a".repeat(64)}),
        )
        .unwrap();

        let events = db
            .prepare("SELECT event FROM audit ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            events,
            [
                "physical_device_acquisition_cancelled",
                "physical_device_acquisition_failed",
                "physical_device_acquisition_finalization_failed",
            ]
        );
        assert!(crate::verify_audit_chain(&db).unwrap().valid);
    }

    #[test]
    fn complete_acquisition_publishes_hash_verified_image_and_package_records() {
        let destination = test_directory();
        let source = TestSource {
            bytes: (0..2048).map(|n| (n % 251) as u8).collect(),
            fail_after: None,
        };
        let cancel = AtomicBool::new(false);
        let package = capture(
            &source,
            &test_device(),
            42,
            &destination,
            true,
            &cancel,
            |_, _, _| {},
        )
        .expect("capture succeeds")
        .expect("package publishes");

        assert_eq!(package.read_error_ranges, 0);
        assert_eq!(fs::read(&package.image_path).unwrap(), source.bytes);
        assert_eq!(
            checksum_file(&package.image_path).unwrap(),
            package.image_sha256
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(package.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["package_type"], "physical_device_acquisition");
        assert!(manifest["acquisition_method"]
            .as_str()
            .unwrap()
            .contains("binary subdivision through the reported sector size"));
        assert_eq!(manifest["image_name"], "image.raw");
        assert!(package.directory.join("checksums.sha256").is_file());
        assert!(package.directory.join("completion.json").is_file());
        assert_eq!(
            crate::recovery_verify::verify_package(&package.directory)
                .unwrap()
                .state,
            "complete"
        );
        assert_eq!(
            fs::read(package.directory.join("read-errors.jsonl")).unwrap(),
            b""
        );
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn unreadable_ranges_are_zero_filled_and_package_is_marked_partial() {
        let destination = test_directory();
        let mut device = test_device();
        device.size_bytes = (READ_CHUNK * 2) as u64;
        let source = TestSource {
            bytes: vec![0x5a; READ_CHUNK * 2],
            fail_after: Some(READ_CHUNK),
        };
        let cancel = AtomicBool::new(false);
        let package = capture(
            &source,
            &device,
            42,
            &destination,
            true,
            &cancel,
            |_, _, _| {},
        )
        .expect("capture succeeds with read errors")
        .expect("partial package publishes");

        assert_eq!(package.read_error_ranges, 1);
        let image = fs::read(&package.image_path).unwrap();
        assert_eq!(&image[..READ_CHUNK], &source.bytes[..READ_CHUNK]);
        assert!(image[READ_CHUNK..].iter().all(|byte| *byte == 0));
        let completion: serde_json::Value =
            serde_json::from_slice(&fs::read(package.directory.join("completion.json")).unwrap())
                .unwrap();
        assert_eq!(completion["state"], "partial");
        let errors = fs::read_to_string(package.directory.join("read-errors.jsonl")).unwrap();
        let range: serde_json::Value = serde_json::from_str(errors.trim()).unwrap();
        assert_eq!(range["offset"], READ_CHUNK as u64);
        assert_eq!(range["length"], READ_CHUNK as u64);
        assert_eq!(range["attempts"], MAX_RETRIES);
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn acquisition_recovers_readable_sectors_around_a_bad_sector() {
        let destination = test_directory();
        let source = SectorFailureSource {
            bytes: (0..READ_CHUNK).map(|byte| (byte % 251) as u8).collect(),
            unreadable: 256 * 1024..256 * 1024 + 512,
        };
        let mut device = test_device();
        device.size_bytes = source.len();
        let package = capture(
            &source,
            &device,
            42,
            &destination,
            true,
            &AtomicBool::new(false),
            |_, _, _| {},
        )
        .expect("capture completes as a partial image")
        .expect("partial package publishes");

        let image = fs::read(&package.image_path).unwrap();
        let bad_start = 256 * 1024;
        let bad_end = bad_start + 512;
        assert_eq!(&image[..bad_start], &source.bytes[..bad_start]);
        assert!(image[bad_start..bad_end].iter().all(|byte| *byte == 0));
        assert_eq!(&image[bad_end..], &source.bytes[bad_end..]);
        let errors = fs::read_to_string(package.directory.join("read-errors.jsonl")).unwrap();
        let record: serde_json::Value = serde_json::from_str(errors.trim()).unwrap();
        assert_eq!(record["offset"], bad_start as u64);
        assert_eq!(record["length"], 512);
        assert_eq!(record["attempts"], MAX_RETRIES);
        let verification = crate::recovery_verify::verify_package(&package.directory)
            .expect("single-sector read-error package verifies");
        assert_eq!(verification.state, "partial");
        assert_eq!(verification.failed, 1);
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn disconnected_source_fails_without_publishing_a_zero_filled_image() {
        let destination = test_directory();
        let source = DisconnectedSource { size: 2048 };
        let error = capture(
            &source,
            &test_device(),
            42,
            &destination,
            true,
            &AtomicBool::new(false),
            |_, _, _| {},
        )
        .err()
        .expect("a disconnected source must not be converted into a partial image");

        assert!(error.contains("source became unavailable"));
        let mut entries = fs::read_dir(&destination).unwrap();
        let partial = entries.next().unwrap().unwrap().path();
        assert!(entries.next().is_none());
        assert!(partial
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".partial"));
        assert!(partial.join("INCOMPLETE.txt").is_file());
        assert!(partial.join("image.raw").is_file());
        assert!(error.contains(&partial.to_string_lossy().to_string()));
        assert!(error.contains("Preserve this folder"));
        assert!(error.contains("Resume interrupted image"));
        assert!(fs::read_to_string(partial.join("INCOMPLETE.txt"))
            .unwrap()
            .contains("UNPUBLISHED ACQUISITION"));
        assert!(crate::recovery_verify::verify_package(&partial).is_err());
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn resumed_acquisition_revalidates_committed_bytes_and_publishes_exact_image() {
        let destination = test_directory();
        let committed = ACQUISITION_CHECKPOINT_INTERVAL as usize;
        let size = committed + 1024 * 1024;
        let bytes: Vec<u8> = (0..size)
            .map(|index| (index.wrapping_mul(31) % 251) as u8)
            .collect();
        let source = DisconnectAfterOffsetSource {
            bytes: bytes.clone(),
            cutoff: committed,
        };
        let mut device = test_device();
        device.size_bytes = size as u64;
        let error = capture(
            &source,
            &device,
            42,
            &destination,
            true,
            &AtomicBool::new(false),
            |_, _, _| {},
        )
        .err()
        .expect("the simulated disconnect must retain the checkpointed prefix");
        let staging = fs::read_dir(&destination)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(error.contains(&staging.to_string_lossy().to_string()));
        let checkpoint = load_acquisition_resume(&staging, &device, 42).unwrap();
        assert_eq!(checkpoint.state.committed_bytes, committed as u64);
        assert_eq!(checkpoint.state.read_error_ranges, 0);

        let mut changed_bytes = bytes.clone();
        changed_bytes[4096] ^= 0x40;
        let changed_source = TestSource {
            bytes: changed_bytes,
            fail_after: None,
        };
        let mismatch = resume_capture(
            &changed_source,
            &device,
            &staging,
            AcquisitionOptions {
                case_id: 42,
                write_blocker_attested: true,
            },
            &AtomicBool::new(false),
            &mut |_, _, _| {},
        )
        .unwrap_err();
        assert!(mismatch.contains("no longer matches the committed staged image"));
        assert_eq!(
            fs::metadata(staging.join("image.raw")).unwrap().len(),
            committed as u64
        );

        let complete_source = TestSource {
            bytes: bytes.clone(),
            fail_after: None,
        };
        let package = resume_capture(
            &complete_source,
            &device,
            &staging,
            AcquisitionOptions {
                case_id: 42,
                write_blocker_attested: true,
            },
            &AtomicBool::new(false),
            &mut |_, _, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(fs::read(&package.image_path).unwrap(), bytes);
        assert_eq!(
            crate::recovery_verify::verify_package(&package.directory)
                .unwrap()
                .state,
            "complete"
        );
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn incomplete_marker_is_flushed_before_the_first_source_read() {
        let destination = test_directory();
        let source = MarkerBlockedSource {
            destination: destination.clone(),
            size: 2048,
        };
        let mut device = test_device();
        device.size_bytes = source.len();
        let error = capture(
            &source,
            &device,
            42,
            &destination,
            true,
            &AtomicBool::new(false),
            |_, _, _| {},
        )
        .err()
        .expect("device read failure must retain an unverified staging folder");

        assert!(error.contains("source became unavailable"));
        assert!(!error.contains("Could not verify the incomplete marker"));
        let staging = fs::read_dir(&destination)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(error.contains(&staging.to_string_lossy().to_string()));
        assert!(crate::recovery_verify::verify_package(&staging).is_err());
        fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn cancelled_acquisition_removes_unpublished_staging_data() {
        let destination = test_directory();
        let source = TestSource {
            bytes: vec![0x11; 2048],
            fail_after: None,
        };
        let cancel = AtomicBool::new(true);
        assert!(capture(
            &source,
            &test_device(),
            42,
            &destination,
            true,
            &cancel,
            |_, _, _| {},
        )
        .unwrap()
        .is_none());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        fs::remove_dir_all(destination).unwrap();
    }
}
