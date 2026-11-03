use std::{
    collections::BTreeSet,
    ffi::c_void,
    fs::OpenOptions,
    io,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetVolumePathNameW(path: *const u16, volume: *mut u16, length: u32) -> i32;
    fn GetVolumeNameForVolumeMountPointW(mount: *const u16, name: *mut u16, length: u32) -> i32;
    fn GetDiskFreeSpaceExW(
        path: *const u16,
        available: *mut u64,
        total: *mut u64,
        free: *mut u64,
    ) -> i32;
    fn DeviceIoControl(
        handle: *mut c_void,
        code: u32,
        input: *mut c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn MoveFileW(from: *const u16, to: *const u16) -> i32;
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn wide_file_path(path: &Path) -> io::Result<Vec<u16>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let encoded = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.len() < 248 || encoded.starts_with(&"\\\\?\\".encode_utf16().collect::<Vec<_>>()) {
        return Ok(encoded.into_iter().chain(Some(0)).collect());
    }
    let display = absolute.to_string_lossy();
    let extended = if display.starts_with("\\\\") {
        format!("\\\\?\\UNC\\{}", display.trim_start_matches('\\'))
    } else {
        format!("\\\\?\\{display}")
    };
    Ok(extended.encode_utf16().chain(Some(0)).collect())
}
fn volume(path: &Path) -> io::Result<Vec<u16>> {
    let path = wide(path);
    let mut root = vec![0; 32768];
    // The input and output buffers stay alive for the duration of each call.
    if unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(root)
}
fn disks(path: &Path) -> io::Result<BTreeSet<u32>> {
    let root = volume(path)?;
    let mut name = vec![0; 128];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), name.as_mut_ptr(), name.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = name
        .iter()
        .position(|x| *x == 0)
        .ok_or_else(|| io::Error::other("Invalid volume GUID path"))?;
    let text = String::from_utf16(&name[..length])
        .map_err(|_| io::Error::other("Invalid volume GUID encoding"))?;
    let handle = OpenOptions::new()
        .access_mode(0)
        .share_mode(3)
        .open(text.trim_end_matches('\\'))?;
    let mut buffer = [0u64; 256];
    let mut returned = 0u32;
    // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS is a metadata query; no disk writes.
    if unsafe {
        DeviceIoControl(
            handle.as_raw_handle(),
            0x0056_0000,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(&buffer) as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > std::mem::size_of_val(&buffer) {
        return Err(io::Error::other("Invalid volume extent response length"));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize) };
    parse_extents(bytes)
}
fn parse_extents(bytes: &[u8]) -> io::Result<BTreeSet<u32>> {
    let count = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| io::Error::other("Missing disk extent count"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if count == 0 || count > 64 || 8 + count * 24 > bytes.len() {
        return Err(io::Error::other("Invalid or excessive disk extent list"));
    }
    Ok((0..count)
        .map(|i| u32::from_le_bytes(bytes[8 + i * 24..12 + i * 24].try_into().unwrap()))
        .collect())
}
pub fn check_destination(
    source: &Path,
    destination: &Path,
    required: u64,
) -> Result<PathBuf, String> {
    let destination = destination.canonicalize().map_err(|e| e.to_string())?;
    if !destination.is_dir() {
        return Err("Choose an existing recovery folder on a different physical disk.".into());
    }
    let source_disks=disks(source).map_err(|e|format!("Cannot establish the source's physical disk identity: {e}. Export requires a local source with known disk extents."))?;
    let destination_disks=disks(&destination).map_err(|e|format!("Cannot establish the destination's physical disk identity: {e}. Choose a supported local destination."))?;
    if !source_disks.is_disjoint(&destination_disks) {
        return Err("The recovery destination shares a physical disk with the source image. Choose a different physical disk.".into());
    }
    let root = wide(&destination);
    let mut available = 0;
    if unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if required
        .checked_add(1024 * 1024)
        .is_none_or(|n| n > available)
    {
        return Err("There is not enough free space at the selected destination.".into());
    }
    Ok(destination)
}

pub fn check_device_destination(
    source_disk: u32,
    destination: &Path,
    required: u64,
) -> Result<PathBuf, String> {
    let destination = destination
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !destination.is_dir() {
        return Err("Choose an existing local acquisition folder.".into());
    }
    let destination_disks = disks(&destination).map_err(|error| {
        format!("Cannot establish the destination's physical disk identity: {error}")
    })?;
    if destination_disks.contains(&source_disk) {
        return Err(
            "The acquisition destination is on the source physical disk. Choose a separate disk."
                .into(),
        );
    }
    let root = wide(&destination);
    let mut available = 0;
    if unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if required
        .checked_add(16 * 1024 * 1024)
        .is_none_or(|needed| needed > available)
    {
        return Err("There is not enough free space for the image and acquisition records.".into());
    }
    Ok(destination)
}

pub fn publish_new(from: &Path, to: &Path) -> io::Result<()> {
    let from = wide_file_path(from)?;
    let to = wide_file_path(to)?;
    // MoveFileW does not replace an existing file, including a raced-in target.
    if unsafe { MoveFileW(from.as_ptr(), to.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_extent_response_before_reading_ids() {
        let mut b = vec![0; 56];
        b[..4].copy_from_slice(&2u32.to_le_bytes());
        b[8..12].copy_from_slice(&3u32.to_le_bytes());
        b[32..36].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(parse_extents(&b).unwrap(), BTreeSet::from([3, 7]));
        b[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_extents(&b).is_err());
    }

    #[test]
    #[ignore = "requires a local Windows volume supporting disk extent queries"]
    fn windows_rejects_same_physical_disk_destination() {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("daemoncore-topology-{}.img", std::process::id()));
        std::fs::write(&path, b"test evidence").unwrap();
        let result = check_destination(&path, &directory, 1);
        std::fs::remove_file(path).unwrap();
        assert!(result.unwrap_err().contains("shares a physical disk"));
    }
}

#[cfg(test)]
mod publish_tests {
    use super::*;
    #[test]
    fn existing_output_is_never_replaced() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("daemoncore-publish-{stamp}"));
        std::fs::create_dir(&root).unwrap();
        let from = root.join("partial");
        let target = root.join("existing");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&target, b"original").unwrap();
        assert!(publish_new(&from, &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert_eq!(std::fs::read(&from).unwrap(), b"new");
        std::fs::remove_dir_all(root).unwrap();
    }
}
