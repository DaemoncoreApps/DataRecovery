use std::{
    collections::BTreeSet,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

const MAX_DIRECTORY_HANDLES: usize = 4096;

pub(crate) fn open_regular_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;

        // Open the final path component itself so a raced-in file reparse point is not followed.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?
    };
    #[cfg(not(windows))]
    let file = File::open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path is not a regular file.",
        ));
    }
    Ok(file)
}

pub(crate) fn require_plain_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path is not a plain directory.",
        ));
    }
    Ok(())
}

pub(crate) fn open_plain_directory(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
    };
    #[cfg(not(windows))]
    let directory = File::open(path)?;

    let metadata = directory.metadata()?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path is not a plain directory.",
        ));
    }
    Ok(directory)
}

#[derive(Default)]
pub(crate) struct ReadLocks {
    handles: Vec<File>,
    directories: BTreeSet<PathBuf>,
}

impl ReadLocks {
    pub(crate) fn retain_file(&mut self, file: File) {
        self.handles.push(file);
    }

    pub(crate) fn retain_directory(&mut self, path: &Path) -> io::Result<()> {
        if self.directories.contains(path) {
            return Ok(());
        }
        if self.directories.len() >= MAX_DIRECTORY_HANDLES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Package contains too many directories to verify safely.",
            ));
        }
        let directory = open_plain_directory(path)?;
        self.directories.insert(path.to_path_buf());
        self.handles.push(directory);
        Ok(())
    }
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn test_root() -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-temp")
            .join(format!("safe-file-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn opens_regular_files() {
        let root = test_root();
        let path = root.join("source.txt");
        fs::write(&path, b"controlled").unwrap();
        let mut contents = Vec::new();
        open_regular_file(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"controlled");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_file_and_directory_symlinks() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let root = test_root();
        let target_dir = root.join("target-dir");
        fs::create_dir(&target_dir).unwrap();
        let target_file = target_dir.join("source.txt");
        fs::write(&target_file, b"controlled").unwrap();

        let file_link = root.join("file-link.txt");
        symlink_file(&target_file, &file_link).unwrap();
        assert!(open_regular_file(&file_link).is_err());

        let directory_link = root.join("directory-link");
        symlink_dir(&target_dir, &directory_link).unwrap();
        assert!(require_plain_directory(&directory_link).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn read_locks_block_file_mutations_until_released() {
        let root = test_root();
        let path = root.join("source.txt");
        fs::write(&path, b"controlled").unwrap();

        let mut locks = ReadLocks::default();
        let file = open_regular_file(&path).unwrap();
        locks.retain_file(file);

        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(fs::rename(&path, root.join("renamed.txt")).is_err());

        drop(locks);
        fs::write(&path, b"updated").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn retained_directory_handle_blocks_rename_but_allows_enumeration() {
        let root = test_root();
        let directory = root.join("package");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("entry.txt"), b"controlled").unwrap();

        let mut locks = ReadLocks::default();
        locks.retain_file(open_plain_directory(&directory).unwrap());

        assert!(fs::read_dir(&directory).is_ok());
        assert!(fs::rename(&directory, root.join("renamed")).is_err());
        fs::create_dir(directory.join("new-entry")).unwrap();

        drop(locks);
        fs::rename(&directory, root.join("renamed")).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
