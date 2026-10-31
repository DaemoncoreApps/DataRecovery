use std::{fs, fs::File, io, path::Path};

pub(crate) fn open_regular_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;

        // Open the final path component itself so a raced-in file reparse point is not followed.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        fs::OpenOptions::new()
            .read(true)
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
}
