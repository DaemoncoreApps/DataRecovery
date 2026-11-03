pub mod exfat;
pub mod fat32;
pub mod ntfs;
pub mod partition;

pub mod storage {
    use std::io;

    pub trait BlockSource: Send + Sync {
        fn len(&self) -> u64;
        fn is_empty(&self) -> bool {
            self.len() == 0
        }
        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()>;
    }
}
