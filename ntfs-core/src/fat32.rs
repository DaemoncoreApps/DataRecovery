use crate::storage::BlockSource;
use std::collections::HashSet;

type Result<T> = std::result::Result<T, String>;

const FAT32_EOC: u32 = 0x0fff_fff8;
const FAT32_BAD: u32 = 0x0fff_fff7;
const FAT32_RESERVED_START: u32 = 0x0fff_fff0;
const MAX_CHAIN_CLUSTERS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    offset: u64,
    volume_size: u64,
    bytes_per_sector: u32,
    sectors_per_cluster: u8,
    cluster_count: u32,
    root_cluster: u32,
    fat_offset: u64,
    data_offset: u64,
    sectors_per_fat: u32,
    fat_count: u8,
    active_fat: u8,
    mirrored_fats: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMapping {
    size: u64,
    clusters: Vec<u32>,
}

impl Volume {
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    pub fn open(source: &dyn BlockSource, offset: u64, partition_size: u64) -> Result<Self> {
        if partition_size < 512
            || offset
                .checked_add(partition_size)
                .is_none_or(|end| end > source.len())
        {
            return Err("FAT32 partition extends beyond the source image".into());
        }
        let mut boot = [0; 512];
        source
            .read_exact_at(offset, &mut boot)
            .map_err(|error| format!("Could not read FAT32 boot sector: {error}"))?;
        if !matches!(boot.get(..3), Some([0xeb, _, 0x90]) | Some([0xe9, _, _]))
            || boot[510..512] != [0x55, 0xaa]
        {
            return Err("No valid FAT32 boot-sector signature at this offset".into());
        }

        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u32;
        let sectors_per_cluster = boot[13];
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]) as u32;
        let fat_count = boot[16];
        let root_entry_count = u16::from_le_bytes([boot[17], boot[18]]);
        let total_sectors_16 = u16::from_le_bytes([boot[19], boot[20]]);
        let fat_size_16 = u16::from_le_bytes([boot[22], boot[23]]);
        let total_sectors_32 = u32::from_le_bytes(boot[32..36].try_into().unwrap());
        let sectors_per_fat = u32::from_le_bytes(boot[36..40].try_into().unwrap());
        let extended_flags = u16::from_le_bytes([boot[40], boot[41]]);
        let filesystem_version = u16::from_le_bytes([boot[42], boot[43]]);
        let root_cluster = u32::from_le_bytes(boot[44..48].try_into().unwrap());

        let total_sectors = if total_sectors_32 != 0 {
            total_sectors_32
        } else {
            u32::from(total_sectors_16)
        };
        let active_fat = (extended_flags & 0x000f) as u8;
        let mirrored_fats = extended_flags & 0x0080 == 0;

        if !(512..=4096).contains(&bytes_per_sector)
            || !bytes_per_sector.is_power_of_two()
            || !matches!(sectors_per_cluster, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128)
            || reserved_sectors == 0
            || !matches!(fat_count, 1 | 2)
            || root_entry_count != 0
            || total_sectors_16 != 0
            || fat_size_16 != 0
            || total_sectors == 0
            || sectors_per_fat == 0
            || extended_flags & !0x008f != 0
            || (!mirrored_fats && active_fat >= fat_count)
            || filesystem_version != 0
        {
            return Err("Invalid or unsupported FAT32 boot geometry".into());
        }

        let volume_size = u64::from(total_sectors)
            .checked_mul(u64::from(bytes_per_sector))
            .ok_or("FAT32 volume size overflow")?;
        if volume_size > partition_size
            || offset
                .checked_add(volume_size)
                .is_none_or(|end| end > source.len())
        {
            return Err("FAT32 volume extends beyond its partition or source image".into());
        }

        let fat_area_sectors = u64::from(fat_count)
            .checked_mul(u64::from(sectors_per_fat))
            .ok_or("FAT32 table area overflow")?;
        let data_start_sector = u64::from(reserved_sectors)
            .checked_add(fat_area_sectors)
            .ok_or("FAT32 data offset overflow")?;
        if data_start_sector >= u64::from(total_sectors) {
            return Err("FAT32 data region is empty or outside the volume".into());
        }

        let data_sectors = u64::from(total_sectors) - data_start_sector;
        let cluster_count = data_sectors / u64::from(sectors_per_cluster);
        let fat_capacity_entries = u64::from(sectors_per_fat)
            .checked_mul(u64::from(bytes_per_sector))
            .and_then(|bytes| bytes.checked_div(4))
            .ok_or("FAT32 table capacity overflow")?;
        if !(65_525..=0x0fff_fff5).contains(&cluster_count)
            || u64::from(root_cluster) < 2
            || u64::from(root_cluster) > cluster_count + 1
            || fat_capacity_entries < cluster_count + 2
        {
            return Err("FAT32 cluster count, root cluster, or table capacity is invalid".into());
        }

        let fat_offset = offset
            .checked_add(u64::from(reserved_sectors) * u64::from(bytes_per_sector))
            .ok_or("FAT32 table offset overflow")?;
        let data_offset = offset
            .checked_add(
                data_start_sector
                    .checked_mul(u64::from(bytes_per_sector))
                    .ok_or("FAT32 data offset overflow")?,
            )
            .ok_or("FAT32 data offset overflow")?;
        Ok(Self {
            offset,
            volume_size,
            bytes_per_sector,
            sectors_per_cluster,
            cluster_count: cluster_count as u32,
            root_cluster,
            fat_offset,
            data_offset,
            sectors_per_fat,
            fat_count,
            active_fat,
            mirrored_fats,
        })
    }

    pub fn cluster_size(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_cluster)
    }

    fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if !(2..=self.cluster_count + 1).contains(&cluster) {
            return Err("FAT32 cluster number is outside the data region".into());
        }
        let offset = self
            .data_offset
            .checked_add(
                u64::from(cluster - 2)
                    .checked_mul(self.cluster_size())
                    .ok_or("FAT32 cluster offset overflow")?,
            )
            .ok_or("FAT32 cluster offset overflow")?;
        if offset
            .checked_add(self.cluster_size())
            .is_none_or(|end| end > self.offset + self.volume_size)
        {
            return Err("FAT32 cluster extends beyond the volume".into());
        }
        Ok(offset)
    }

    fn next_cluster(&self, source: &dyn BlockSource, cluster: u32) -> Result<Option<u32>> {
        if !(2..=self.cluster_count + 1).contains(&cluster) {
            return Err("FAT32 cluster chain references an invalid cluster".into());
        }
        let copies: Box<dyn Iterator<Item = u8>> = if self.mirrored_fats {
            Box::new(0..self.fat_count)
        } else {
            Box::new(std::iter::once(self.active_fat))
        };
        let mut value = None;
        for fat_index in copies {
            let entry_offset = self
                .fat_offset
                .checked_add(
                    u64::from(fat_index)
                        .checked_mul(u64::from(self.sectors_per_fat))
                        .and_then(|base| base.checked_mul(u64::from(self.bytes_per_sector)))
                        .ok_or("FAT32 entry offset overflow")?,
                )
                .and_then(|base| base.checked_add(u64::from(cluster) * 4))
                .ok_or("FAT32 entry offset overflow")?;
            let mut raw = [0; 4];
            source
                .read_exact_at(entry_offset, &mut raw)
                .map_err(|error| format!("Could not read FAT32 allocation entry: {error}"))?;
            let next = u32::from_le_bytes(raw) & 0x0fff_ffff;
            if value.is_some_and(|previous| previous != next) {
                return Err("Mirrored FAT32 allocation tables disagree for this cluster".into());
            }
            value = Some(next);
        }
        let value = value.ok_or("FAT32 volume has no active allocation table")?;
        match value {
            0 => Err("FAT32 cluster chain enters a free cluster".into()),
            1 | FAT32_RESERVED_START..=0x0fff_fff6 => {
                Err("FAT32 cluster chain contains a reserved value".into())
            }
            FAT32_BAD => Err("FAT32 cluster chain contains a bad-cluster marker".into()),
            FAT32_EOC..=0x0fff_ffff => Ok(None),
            next if (2..=self.cluster_count + 1).contains(&next) => Ok(Some(next)),
            _ => Err("FAT32 cluster chain points beyond the data region".into()),
        }
    }

    pub fn map_file(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
        size: u64,
    ) -> Result<FileMapping> {
        if size == 0 && first_cluster == 0 {
            return Ok(FileMapping {
                size,
                clusters: Vec::new(),
            });
        }
        if size > self.volume_size || first_cluster < 2 {
            return Err("FAT32 file size or starting cluster is invalid".into());
        }
        let required_clusters = size.div_ceil(self.cluster_size());
        let mut clusters = Vec::new();
        let mut visited = HashSet::new();
        let mut current = first_cluster;
        loop {
            if !visited.insert(current) {
                return Err("FAT32 cluster chain contains a cycle".into());
            }
            self.cluster_offset(current)?;
            if clusters.len() >= MAX_CHAIN_CLUSTERS || clusters.len() >= self.cluster_count as usize
            {
                return Err("FAT32 cluster chain exceeds the volume safety bound".into());
            }
            clusters.push(current);
            match self.next_cluster(source, current)? {
                Some(next) => current = next,
                None => break,
            }
        }
        if (clusters.len() as u64) < required_clusters {
            return Err("FAT32 cluster chain is shorter than the file size".into());
        }
        Ok(FileMapping { size, clusters })
    }

    pub fn read_file_at(
        &self,
        source: &dyn BlockSource,
        mapping: &FileMapping,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > mapping.size)
        {
            return Err("FAT32 file read exceeds the directory entry size".into());
        }
        let cluster_size = self.cluster_size();
        let mut written = 0;
        while written < output.len() {
            let position = offset + written as u64;
            let cluster_index = usize::try_from(position / cluster_size)
                .map_err(|_| "FAT32 file position is too large")?;
            let cluster = *mapping
                .clusters
                .get(cluster_index)
                .ok_or("FAT32 file mapping is shorter than the requested read")?;
            let within_cluster = position % cluster_size;
            let count =
                (cluster_size - within_cluster).min((output.len() - written) as u64) as usize;
            let physical = self
                .cluster_offset(cluster)?
                .checked_add(within_cluster)
                .ok_or("FAT32 file offset overflow")?;
            source
                .read_exact_at(physical, &mut output[written..written + count])
                .map_err(|error| format!("Could not read FAT32 file data: {error}"))?;
            written += count;
        }
        Ok(())
    }
}

impl FileMapping {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn clusters(&self) -> &[u32] {
        &self.clusters
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct SliceSource<'a>(&'a [u8]);

    impl BlockSource for SliceSource<'_> {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
            let start =
                usize::try_from(offset).map_err(|_| io::Error::other("test offset overflow"))?;
            let end = start
                .checked_add(buffer.len())
                .ok_or_else(|| io::Error::other("test read overflow"))?;
            buffer.copy_from_slice(
                self.0
                    .get(start..end)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?,
            );
            Ok(())
        }
    }

    fn fixture() -> Vec<u8> {
        let total_sectors = 66_581_u32;
        let mut image = vec![0; total_sectors as usize * 512];
        image[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        image[11..13].copy_from_slice(&512_u16.to_le_bytes());
        image[13] = 1;
        image[14..16].copy_from_slice(&32_u16.to_le_bytes());
        image[16] = 2;
        image[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        image[36..40].copy_from_slice(&512_u32.to_le_bytes());
        image[44..48].copy_from_slice(&2_u32.to_le_bytes());
        image[48..50].copy_from_slice(&1_u16.to_le_bytes());
        image[50..52].copy_from_slice(&6_u16.to_le_bytes());
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        for fat_sector in [32_usize, 544] {
            let fat = fat_sector * 512;
            image[fat + 2 * 4..fat + 2 * 4 + 4].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
            image[fat + 3 * 4..fat + 3 * 4 + 4].copy_from_slice(&5_u32.to_le_bytes());
            image[fat + 5 * 4..fat + 5 * 4 + 4].copy_from_slice(&0x0fff_ffff_u32.to_le_bytes());
        }
        let data = 1056 * 512;
        image[data + 512..data + 1024].fill(b'a');
        image[data + 3 * 512..data + 4 * 512].fill(b'b');
        image
    }

    fn set_fat_entry(image: &mut [u8], fat_sector: usize, cluster: usize, value: u32) {
        let offset = fat_sector * 512 + cluster * 4;
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn maps_fragmented_fat32_file_and_rejects_untrusted_chains() {
        let mut image = fixture();
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert_eq!(volume.cluster_count, 65_525);
        let mapping = volume.map_file(&source, 3, 700).unwrap();
        assert_eq!(mapping.clusters, vec![3, 5]);
        let mut recovered = vec![0; 200];
        volume
            .read_file_at(&source, &mapping, 500, &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..12], &[b'a'; 12]);
        assert_eq!(&recovered[12..], &[b'b'; 188]);
        assert!(volume
            .read_file_at(&source, &mapping, 650, &mut recovered)
            .is_err());
        drop(source);

        for fat_sector in [32_usize, 544] {
            set_fat_entry(&mut image, fat_sector, 5, 3);
        }
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_file(&source, 3, 700)
            .unwrap_err()
            .contains("cycle"));
        drop(source);

        set_fat_entry(&mut image, 32, 5, 0x0fff_ffff);
        set_fat_entry(&mut image, 544, 5, 0x0fff_ffff);
        set_fat_entry(&mut image, 544, 3, 6);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_file(&source, 3, 700)
            .unwrap_err()
            .contains("disagree"));
        drop(source);

        set_fat_entry(&mut image, 32, 3, 0);
        set_fat_entry(&mut image, 544, 3, 0);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_file(&source, 3, 100)
            .unwrap_err()
            .contains("free"));
        drop(source);

        for invalid in [FAT32_BAD, FAT32_RESERVED_START] {
            set_fat_entry(&mut image, 32, 3, invalid);
            set_fat_entry(&mut image, 544, 3, invalid);
            let source = SliceSource(&image);
            let volume = Volume::open(&source, 0, source.len()).unwrap();
            let error = volume.map_file(&source, 3, 100).unwrap_err();
            assert!(error.contains("bad-cluster") || error.contains("reserved"));
        }

        set_fat_entry(&mut image, 32, 3, FAT32_EOC);
        set_fat_entry(&mut image, 544, 3, FAT32_EOC);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_file(&source, 3, 600)
            .unwrap_err()
            .contains("shorter"));
        assert!(Volume::open(&source, 0, source.len() - 1).is_err());
    }
}
