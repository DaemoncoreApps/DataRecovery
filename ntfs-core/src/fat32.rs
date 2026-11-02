use crate::storage::BlockSource;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

type Result<T> = std::result::Result<T, String>;

const FAT32_EOC: u32 = 0x0fff_fff8;
const FAT32_BAD: u32 = 0x0fff_fff7;
const FAT32_RESERVED_START: u32 = 0x0fff_fff0;
const MAX_CHAIN_CLUSTERS: usize = 1_000_000;
const MAX_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAX_DIRECTORY_DEPTH: usize = 256;
const FAT_RANGE_READ_BYTES: usize = 64 * 1024;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedFileMapping {
    mapping: FileMapping,
    layout: DeletedClusterLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletedClusterLayout {
    ContiguousAssumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DirectoryEntry {
    /// Absolute source offset of the short-name record.
    pub source_offset: u64,
    /// Exact 32-byte short-name record from the image.
    pub raw_record: [u8; 32],
    /// The on-disk 8.3 name bytes, retained for exact identification.
    pub short_name: [u8; 11],
    /// A checksum-verified long name, when its complete LFN sequence is valid.
    pub long_name: Option<String>,
    pub deleted: bool,
    pub attributes: u8,
    pub first_cluster: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct TreeEntry {
    pub path: Vec<String>,
    pub entry: DirectoryEntry,
}

impl DirectoryEntry {
    pub fn is_directory(&self) -> bool {
        self.attributes & 0x10 != 0
    }

    pub fn is_volume_label(&self) -> bool {
        self.attributes & 0x08 != 0
    }

    /// Render the short name without interpreting non-ASCII OEM bytes.
    /// The original bytes remain available in `short_name` for forensic use.
    pub fn display_name(&self) -> String {
        if let Some(long_name) = &self.long_name {
            return long_name.clone();
        }
        let mut short_name = self.short_name;
        if self.deleted {
            short_name[0] = b'?';
        }
        let base = String::from_utf8_lossy(&short_name[..8])
            .trim_end()
            .to_owned();
        let extension = String::from_utf8_lossy(&short_name[8..])
            .trim_end()
            .to_owned();
        if extension.is_empty() {
            base
        } else {
            format!("{base}.{extension}")
        }
    }
}

impl Volume {
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
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
        let primary_metadata = crate::partition::parse_fat32_boot_sector(
            &boot,
            bytes_per_sector,
            partition_size / u64::from(bytes_per_sector.max(1)),
        )
        .ok_or("FAT32 primary boot metadata is inconsistent")?;
        if primary_metadata.backup_boot_sector != 0 {
            let backup_offset = offset
                .checked_add(
                    u64::from(primary_metadata.backup_boot_sector)
                        .checked_mul(u64::from(bytes_per_sector))
                        .ok_or("FAT32 backup boot-sector offset overflow")?,
                )
                .ok_or("FAT32 backup boot-sector offset overflow")?;
            let mut backup = [0; 512];
            source
                .read_exact_at(backup_offset, &mut backup)
                .map_err(|error| format!("Could not read FAT32 backup boot sector: {error}"))?;
            let backup_metadata = crate::partition::parse_fat32_boot_sector(
                &backup,
                bytes_per_sector,
                partition_size / u64::from(bytes_per_sector.max(1)),
            )
            .ok_or("FAT32 backup boot metadata is invalid")?;
            if backup_metadata != primary_metadata {
                return Err("FAT32 primary and backup boot metadata disagree".into());
            }
        }
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

    /// Enumerate live short-name entries and validated long-name records in a
    /// directory cluster chain. Deleted entries are not inferred here.
    pub fn read_directory(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
    ) -> Result<Vec<DirectoryEntry>> {
        self.read_directory_records(source, first_cluster, false)
    }

    fn read_directory_records(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
        include_deleted: bool,
    ) -> Result<Vec<DirectoryEntry>> {
        if first_cluster < 2 {
            return Err("FAT32 directory starting cluster is invalid".into());
        }
        let mut entries = Vec::new();
        let mut visited = HashSet::new();
        let mut cluster = first_cluster;
        let mut lfn_parts: Option<Vec<Option<[u16; 13]>>> = None;
        let mut lfn_expected = None;
        let mut lfn_checksum = None;
        loop {
            if !visited.insert(cluster) {
                return Err("FAT32 directory chain contains a cycle".into());
            }
            if visited.len() > MAX_CHAIN_CLUSTERS || visited.len() > self.cluster_count as usize {
                return Err("FAT32 directory chain exceeds the volume safety bound".into());
            }
            let offset = self.cluster_offset(cluster)?;
            let mut bytes = vec![0; self.cluster_size() as usize];
            source
                .read_exact_at(offset, &mut bytes)
                .map_err(|error| format!("Could not read FAT32 directory cluster: {error}"))?;
            let mut ended = false;
            let (records, remainder) = bytes.as_chunks::<32>();
            if !remainder.is_empty() {
                return Err("FAT32 directory cluster has an invalid record boundary".into());
            }
            for (record_index, record) in records.iter().enumerate() {
                if record[0] == 0 {
                    ended = true;
                    break;
                }
                let deleted = record[0] == 0xe5;
                if deleted {
                    lfn_parts = None;
                    lfn_expected = None;
                    lfn_checksum = None;
                    if !include_deleted || record[11] == 0x0f || record[11] & 0x08 != 0 {
                        continue;
                    }
                }
                if !deleted && record[11] == 0x0f {
                    let ordinal = record[0] & 0x1f;
                    let is_last = record[0] & 0x40 != 0;
                    if record[0] & 0xa0 != 0
                        || ordinal == 0
                        || ordinal > 20
                        || record[12] != 0
                        || record[26..28] != [0, 0]
                    {
                        lfn_parts = None;
                        lfn_expected = None;
                        lfn_checksum = None;
                        continue;
                    }
                    if is_last {
                        lfn_parts = Some(vec![None; ordinal as usize]);
                        lfn_expected = Some(ordinal);
                        lfn_checksum = Some(record[13]);
                    }
                    if lfn_expected != Some(ordinal) || lfn_checksum != Some(record[13]) {
                        lfn_parts = None;
                        lfn_expected = None;
                        lfn_checksum = None;
                        continue;
                    }
                    let mut units = [0; 13];
                    for (slot, source) in [(0..5, 1..11), (5..11, 14..26), (11..13, 28..32)] {
                        for (unit_index, byte_index) in slot.zip(source.step_by(2)) {
                            units[unit_index] =
                                u16::from_le_bytes([record[byte_index], record[byte_index + 1]]);
                        }
                    }
                    if let Some(parts) = lfn_parts.as_mut() {
                        parts[ordinal as usize - 1] = Some(units);
                        lfn_expected = Some(ordinal - 1);
                    }
                    continue;
                }
                if entries.len() >= MAX_DIRECTORY_ENTRIES {
                    return Err("FAT32 directory exceeds the entry safety bound".into());
                }
                let mut short_name = [0; 11];
                short_name.copy_from_slice(&record[..11]);
                let long_name = if !deleted
                    && lfn_expected == Some(0)
                    && lfn_checksum == Some(lfn_short_name_checksum(&short_name))
                {
                    lfn_parts.as_ref().and_then(|parts| decode_lfn_parts(parts))
                } else {
                    None
                };
                lfn_parts = None;
                lfn_expected = None;
                lfn_checksum = None;
                let high = u16::from_le_bytes([record[20], record[21]]) as u32;
                let low = u16::from_le_bytes([record[26], record[27]]) as u32;
                let mut raw_record = [0; 32];
                raw_record.copy_from_slice(record);
                entries.push(DirectoryEntry {
                    source_offset: offset + (record_index * 32) as u64,
                    raw_record,
                    short_name,
                    long_name,
                    deleted,
                    attributes: record[11],
                    first_cluster: (high << 16) | low,
                    size: u32::from_le_bytes(record[28..32].try_into().unwrap()),
                });
            }
            if ended {
                return Ok(entries);
            }
            match self.next_cluster(source, cluster)? {
                Some(next) => cluster = next,
                None => return Ok(entries),
            }
        }
    }

    /// Enumerate live entries below the FAT32 root with explicit depth,
    /// entry-count, and directory-cluster cycle bounds.
    pub fn read_tree(&self, source: &dyn BlockSource) -> Result<Vec<TreeEntry>> {
        self.read_tree_records(source, false)
    }

    /// Include deleted short-name directory records in the traversal result.
    /// Deleted long-name slots are not emitted as files because their original
    /// ordinals are overwritten by the deletion marker.
    pub fn read_tree_including_deleted(&self, source: &dyn BlockSource) -> Result<Vec<TreeEntry>> {
        self.read_tree_records(source, true)
    }

    fn read_tree_records(
        &self,
        source: &dyn BlockSource,
        include_deleted: bool,
    ) -> Result<Vec<TreeEntry>> {
        let mut output = Vec::new();
        let mut visited_directories = HashSet::new();
        let mut pending = vec![(self.root_cluster, Vec::<String>::new(), 0_usize)];
        visited_directories.insert(self.root_cluster);

        while let Some((cluster, parent_path, depth)) = pending.pop() {
            let entries = self.read_directory_records(source, cluster, include_deleted)?;
            let mut child_directories = Vec::new();
            for entry in entries {
                if !entry.deleted
                    && (entry.short_name == *b".          " || entry.short_name == *b"..         ")
                {
                    continue;
                }
                if output.len() >= MAX_DIRECTORY_ENTRIES {
                    return Err("FAT32 tree exceeds the entry safety bound".into());
                }
                let mut path = parent_path.clone();
                path.push(entry.display_name());
                if !entry.deleted && entry.is_directory() && !entry.is_volume_label() {
                    if depth >= MAX_DIRECTORY_DEPTH {
                        return Err("FAT32 directory tree exceeds the depth safety bound".into());
                    }
                    if entry.first_cluster < 2 {
                        return Err("FAT32 subdirectory has an invalid starting cluster".into());
                    }
                    if !visited_directories.insert(entry.first_cluster) {
                        return Err(
                            "FAT32 directory tree contains a cycle or cross-linked directory"
                                .into(),
                        );
                    }
                    child_directories.push((entry.first_cluster, path.clone(), depth + 1));
                }
                output.push(TreeEntry { path, entry });
            }
            pending.extend(child_directories.into_iter().rev());
        }
        Ok(output)
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
        let value = self.fat_entry(source, cluster)?;
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

    fn fat_entry(&self, source: &dyn BlockSource, cluster: u32) -> Result<u32> {
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
        value.ok_or_else(|| "FAT32 volume has no active allocation table".into())
    }

    fn ensure_free_contiguous_range(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
        cluster_count: u64,
    ) -> Result<()> {
        let entry_bytes = cluster_count
            .checked_mul(4)
            .ok_or("Deleted FAT32 allocation range overflow")?;
        let fat_bytes = u64::from(self.sectors_per_fat)
            .checked_mul(u64::from(self.bytes_per_sector))
            .ok_or("FAT32 table size overflow")?;
        let fat_indexes: Vec<u8> = if self.mirrored_fats {
            (0..self.fat_count).collect()
        } else {
            vec![self.active_fat]
        };
        let mut position = 0_u64;
        let mut buffers = vec![vec![0; FAT_RANGE_READ_BYTES]; fat_indexes.len()];
        while position < entry_bytes {
            let count = (entry_bytes - position).min(FAT_RANGE_READ_BYTES as u64) as usize;
            for (copy_index, fat_index) in fat_indexes.iter().enumerate() {
                let copy_offset = u64::from(*fat_index)
                    .checked_mul(fat_bytes)
                    .ok_or("FAT32 table offset overflow")?;
                let offset = self
                    .fat_offset
                    .checked_add(copy_offset)
                    .and_then(|base| base.checked_add(u64::from(first_cluster) * 4))
                    .and_then(|base| base.checked_add(position))
                    .ok_or("FAT32 allocation range offset overflow")?;
                source
                    .read_exact_at(offset, &mut buffers[copy_index][..count])
                    .map_err(|error| format!("Could not read FAT32 allocation range: {error}"))?;
            }
            for entry_index in 0..(count / 4) {
                let start = entry_index * 4;
                let first_value =
                    u32::from_le_bytes(buffers[0][start..start + 4].try_into().unwrap())
                        & 0x0fff_ffff;
                if buffers.iter().skip(1).any(|buffer| {
                    (u32::from_le_bytes(buffer[start..start + 4].try_into().unwrap()) & 0x0fff_ffff)
                        != first_value
                }) {
                    return Err(
                        "Mirrored FAT32 allocation tables disagree for this cluster range".into(),
                    );
                }
                if first_value != 0 {
                    return Err("Deleted FAT32 file overlaps a cluster that is not free".into());
                }
            }
            position += count as u64;
        }
        Ok(())
    }

    /// Map a deleted file only when its entire expected cluster run is
    /// contiguous and remains free in every selected/mirrored FAT copy. This
    /// is an explicit recovery assumption; a prior fragmented chain cannot be
    /// reconstructed from a deleted directory entry alone.
    pub fn map_deleted_file_contiguous(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
        size: u64,
    ) -> Result<DeletedFileMapping> {
        if size == 0 || size > self.volume_size || first_cluster < 2 {
            return Err("Deleted FAT32 file size or starting cluster is invalid".into());
        }
        let required_clusters = size.div_ceil(self.cluster_size());
        if required_clusters > MAX_CHAIN_CLUSTERS as u64 {
            return Err("Deleted FAT32 file exceeds the recovery safety bound".into());
        }
        let last_cluster = first_cluster
            .checked_add(
                u32::try_from(required_clusters - 1)
                    .map_err(|_| "Deleted FAT32 file is too large")?,
            )
            .ok_or("Deleted FAT32 cluster range overflow")?;
        self.cluster_offset(first_cluster)?;
        self.cluster_offset(last_cluster)?;
        self.ensure_free_contiguous_range(source, first_cluster, required_clusters)?;
        let mut clusters = Vec::with_capacity(required_clusters as usize);
        for cluster in first_cluster..=last_cluster {
            clusters.push(cluster);
        }
        Ok(DeletedFileMapping {
            mapping: FileMapping { size, clusters },
            layout: DeletedClusterLayout::ContiguousAssumed,
        })
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

fn lfn_short_name_checksum(short_name: &[u8; 11]) -> u8 {
    short_name.iter().fold(0_u8, |checksum, byte| {
        checksum.rotate_right(1).wrapping_add(*byte)
    })
}

fn decode_lfn_parts(parts: &[Option<[u16; 13]>]) -> Option<String> {
    if parts.is_empty() || parts.len() > 20 {
        return None;
    }
    let mut units = Vec::with_capacity(parts.len() * 13);
    for part in parts {
        units.extend_from_slice(part.as_ref()?);
    }
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    if units[end..]
        .iter()
        .any(|unit| *unit != 0 && *unit != 0xffff)
        || units[..end].contains(&0xffff)
        || end == 0
    {
        return None;
    }
    String::from_utf16(&units[..end]).ok()
}

impl FileMapping {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn clusters(&self) -> &[u32] {
        &self.clusters
    }
}

impl DeletedFileMapping {
    pub fn mapping(&self) -> &FileMapping {
        &self.mapping
    }

    pub fn layout(&self) -> DeletedClusterLayout {
        self.layout
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
        let primary_boot = image[..512].to_vec();
        image[6 * 512..7 * 512].copy_from_slice(&primary_boot);
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

    fn set_directory_entry(
        image: &mut [u8],
        index: usize,
        short_name: &[u8; 11],
        attributes: u8,
        first_cluster: u32,
        size: u32,
    ) {
        set_directory_entry_in_cluster(
            image,
            2,
            index,
            short_name,
            attributes,
            first_cluster,
            size,
        );
    }

    fn set_directory_entry_in_cluster(
        image: &mut [u8],
        cluster: u32,
        index: usize,
        short_name: &[u8; 11],
        attributes: u8,
        first_cluster: u32,
        size: u32,
    ) {
        let offset = 1056 * 512 + (cluster as usize - 2) * 512 + index * 32;
        image[offset..offset + 11].copy_from_slice(short_name);
        image[offset + 11] = attributes;
        image[offset + 20..offset + 22]
            .copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        image[offset + 26..offset + 28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        image[offset + 28..offset + 32].copy_from_slice(&size.to_le_bytes());
    }

    fn set_lfn_entries(image: &mut [u8], start: usize, name: &str, short_name: &[u8; 11]) {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        units.push(0);
        let count = units.len().div_ceil(13);
        units.resize(count * 13, 0xffff);
        let checksum = lfn_short_name_checksum(short_name);
        for ordinal in (1..=count).rev() {
            let image_index = start + count - ordinal;
            let offset = 1056 * 512 + image_index * 32;
            let record = &mut image[offset..offset + 32];
            record.fill(0);
            record[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
            record[11] = 0x0f;
            record[13] = checksum;
            let chunk = &units[(ordinal - 1) * 13..ordinal * 13];
            for (unit_index, byte_index) in (0..5)
                .zip((1..11).step_by(2))
                .chain((5..11).zip((14..26).step_by(2)))
                .chain((11..13).zip((28..32).step_by(2)))
            {
                record[byte_index..byte_index + 2]
                    .copy_from_slice(&chunk[unit_index].to_le_bytes());
            }
        }
    }

    #[test]
    fn reads_live_fat32_directory_entries_and_preserves_raw_short_names() {
        let mut image = fixture();
        set_directory_entry(&mut image, 0, b"REPORT  TXT", 0x20, 3, 700);
        set_directory_entry(&mut image, 1, b"SUBDIR     ", 0x10, 5, 0);
        set_directory_entry(&mut image, 2, b"DELETED TXT", 0x20, 6, 10);
        image[1056 * 512 + 2 * 32] = 0xe5;
        set_directory_entry(&mut image, 3, b"LONGNA~1TXT", 0x0f, 0, 0);
        set_directory_entry(&mut image, 4, b"VOLUME     ", 0x08, 0, 0);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();

        assert_eq!(volume.root_cluster(), 2);
        let entries = volume
            .read_directory(&source, volume.root_cluster())
            .unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].source_offset, 1056 * 512);
        assert_eq!(&entries[0].raw_record[..11], b"REPORT  TXT");
        assert_eq!(entries[0].short_name, *b"REPORT  TXT");
        assert_eq!(entries[0].display_name(), "REPORT.TXT");
        assert_eq!(entries[0].size, 700);
        assert!(!entries[0].is_directory());
        assert!(entries[1].is_directory());
        assert_eq!(entries[1].first_cluster, 5);
        assert!(entries[2].is_volume_label());
        assert!(volume.read_directory(&source, 1).is_err());
    }

    #[test]
    fn reconstructs_only_complete_checksum_valid_lfn_sequences() {
        let mut image = fixture();
        let short_name = b"RECOVE~1TXT";
        set_lfn_entries(&mut image, 0, "Recovered evidence.txt", short_name);
        set_directory_entry(&mut image, 2, short_name, 0x20, 3, 700);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let entries = volume
            .read_directory(&source, volume.root_cluster())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_offset, 1056 * 512 + 2 * 32);
        assert_eq!(
            entries[0].long_name.as_deref(),
            Some("Recovered evidence.txt")
        );
        assert_eq!(entries[0].display_name(), "Recovered evidence.txt");
        drop(source);

        image[1056 * 512 + 13] ^= 0x80;
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let entries = volume
            .read_directory(&source, volume.root_cluster())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].long_name, None);
        assert_eq!(entries[0].display_name(), "RECOVE~1.TXT");
    }

    #[test]
    fn deleted_lfn_records_never_attach_to_a_live_short_entry() {
        let mut image = fixture();
        let short_name = b"RECOVE~1TXT";
        set_lfn_entries(&mut image, 0, "Recovered evidence.txt", short_name);
        image[1056 * 512] = 0xe5;
        set_directory_entry(&mut image, 2, short_name, 0x20, 3, 700);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let entries = volume
            .read_directory(&source, volume.root_cluster())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].long_name, None);
        assert_eq!(entries[0].display_name(), "RECOVE~1.TXT");
    }

    #[test]
    fn reads_nested_fat32_entries_and_rejects_directory_cross_links() {
        let mut image = fixture();
        set_directory_entry(&mut image, 0, b"SUBDIR     ", 0x10, 5, 0);
        set_directory_entry_in_cluster(&mut image, 5, 0, b"NOTE    TXT", 0x20, 3, 12);
        image[1056 * 512 + 3 * 512 + 32] = 0;
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let tree = volume.read_tree(&source).unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].path, ["SUBDIR"]);
        assert_eq!(tree[1].path, ["SUBDIR", "NOTE.TXT"]);
        drop(source);

        set_directory_entry_in_cluster(&mut image, 5, 0, b"BACK       ", 0x10, 2, 0);
        image[1056 * 512 + 3 * 512 + 32] = 0;
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .read_tree(&source)
            .unwrap_err()
            .contains("cross-linked directory"));
    }

    #[test]
    fn lists_deleted_short_entries_and_only_maps_free_contiguous_clusters() {
        let mut image = fixture();
        set_directory_entry(&mut image, 0, b"DELETED TXT", 0x20, 10, 700);
        image[1056 * 512] = 0xe5;
        let cluster10 = 1056 * 512 + 8 * 512;
        let cluster11 = 1056 * 512 + 9 * 512;
        image[cluster10..cluster10 + 512].fill(b'a');
        image[cluster11..cluster11 + 512].fill(b'b');
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume.read_tree(&source).unwrap().is_empty());
        let tree = volume.read_tree_including_deleted(&source).unwrap();
        assert_eq!(tree.len(), 1);
        assert!(tree[0].entry.deleted);
        assert_eq!(tree[0].path, ["?ELETED.TXT"]);

        let deleted = volume
            .map_deleted_file_contiguous(&source, 10, 700)
            .unwrap();
        assert_eq!(deleted.layout(), DeletedClusterLayout::ContiguousAssumed);
        assert_eq!(deleted.mapping().clusters(), &[10, 11]);
        let mut recovered = vec![0; 200];
        volume
            .read_file_at(&source, deleted.mapping(), 500, &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..12], &[b'a'; 12]);
        assert_eq!(&recovered[12..], &[b'b'; 188]);
        drop(source);

        set_fat_entry(&mut image, 544, 11, 1);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_deleted_file_contiguous(&source, 10, 700)
            .unwrap_err()
            .contains("disagree"));
        drop(source);

        set_fat_entry(&mut image, 32, 11, FAT32_EOC);
        set_fat_entry(&mut image, 544, 11, FAT32_EOC);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_deleted_file_contiguous(&source, 10, 700)
            .unwrap_err()
            .contains("not free"));
        assert!(volume
            .map_deleted_file_contiguous(&source, 0x0fff_fff5, 700)
            .is_err());
    }

    #[test]
    fn deleted_mapping_uses_the_declared_active_fat_when_mirroring_is_disabled() {
        let mut image = fixture();
        for boot_offset in [0, 6 * 512] {
            image[boot_offset + 40..boot_offset + 42].copy_from_slice(&0x0081_u16.to_le_bytes());
        }
        for cluster in [10, 11] {
            set_fat_entry(&mut image, 32, cluster, FAT32_EOC);
        }
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let deleted = volume
            .map_deleted_file_contiguous(&source, 10, 700)
            .unwrap();
        assert_eq!(deleted.mapping().clusters(), &[10, 11]);
        drop(source);

        set_fat_entry(&mut image, 544, 11, FAT32_EOC);
        let source = SliceSource(&image);
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        assert!(volume
            .map_deleted_file_contiguous(&source, 10, 700)
            .unwrap_err()
            .contains("not free"));
    }

    #[test]
    fn refuses_invalid_or_conflicting_fat32_backup_boot_metadata() {
        let mut image = fixture();
        image[6 * 512 + 510] ^= 1;
        let source = SliceSource(&image);
        assert!(Volume::open(&source, 0, source.len())
            .unwrap_err()
            .contains("backup boot metadata is invalid"));
        drop(source);

        let mut image = fixture();
        image[6 * 512 + 40..6 * 512 + 42].copy_from_slice(&0x0081_u16.to_le_bytes());
        let source = SliceSource(&image);
        assert!(Volume::open(&source, 0, source.len())
            .unwrap_err()
            .contains("metadata disagree"));
        drop(source);

        let mut image = fixture();
        image[6 * 512 + 67..6 * 512 + 71].copy_from_slice(&1_u32.to_le_bytes());
        let source = SliceSource(&image);
        assert!(Volume::open(&source, 0, source.len())
            .unwrap_err()
            .contains("metadata disagree"));
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
