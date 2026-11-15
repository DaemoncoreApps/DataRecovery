use crate::{partition, storage::BlockSource};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

type Result<T> = std::result::Result<T, String>;
type BitmapEntry = (u8, u32, u64);
type UpcaseEntry = (u32, u64, u32);

const FAT_EOC: u32 = 0xffff_fff8;
const FAT_BAD: u32 = 0xffff_fff7;
const FAT_RESERVED_START: u32 = 0xffff_fff0;
const FAT_RESERVED_END: u32 = 0xffff_fff6;
const MAX_CHAIN_CLUSTERS: usize = 1_000_000;
const MAX_DIRECTORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAX_DIRECTORY_DEPTH: usize = 256;
const MAX_PARSED_DIRECTORY_MEMORY: usize = 128 * 1024 * 1024;
const MAX_DIRECTORY_TREE_MEMORY: usize = 256 * 1024 * 1024;
const MAX_DIRECTORY_TREE_CLUSTERS: usize = 2_000_000;
const MAX_UPCASE_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Absolute source offset of the file primary entry.
    pub source_offset: u64,
    /// Exact 32-byte records used to construct this entry set.
    pub raw_entries: Vec<[u8; 32]>,
    pub name: String,
    #[serde(default)]
    pub deleted: bool,
    pub attributes: u16,
    pub first_cluster: u32,
    pub valid_data_length: u64,
    pub data_length: u64,
    pub no_fat_chain: bool,
    pub name_hash: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub path: Vec<String>,
    pub entry: DirectoryEntry,
}

/// A deleted exFAT file stream whose full contiguous cluster range was
/// validated as free in the current allocation bitmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedFileStream {
    first_cluster: u32,
    data_length: u64,
    valid_data_length: u64,
    cluster_size: u64,
}

#[derive(Clone, Debug)]
struct Bitmap {
    clusters: Vec<u32>,
    length: u64,
}

#[derive(Clone, Debug)]
struct Stream {
    name_length: usize,
    name_hash: u16,
    valid_data_length: u64,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
}

struct DirectoryTreeResults {
    visited_directories: HashSet<u32>,
    entries: Vec<TreeEntry>,
    estimated_bytes: usize,
}

struct PendingDirectory {
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    path: Vec<String>,
    depth: usize,
}

#[derive(Clone, Debug)]
pub struct Volume {
    offset: u64,
    size: u64,
    bytes_per_sector: u32,
    cluster_size: u64,
    cluster_count: u32,
    root_cluster: u32,
    fat_offset: u64,
    fat_length: u64,
    heap_offset: u64,
    number_of_fats: u8,
    active_fat: u8,
    upcase: Vec<u16>,
    bitmap: Bitmap,
}

impl Volume {
    /// Open an exFAT volume only when at least one checksum-valid boot copy
    /// exists and valid copies agree on their geometry.
    pub fn open(source: &dyn BlockSource, offset: u64, partition_size: u64) -> Result<Self> {
        if partition_size < 24 * 512
            || offset
                .checked_add(partition_size)
                .is_none_or(|end| end > source.len())
        {
            return Err("exFAT partition is outside the source image or too small.".into());
        }
        let mut sector_probe = [0; 512];
        source
            .read_exact_at(offset, &mut sector_probe)
            .map_err(|error| format!("Could not read exFAT boot sector: {error}"))?;
        let shift = *sector_probe
            .get(108)
            .ok_or("exFAT boot sector is truncated.")?;
        if !(9..=12).contains(&shift) {
            return Err("exFAT sector-size shift is invalid.".into());
        }
        let bytes_per_sector = 1u32 << shift;
        let partition_sectors = partition_size / u64::from(bytes_per_sector);
        if !partition_size.is_multiple_of(u64::from(bytes_per_sector)) || partition_sectors < 24 {
            return Err("exFAT partition size is not sector aligned.".into());
        }
        let region_size = usize::try_from(bytes_per_sector)
            .ok()
            .and_then(|size| size.checked_mul(12))
            .ok_or("exFAT boot-region size overflow.")?;
        let mut main_region = vec![0; region_size];
        source
            .read_exact_at(offset, &mut main_region)
            .map_err(|error| format!("Could not read the exFAT main boot region: {error}"))?;
        let backup_offset = offset
            .checked_add(12 * u64::from(bytes_per_sector))
            .ok_or("exFAT backup boot-region offset overflow.")?;
        let mut backup_region = vec![0; region_size];
        source
            .read_exact_at(backup_offset, &mut backup_region)
            .map_err(|error| format!("Could not read the exFAT backup boot region: {error}"))?;
        let main =
            partition::parse_exfat_boot_region(&main_region, bytes_per_sector, partition_sectors);
        let backup =
            partition::parse_exfat_boot_region(&backup_region, bytes_per_sector, partition_sectors);
        let (geometry, volume_flags) = match (main, backup) {
            (Some(main), Some(_backup)) if main == _backup => (
                main,
                u16::from_le_bytes([main_region[106], main_region[107]]),
            ),
            (Some(_), Some(_)) => return Err(
                "Valid exFAT main and backup boot regions disagree; directory analysis stopped."
                    .into(),
            ),
            (Some(main), None) => (
                main,
                u16::from_le_bytes([main_region[106], main_region[107]]),
            ),
            (None, Some(backup)) => (
                backup,
                u16::from_le_bytes([backup_region[106], backup_region[107]]),
            ),
            (None, None) => return Err("Neither exFAT boot region is valid.".into()),
        };
        if geometry.partition_offset != 0
            && geometry.partition_offset != offset / u64::from(bytes_per_sector)
        {
            return Err("exFAT partition offset does not match the selected image range.".into());
        }
        let cluster_size = u64::from(geometry.bytes_per_sector)
            .checked_mul(geometry.sectors_per_cluster)
            .ok_or("exFAT cluster size overflow.")?;
        let volume_size = geometry
            .volume_length
            .checked_mul(u64::from(geometry.bytes_per_sector))
            .ok_or("exFAT volume size overflow.")?;
        if volume_size > partition_size {
            return Err("exFAT volume extends beyond the selected partition.".into());
        }
        let fat_offset = offset
            .checked_add(
                geometry
                    .fat_offset
                    .checked_mul(u64::from(geometry.bytes_per_sector))
                    .ok_or("exFAT FAT offset overflow.")?,
            )
            .ok_or("exFAT FAT offset overflow.")?;
        let fat_length = geometry
            .fat_length
            .checked_mul(u64::from(geometry.bytes_per_sector))
            .ok_or("exFAT FAT length overflow.")?;
        let heap_offset = offset
            .checked_add(
                geometry
                    .cluster_heap_offset
                    .checked_mul(u64::from(geometry.bytes_per_sector))
                    .ok_or("exFAT cluster-heap offset overflow.")?,
            )
            .ok_or("exFAT cluster-heap offset overflow.")?;
        let active_fat = (volume_flags & 1) as u8;
        let mut volume = Self {
            offset,
            size: volume_size,
            bytes_per_sector: geometry.bytes_per_sector,
            cluster_size,
            cluster_count: u32::try_from(geometry.cluster_count)
                .map_err(|_| "exFAT cluster count is too large.")?,
            root_cluster: geometry.root_cluster,
            fat_offset,
            fat_length,
            heap_offset,
            number_of_fats: geometry.number_of_fats,
            active_fat,
            upcase: Vec::new(),
            bitmap: Bitmap {
                clusters: Vec::new(),
                length: 0,
            },
        };
        let root_clusters = volume.walk_fat_chain(source, volume.root_cluster)?;
        let root_bytes = volume.read_clusters(source, &root_clusters, MAX_DIRECTORY_BYTES)?;
        let (bitmap_entries, upcase_entry) = volume.read_system_entries(&root_bytes)?;
        let bitmap_entry = bitmap_entries
            .into_iter()
            .find(|(flags, _, _)| *flags == active_fat)
            .ok_or("exFAT active allocation bitmap is missing.")?;
        let required_bitmap_bytes = u64::from(volume.cluster_count)
            .checked_add(7)
            .ok_or("exFAT allocation bitmap size overflow.")?
            / 8;
        if bitmap_entry.2 != required_bitmap_bytes {
            return Err("exFAT allocation bitmap length does not match the cluster heap.".into());
        }
        volume.bitmap = Bitmap {
            clusters: volume.walk_fat_chain(source, bitmap_entry.1)?,
            length: bitmap_entry.2,
        };
        if volume.bitmap.clusters.len() as u64 * volume.cluster_size < volume.bitmap.length {
            return Err(
                "exFAT allocation bitmap chain is shorter than its declared length.".into(),
            );
        }
        let (upcase_first_cluster, upcase_length, upcase_checksum) = upcase_entry;
        if upcase_length == 0 || upcase_length > MAX_UPCASE_BYTES {
            return Err("exFAT up-case table length is outside the supported bound.".into());
        }
        let upcase_clusters = volume.walk_fat_chain(source, upcase_first_cluster)?;
        let upcase_bytes = volume.read_file_bytes(source, &upcase_clusters, upcase_length)?;
        if checksum32(&upcase_bytes) != upcase_checksum {
            return Err("exFAT up-case table checksum is invalid.".into());
        }
        volume.upcase = decode_upcase_table(&upcase_bytes)?;
        for cluster in &volume.bitmap.clusters {
            if !volume.cluster_allocated(source, *cluster)? {
                return Err("exFAT allocation bitmap uses a cluster marked free.".into());
            }
        }
        for cluster in &upcase_clusters {
            if !volume.cluster_allocated(source, *cluster)? {
                return Err("exFAT up-case table uses a cluster marked free.".into());
            }
        }
        for cluster in root_clusters {
            if !volume.cluster_allocated(source, cluster)? {
                return Err(
                    "exFAT root directory uses a cluster marked free in its allocation bitmap."
                        .into(),
                );
            }
        }
        Ok(volume)
    }

    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    pub fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    pub fn bytes_per_sector(&self) -> u32 {
        self.bytes_per_sector
    }

    /// Validate a deleted file's contiguous allocation before any recovery
    /// reads. Chained deleted files are refused because their former FAT chain
    /// cannot be trusted after deletion.
    pub fn prepare_deleted_file(
        &self,
        source: &dyn BlockSource,
        entry: &DirectoryEntry,
    ) -> Result<DeletedFileStream> {
        let current_entry = self
            .read_tree_with_deleted(source)?
            .into_iter()
            .find(|tree_entry| tree_entry.entry.source_offset == entry.source_offset)
            .ok_or("Selected exFAT entry is no longer present in the source volume.")?;
        if current_entry.entry != *entry {
            return Err("Selected exFAT entry changed since it was inventoried.".into());
        }
        if !entry.deleted || entry.attributes & 0x10 != 0 || entry.data_length == 0 {
            return Err("Selected exFAT record is not a nonempty deleted file.".into());
        }
        if !entry.no_fat_chain {
            return Err(
                "Deleted exFAT file uses a cluster chain; its former allocation cannot be trusted."
                    .into(),
            );
        }
        if entry.valid_data_length > entry.data_length {
            return Err("Deleted exFAT valid-data length exceeds its file length.".into());
        }
        let clusters = entry
            .data_length
            .checked_add(self.cluster_size - 1)
            .ok_or("Deleted exFAT stream cluster count overflow.")?
            / self.cluster_size;
        if clusters == 0 || clusters > u64::from(self.cluster_count) {
            return Err("Deleted exFAT stream exceeds the cluster heap.".into());
        }
        let end = u64::from(entry.first_cluster)
            .checked_add(clusters - 1)
            .ok_or("Deleted exFAT contiguous stream range overflow.")?;
        if end > u64::from(self.cluster_count) + 1 {
            return Err("Deleted exFAT contiguous stream exceeds the cluster heap.".into());
        }
        for cluster in u64::from(entry.first_cluster)..=end {
            if self.cluster_allocated(source, cluster as u32)? {
                return Err(format!(
                    "Deleted exFAT cluster {cluster} is allocated; recovery stopped to avoid mixing live data."
                ));
            }
        }
        Ok(DeletedFileStream {
            first_cluster: entry.first_cluster,
            data_length: entry.data_length,
            valid_data_length: entry.valid_data_length,
            cluster_size: self.cluster_size,
        })
    }

    /// Read a bounded range from a previously validated deleted file stream.
    /// Bytes beyond ValidDataLength are returned as zero per exFAT semantics.
    pub fn read_deleted_file_range(
        &self,
        source: &dyn BlockSource,
        stream: &DeletedFileStream,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or("Deleted exFAT read range overflow.")?;
        if end > stream.data_length {
            return Err("Deleted exFAT read range exceeds the file length.".into());
        }
        output.fill(0);
        let initialized_end = end.min(stream.valid_data_length);
        if offset >= initialized_end {
            return Ok(());
        }
        let mut source_position = offset;
        let mut output_position = 0usize;
        let initialized_bytes = (initialized_end - offset) as usize;
        while output_position < initialized_bytes {
            let relative_cluster = source_position / stream.cluster_size;
            let within_cluster = source_position % stream.cluster_size;
            let cluster = u64::from(stream.first_cluster)
                .checked_add(relative_cluster)
                .ok_or("Deleted exFAT cluster number overflow.")?;
            let count = (initialized_bytes - output_position)
                .min((stream.cluster_size - within_cluster) as usize);
            let source_offset = self
                .cluster_offset(u32::try_from(cluster).map_err(|_| "Invalid exFAT cluster.")?)?
                .checked_add(within_cluster)
                .ok_or("Deleted exFAT source offset overflow.")?;
            source
                .read_exact_at(
                    source_offset,
                    &mut output[output_position..output_position + count],
                )
                .map_err(|error| format!("Could not read deleted exFAT file data: {error}"))?;
            source_position += count as u64;
            output_position += count;
        }
        Ok(())
    }

    pub fn read_tree(&self, source: &dyn BlockSource) -> Result<Vec<TreeEntry>> {
        self.read_tree_mode(source, false)
    }

    /// Inventory active entries and checksum-valid deleted file entry sets.
    /// Deleted directory contents are not traversed because an inactive
    /// directory entry cannot establish that its cluster chain is intact.
    pub fn read_tree_with_deleted(&self, source: &dyn BlockSource) -> Result<Vec<TreeEntry>> {
        self.read_tree_mode(source, true)
    }

    fn read_tree_mode(
        &self,
        source: &dyn BlockSource,
        include_deleted: bool,
    ) -> Result<Vec<TreeEntry>> {
        let mut results = DirectoryTreeResults {
            visited_directories: HashSet::new(),
            entries: Vec::new(),
            estimated_bytes: 0,
        };
        self.read_directory_tree(
            source,
            self.walk_fat_chain(source, self.root_cluster)?,
            Vec::new(),
            0,
            include_deleted,
            &mut results,
        )?;
        Ok(results.entries)
    }

    fn active_fat_offset(&self) -> Result<u64> {
        let per_fat_bytes = self.fat_length;
        self.fat_offset
            .checked_add(
                per_fat_bytes
                    .checked_mul(u64::from(self.active_fat))
                    .ok_or("exFAT active FAT offset overflow.")?,
            )
            .ok_or_else(|| "exFAT active FAT offset overflow.".into())
    }

    fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if !(2..=self.cluster_count + 1).contains(&cluster) {
            return Err("exFAT cluster number is outside the cluster heap.".into());
        }
        let offset = self
            .heap_offset
            .checked_add(
                u64::from(cluster - 2)
                    .checked_mul(self.cluster_size)
                    .ok_or("exFAT cluster offset overflow.")?,
            )
            .ok_or("exFAT cluster offset overflow.")?;
        let end = offset
            .checked_add(self.cluster_size)
            .ok_or("exFAT cluster end overflow.")?;
        if end > self.offset + self.size {
            return Err("exFAT cluster extends beyond the volume.".into());
        }
        Ok(offset)
    }

    fn next_cluster(&self, source: &dyn BlockSource, cluster: u32) -> Result<Option<u32>> {
        let relative = u64::from(cluster)
            .checked_mul(4)
            .ok_or("exFAT FAT entry offset overflow.")?;
        if relative
            .checked_add(4)
            .is_none_or(|end| end > self.fat_length)
        {
            return Err("exFAT FAT entry is outside the active table.".into());
        }
        let mut raw = [0; 4];
        source
            .read_exact_at(self.active_fat_offset()? + relative, &mut raw)
            .map_err(|error| format!("Could not read exFAT FAT entry: {error}"))?;
        let next = u32::from_le_bytes(raw);
        match next {
            0 => Err("exFAT cluster chain enters a free cluster.".into()),
            1 | FAT_RESERVED_START..=FAT_RESERVED_END => {
                Err("exFAT cluster chain contains a reserved value.".into())
            }
            FAT_BAD => Err("exFAT cluster chain contains a bad-cluster marker.".into()),
            FAT_EOC..=u32::MAX => Ok(None),
            value if (2..=self.cluster_count + 1).contains(&value) => Ok(Some(value)),
            _ => Err("exFAT cluster chain points outside the cluster heap.".into()),
        }
    }

    fn walk_fat_chain(&self, source: &dyn BlockSource, first: u32) -> Result<Vec<u32>> {
        self.cluster_offset(first)?;
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = first;
        loop {
            if chain.len() >= MAX_CHAIN_CLUSTERS || !visited.insert(current) {
                return Err(
                    "exFAT cluster chain contains a cycle or exceeds its safety bound.".into(),
                );
            }
            self.cluster_offset(current)?;
            chain.push(current);
            match self.next_cluster(source, current)? {
                Some(next) => current = next,
                None => return Ok(chain),
            }
        }
    }

    fn read_clusters(
        &self,
        source: &dyn BlockSource,
        clusters: &[u32],
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let total = (clusters.len() as u64)
            .checked_mul(self.cluster_size)
            .ok_or("exFAT directory size overflow.")?;
        if total > maximum as u64 {
            return Err("exFAT directory exceeds the supported byte limit.".into());
        }
        let mut bytes = vec![0; total as usize];
        for (index, cluster) in clusters.iter().enumerate() {
            let start = index * self.cluster_size as usize;
            source
                .read_exact_at(
                    self.cluster_offset(*cluster)?,
                    &mut bytes[start..start + self.cluster_size as usize],
                )
                .map_err(|error| format!("Could not read exFAT directory cluster: {error}"))?;
        }
        Ok(bytes)
    }

    fn read_file_bytes(
        &self,
        source: &dyn BlockSource,
        clusters: &[u32],
        length: u64,
    ) -> Result<Vec<u8>> {
        let capacity = (clusters.len() as u64)
            .checked_mul(self.cluster_size)
            .ok_or("exFAT system-file size overflow.")?;
        if length > capacity || length > MAX_UPCASE_BYTES {
            return Err(
                "exFAT system file is shorter than its declared length or too large.".into(),
            );
        }
        let mut result = vec![0; length as usize];
        let mut copied = 0usize;
        for cluster in clusters {
            if copied == result.len() {
                break;
            }
            let count = (result.len() - copied).min(self.cluster_size as usize);
            source
                .read_exact_at(
                    self.cluster_offset(*cluster)?,
                    &mut result[copied..copied + count],
                )
                .map_err(|error| format!("Could not read exFAT system file: {error}"))?;
            copied += count;
        }
        if copied != result.len() {
            return Err("exFAT system file chain is incomplete.".into());
        }
        Ok(result)
    }

    fn read_system_entries(&self, root: &[u8]) -> Result<(Vec<BitmapEntry>, UpcaseEntry)> {
        let records = directory_records(root)?;
        let mut bitmaps = Vec::new();
        let mut upcase = None;
        let mut index = 0usize;
        while index < records.len() {
            let record = records[index];
            let kind = record[0];
            match kind {
                0x81 => {
                    if record[2..20].iter().any(|byte| *byte != 0) {
                        return Err(
                            "exFAT allocation bitmap entry has nonzero reserved fields.".into()
                        );
                    }
                    let flags = record[1];
                    let cluster = u32_at(&record, 20)?;
                    let length = u64_at(&record, 24)?;
                    if flags >= self.number_of_fats
                        || bitmaps.iter().any(|(existing, _, _)| *existing == flags)
                    {
                        return Err(
                            "exFAT allocation bitmap flags are invalid or duplicated.".into()
                        );
                    }
                    bitmaps.push((flags, cluster, length));
                    index += 1;
                }
                0x82 => {
                    if upcase.is_some()
                        || record[1] != 0
                        || record[2..4].iter().any(|byte| *byte != 0)
                        || record[8..20].iter().any(|byte| *byte != 0)
                    {
                        return Err("exFAT up-case table entry is duplicated or invalid.".into());
                    }
                    upcase = Some((
                        u32_at(&record, 20)?,
                        u64_at(&record, 24)?,
                        u32_at(&record, 4)?,
                    ));
                    index += 1;
                }
                0x85 => {
                    let count = usize::from(record[1]);
                    let end = index
                        .checked_add(count + 1)
                        .ok_or("exFAT root entry-set index overflow.")?;
                    if end > records.len() {
                        return Err("exFAT root file entry set is truncated.".into());
                    }
                    if entry_set_checksum(&records[index..end])
                        != u16::from_le_bytes([record[2], record[3]])
                    {
                        return Err("exFAT root file entry-set checksum is invalid.".into());
                    }
                    index = end;
                }
                0x83 => {
                    index += 1;
                }
                entry_type if entry_type & 0x80 == 0 => index += 1,
                entry_type if entry_type & 0x20 != 0 => index += 1,
                _ => return Err("exFAT root contains an unknown critical system entry.".into()),
            }
        }
        if bitmaps.len() != usize::from(self.number_of_fats) {
            return Err(
                "exFAT root does not contain the required allocation bitmap entries.".into(),
            );
        }
        Ok((
            bitmaps,
            upcase.ok_or("exFAT root does not contain an up-case table entry.")?,
        ))
    }

    fn bitmap_byte(&self, source: &dyn BlockSource, position: u64) -> Result<u8> {
        if position >= self.bitmap.length {
            return Err("exFAT allocation bitmap read is out of bounds.".into());
        }
        let cluster_index = usize::try_from(position / self.cluster_size)
            .map_err(|_| "exFAT bitmap cluster index is too large.")?;
        let cluster = *self
            .bitmap
            .clusters
            .get(cluster_index)
            .ok_or("exFAT allocation bitmap chain is shorter than its declared size.")?;
        let within = position % self.cluster_size;
        let mut byte = [0];
        source
            .read_exact_at(self.cluster_offset(cluster)? + within, &mut byte)
            .map_err(|error| format!("Could not read exFAT allocation bitmap: {error}"))?;
        Ok(byte[0])
    }

    fn cluster_allocated(&self, source: &dyn BlockSource, cluster: u32) -> Result<bool> {
        self.cluster_offset(cluster)?;
        let bit = u64::from(cluster - 2);
        Ok(self.bitmap_byte(source, bit / 8)? & (1 << (bit % 8)) != 0)
    }

    fn read_directory_tree(
        &self,
        source: &dyn BlockSource,
        clusters: Vec<u32>,
        parent_path: Vec<String>,
        depth: usize,
        include_deleted: bool,
        results: &mut DirectoryTreeResults,
    ) -> Result<()> {
        if depth > MAX_DIRECTORY_DEPTH {
            return Err("exFAT directory tree exceeds the depth safety limit.".into());
        }
        if results
            .visited_directories
            .len()
            .checked_add(clusters.len())
            .is_none_or(|count| count > MAX_DIRECTORY_TREE_CLUSTERS)
        {
            return Err(
                "exFAT directory tree exceeds the 2,000,000-cluster memory safety limit.".into(),
            );
        }
        for cluster in &clusters {
            if !self.cluster_allocated(source, *cluster)? {
                return Err("exFAT directory chain references a cluster marked free.".into());
            }
            if !results.visited_directories.insert(*cluster) {
                return Err("exFAT directory tree contains a cycle or cross-link.".into());
            }
        }
        let directory = self.read_clusters(source, &clusters, MAX_DIRECTORY_BYTES)?;
        let entries =
            self.parse_file_entries(source, &directory, &clusters, depth == 0, include_deleted)?;
        let mut child_directories: Vec<PendingDirectory> = Vec::new();
        for entry in entries {
            if results.entries.len() >= MAX_DIRECTORY_ENTRIES {
                return Err("exFAT directory tree exceeds the entry safety limit.".into());
            }
            let mut path = parent_path.clone();
            path.push(entry.name.clone());
            let is_directory = entry.attributes & 0x10 != 0;
            let mut entry_memory = tree_entry_dynamic_memory(&path, &entry)?;
            if is_directory && !entry.deleted {
                entry_memory = entry_memory
                    .checked_add(path_memory(&path)?)
                    .and_then(|memory| memory.checked_add(std::mem::size_of::<PendingDirectory>()))
                    .ok_or("exFAT directory tree memory estimate overflow.")?;
            }
            let total_memory = results
                .estimated_bytes
                .checked_add(entry_memory)
                .ok_or("exFAT directory tree memory estimate overflow.")?;
            if total_memory > MAX_DIRECTORY_TREE_MEMORY {
                return Err(
                    "exFAT directory tree exceeds the 256 MiB result memory safety limit.".into(),
                );
            }
            results.estimated_bytes = total_memory;
            if results.entries.len() == results.entries.capacity() {
                results
                    .entries
                    .try_reserve_exact(1024)
                    .map_err(|_| "Could not allocate bounded exFAT directory results.")?;
            }
            let mut allocated_memory = results
                .estimated_bytes
                .checked_add(
                    results
                        .entries
                        .capacity()
                        .checked_mul(std::mem::size_of::<TreeEntry>())
                        .ok_or("exFAT directory tree memory estimate overflow.")?,
                )
                .ok_or("exFAT directory tree memory estimate overflow.")?;
            if is_directory && entry.data_length != 0 {
                if child_directories.len() == child_directories.capacity() {
                    child_directories.try_reserve_exact(64).map_err(|_| {
                        "Could not allocate bounded exFAT directory traversal state."
                    })?;
                }
                allocated_memory = allocated_memory
                    .checked_add(
                        child_directories
                            .capacity()
                            .checked_mul(std::mem::size_of::<PendingDirectory>())
                            .ok_or("exFAT directory tree memory estimate overflow.")?,
                    )
                    .ok_or("exFAT directory tree memory estimate overflow.")?;
            }
            if allocated_memory > MAX_DIRECTORY_TREE_MEMORY {
                return Err(
                    "exFAT directory tree exceeds the 256 MiB result memory safety limit.".into(),
                );
            }
            results.entries.push(TreeEntry {
                path: path.clone(),
                entry: entry.clone(),
            });
            if is_directory && !entry.deleted {
                if entry.data_length == 0 {
                    continue;
                }
                if entry.data_length > 256 * 1024 * 1024
                    || !entry.data_length.is_multiple_of(self.cluster_size)
                {
                    return Err("exFAT directory entry has invalid allocation metadata.".into());
                }
                child_directories.push(PendingDirectory {
                    first_cluster: entry.first_cluster,
                    data_length: entry.data_length,
                    no_fat_chain: entry.no_fat_chain,
                    path: path.clone(),
                    depth: depth + 1,
                });
            }
        }
        drop(directory);
        drop(clusters);
        for child in child_directories {
            let children = self.stream_clusters(
                source,
                child.first_cluster,
                child.data_length,
                child.no_fat_chain,
            )?;
            if children.len() as u64 * self.cluster_size != child.data_length {
                return Err(
                    "exFAT directory allocation length does not match its cluster chain.".into(),
                );
            }
            self.read_directory_tree(
                source,
                children,
                child.path,
                child.depth,
                include_deleted,
                results,
            )?;
        }
        Ok(())
    }

    fn parse_file_entries(
        &self,
        source: &dyn BlockSource,
        bytes: &[u8],
        directory_clusters: &[u32],
        is_root: bool,
        include_deleted: bool,
    ) -> Result<Vec<DirectoryEntry>> {
        let records = directory_records(bytes)?;
        let mut entries = Vec::new();
        let mut parsed_memory = 0usize;
        let mut index = 0usize;
        while index < records.len() {
            let primary = &records[index];
            let deleted = primary[0] == 0x05;
            if primary[0] & 0x80 == 0 && !(include_deleted && deleted) {
                index += 1;
                continue;
            }
            if !deleted && primary[0] != 0x85 {
                if is_root && matches!(primary[0], 0x81..=0x83) {
                    index += 1;
                    continue;
                }
                if primary[0] & 0x20 != 0 {
                    index += 1;
                    continue;
                }
                if primary[0] & 0x40 != 0 {
                    return Err(
                        "exFAT directory contains an orphaned critical secondary entry.".into(),
                    );
                }
                return Err("exFAT directory contains an unknown critical primary entry.".into());
            }
            let secondary_count = usize::from(primary[1]);
            let end = index
                .checked_add(secondary_count + 1)
                .ok_or("exFAT directory entry-set index overflow.")?;
            if end > records.len() {
                return Err("exFAT file entry set is truncated.".into());
            }
            let set = &records[index..end];
            if set.iter().any(|record| (record[0] & 0x80 == 0) != deleted) {
                return Err("exFAT file entry set has inconsistent in-use flags.".into());
            }
            let checksum = if deleted {
                deleted_entry_set_checksum(set)
            } else {
                entry_set_checksum(set)
            };
            if checksum != u16::from_le_bytes([primary[2], primary[3]]) {
                return Err("exFAT file entry-set checksum is invalid.".into());
            }
            if secondary_count < 2 || set[1][0] & 0x7f != 0x40 {
                return Err("exFAT file entry set is missing its stream extension.".into());
            }
            let stream_entry = &set[1];
            let flags = stream_entry[1];
            if flags & 1 == 0 || flags & !3 != 0 {
                if deleted && flags & 1 == 0 {
                    index = end;
                    continue;
                }
                return Err("exFAT stream extension allocation flags are invalid.".into());
            }
            if stream_entry[2] != 0
                || stream_entry[6..8].iter().any(|byte| *byte != 0)
                || stream_entry[16..20].iter().any(|byte| *byte != 0)
            {
                return Err("exFAT stream extension reserved fields are nonzero.".into());
            }
            let stream = Stream {
                name_length: usize::from(stream_entry[3]),
                name_hash: u16::from_le_bytes([stream_entry[4], stream_entry[5]]),
                valid_data_length: u64_at(stream_entry, 8)?,
                first_cluster: u32_at(stream_entry, 20)?,
                data_length: u64_at(stream_entry, 24)?,
                no_fat_chain: flags & 2 != 0,
            };
            if stream.name_length == 0 || stream.valid_data_length > stream.data_length {
                return Err("exFAT stream extension length metadata is invalid.".into());
            }
            if stream.data_length == 0 {
                if stream.first_cluster != 0 || stream.valid_data_length != 0 || stream.no_fat_chain
                {
                    return Err("Empty exFAT file has inconsistent allocation metadata.".into());
                }
            } else if !deleted {
                self.validate_stream_allocation(source, &stream)?;
            } else {
                self.cluster_offset(stream.first_cluster)?;
                let clusters = stream
                    .data_length
                    .checked_add(self.cluster_size - 1)
                    .ok_or("Deleted exFAT stream cluster count overflow.")?
                    / self.cluster_size;
                if clusters == 0 || clusters > u64::from(self.cluster_count) {
                    return Err("Deleted exFAT stream exceeds the cluster heap.".into());
                }
                if stream.no_fat_chain
                    && u64::from(stream.first_cluster)
                        .checked_add(clusters - 1)
                        .is_none_or(|last| last > u64::from(self.cluster_count) + 1)
                {
                    return Err(
                        "Deleted exFAT contiguous stream extends beyond the cluster heap.".into(),
                    );
                }
            }
            let name_entries = stream.name_length.div_ceil(15);
            if 1 + name_entries > secondary_count {
                return Err("exFAT file entry set has too few filename entries.".into());
            }
            let mut units = Vec::with_capacity(name_entries * 15);
            for name_index in 0..name_entries {
                let record = &set[2 + name_index];
                if record[0] & 0x7f != 0x41 || record[1] != 0 {
                    return Err("exFAT filename entries are missing or out of order.".into());
                }
                #[allow(clippy::chunks_exact_to_as_chunks)]
                for pair in record[2..32].chunks_exact(2) {
                    units.push(u16::from_le_bytes([pair[0], pair[1]]));
                }
            }
            units.truncate(stream.name_length);
            let name = String::from_utf16(&units)
                .map_err(|_| "exFAT filename contains invalid UTF-16.")?;
            if name.is_empty()
                || name.contains(['/', '\\', '\0'])
                || self.name_hash(&units) != stream.name_hash
            {
                return Err(
                    "exFAT filename is invalid or its up-case name hash does not match.".into(),
                );
            }
            for extra in &set[2 + name_entries..] {
                if extra[0] & 0x20 == 0 || (extra[0] & 0x80 == 0) != deleted {
                    return Err(
                        "exFAT file entry set contains an unknown critical secondary entry.".into(),
                    );
                }
            }
            let mut raw_entries = Vec::with_capacity(set.len());
            for record in set {
                raw_entries.push(*record);
            }
            let entry = DirectoryEntry {
                source_offset: self.directory_record_offset(directory_clusters, index * 32)?,
                raw_entries,
                name,
                deleted,
                attributes: u16::from_le_bytes([primary[4], primary[5]]),
                first_cluster: stream.first_cluster,
                valid_data_length: stream.valid_data_length,
                data_length: stream.data_length,
                no_fat_chain: stream.no_fat_chain,
                name_hash: stream.name_hash,
            };
            if entries.len() == entries.capacity() {
                entries
                    .try_reserve_exact(256)
                    .map_err(|_| "Could not allocate bounded exFAT directory entries.")?;
            }
            parsed_memory = parsed_memory
                .checked_add(directory_entry_dynamic_memory(&entry)?)
                .ok_or("exFAT parsed directory memory estimate overflow.")?;
            let allocated_memory = parsed_memory
                .checked_add(
                    entries
                        .capacity()
                        .checked_mul(std::mem::size_of::<DirectoryEntry>())
                        .ok_or("exFAT parsed directory memory estimate overflow.")?,
                )
                .ok_or("exFAT parsed directory memory estimate overflow.")?;
            if allocated_memory > MAX_PARSED_DIRECTORY_MEMORY {
                return Err(
                    "exFAT parsed directory exceeds the 128 MiB memory safety limit.".into(),
                );
            }
            entries.push(entry);
            index = end;
        }
        Ok(entries)
    }

    fn directory_record_offset(&self, clusters: &[u32], byte_offset: usize) -> Result<u64> {
        let cluster_size = usize::try_from(self.cluster_size)
            .map_err(|_| "exFAT cluster size is too large for this platform.")?;
        let cluster_index = byte_offset / cluster_size;
        let cluster = *clusters
            .get(cluster_index)
            .ok_or("exFAT directory record offset is outside its cluster chain.")?;
        self.cluster_offset(cluster)?
            .checked_add((byte_offset % cluster_size) as u64)
            .ok_or_else(|| "exFAT directory record offset overflow.".into())
    }

    fn validate_stream_allocation(&self, source: &dyn BlockSource, stream: &Stream) -> Result<()> {
        let required_clusters = stream
            .data_length
            .checked_add(self.cluster_size - 1)
            .ok_or("exFAT stream cluster count overflow.")?
            / self.cluster_size;
        if required_clusters == 0 || required_clusters > u64::from(self.cluster_count) {
            return Err("exFAT stream length exceeds the cluster heap.".into());
        }
        if stream.no_fat_chain {
            self.cluster_offset(stream.first_cluster)?;
            let end = u64::from(stream.first_cluster)
                .checked_add(required_clusters - 1)
                .ok_or("exFAT contiguous stream range overflow.")?;
            if end > u64::from(self.cluster_count) + 1 {
                return Err("exFAT contiguous stream extends beyond the cluster heap.".into());
            }
            for cluster in u64::from(stream.first_cluster)..=end {
                if !self.cluster_allocated(source, cluster as u32)? {
                    return Err(
                        "exFAT file stream uses a cluster marked free in its allocation bitmap."
                            .into(),
                    );
                }
            }
        } else {
            let clusters = self.walk_fat_chain(source, stream.first_cluster)?;
            if (clusters.len() as u64) < required_clusters {
                return Err(
                    "exFAT file cluster chain is shorter than its declared data length.".into(),
                );
            }
            for cluster in clusters {
                if !self.cluster_allocated(source, cluster)? {
                    return Err(
                        "exFAT file stream uses a cluster marked free in its allocation bitmap."
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn stream_clusters(
        &self,
        source: &dyn BlockSource,
        first_cluster: u32,
        data_length: u64,
        no_fat_chain: bool,
    ) -> Result<Vec<u32>> {
        let count = data_length
            .checked_add(self.cluster_size - 1)
            .ok_or("exFAT stream cluster count overflow.")?
            / self.cluster_size;
        if count == 0 {
            return Ok(Vec::new());
        }
        let clusters = if no_fat_chain {
            let end = u64::from(first_cluster)
                .checked_add(count - 1)
                .ok_or("exFAT contiguous stream range overflow.")?;
            if end > u64::from(self.cluster_count) + 1 {
                return Err("exFAT contiguous stream extends beyond the cluster heap.".into());
            }
            (u64::from(first_cluster)..=end)
                .map(|cluster| cluster as u32)
                .collect()
        } else {
            self.walk_fat_chain(source, first_cluster)?
        };
        if (clusters.len() as u64) < count {
            return Err("exFAT stream chain is shorter than its declared data length.".into());
        }
        for cluster in &clusters {
            if !self.cluster_allocated(source, *cluster)? {
                return Err(
                    "exFAT stream uses a cluster marked free in its allocation bitmap.".into(),
                );
            }
        }
        Ok(clusters)
    }

    fn name_hash(&self, units: &[u16]) -> u16 {
        let mut hash = 0u16;
        for unit in units {
            let upcased = self.upcase[usize::from(*unit)];
            for byte in upcased.to_le_bytes() {
                hash = hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        hash
    }
}

fn directory_entry_dynamic_memory(entry: &DirectoryEntry) -> Result<usize> {
    entry
        .name
        .capacity()
        .checked_add(
            entry
                .raw_entries
                .capacity()
                .checked_mul(std::mem::size_of::<[u8; 32]>())
                .ok_or("exFAT directory entry memory estimate overflow.")?,
        )
        .ok_or_else(|| "exFAT directory entry memory estimate overflow.".into())
}

fn path_memory(path: &[String]) -> Result<usize> {
    let slots = path
        .len()
        .checked_mul(std::mem::size_of::<String>())
        .ok_or("exFAT directory path memory estimate overflow.")?;
    path.iter().try_fold(slots, |total, component| {
        total
            .checked_add(component.capacity())
            .ok_or_else(|| "exFAT directory path memory estimate overflow.".into())
    })
}

fn tree_entry_dynamic_memory(path: &[String], entry: &DirectoryEntry) -> Result<usize> {
    let entry_memory = directory_entry_dynamic_memory(entry)?;
    path_memory(path)?
        .checked_add(std::mem::size_of::<DirectoryEntry>())
        .and_then(|total| total.checked_add(entry_memory))
        .ok_or_else(|| "exFAT directory tree memory estimate overflow.".into())
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn directory_records(bytes: &[u8]) -> Result<Vec<[u8; 32]>> {
    if !bytes.len().is_multiple_of(32) {
        return Err("exFAT directory has an invalid 32-byte record boundary.".into());
    }
    let mut records = Vec::new();
    for chunk in bytes.chunks_exact(32) {
        if chunk[0] == 0 {
            break;
        }
        records.push(
            chunk
                .try_into()
                .map_err(|_| "exFAT directory record size is invalid.")?,
        );
    }
    Ok(records)
}

fn entry_set_checksum(set: &[[u8; 32]]) -> u16 {
    let mut checksum = 0u16;
    for (record_index, record) in set.iter().enumerate() {
        for (byte_index, byte) in record.iter().enumerate() {
            if record_index == 0 && matches!(byte_index, 2 | 3) {
                continue;
            }
            checksum = checksum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
    }
    checksum
}

fn deleted_entry_set_checksum(set: &[[u8; 32]]) -> u16 {
    let mut checksum = 0u16;
    for (record_index, record) in set.iter().enumerate() {
        for (byte_index, byte) in record.iter().enumerate() {
            if record_index == 0 && matches!(byte_index, 2 | 3) {
                continue;
            }
            // Deletion clears InUse on disk without rewriting the checksum
            // saved for the original, active entry set.
            let value = if byte_index == 0 { *byte | 0x80 } else { *byte };
            checksum = checksum.rotate_right(1).wrapping_add(u16::from(value));
        }
    }
    checksum
}

fn checksum32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |checksum, byte| {
        checksum.rotate_right(1).wrapping_add(u32::from(*byte))
    })
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn decode_upcase_table(bytes: &[u8]) -> Result<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return Err("exFAT up-case table has an odd byte length.".into());
    }
    let raw_words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let table = if raw_words.len() == 65_536 && has_mandatory_ascii_mappings(&raw_words) {
        // In an uncompressed table, FFFFh at the final index is a literal
        // mapping. Treating it as a compression marker rejects valid media.
        raw_words
    } else {
        let mut words = raw_words.into_iter();
        let mut table = Vec::with_capacity(65_536);
        while table.len() < 65_536 {
            let value = words.next().ok_or("exFAT up-case table is incomplete.")?;
            if value != 0xffff {
                table.push(value);
                continue;
            }
            // The final Unicode mapping is itself U+FFFF in the recommended
            // table. At position FFFFh with no following run length, this is
            // the literal last mapping rather than a compression marker.
            if table.len() == 65_535 && words.len() == 0 {
                table.push(0xffff);
                break;
            }
            let count = usize::from(
                words
                    .next()
                    .ok_or("exFAT up-case identity run is truncated.")?,
            );
            if count == 0
                || table
                    .len()
                    .checked_add(count)
                    .is_none_or(|end| end > 65_536)
            {
                return Err("exFAT up-case identity run exceeds the table bounds.".into());
            }
            let start = table.len();
            table.extend((start..start + count).map(|unit| unit as u16));
        }
        if words.next().is_some() {
            return Err("exFAT up-case table has trailing data.".into());
        }
        table
    };
    if !has_mandatory_ascii_mappings(&table) {
        return Err("exFAT up-case table violates mandatory ASCII mappings.".into());
    }
    Ok(table)
}

fn has_mandatory_ascii_mappings(table: &[u16]) -> bool {
    table.len() >= 128
        && (0..128).all(|index| {
            let expected = if (0x61..=0x7a).contains(&index) {
                index - 0x20
            } else {
                index
            };
            table[index] == expected as u16
        })
}

fn u32_at(record: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        record
            .get(offset..offset + 4)
            .ok_or("exFAT directory field is truncated.")?
            .try_into()
            .map_err(|_| "exFAT directory field is truncated.")?,
    ))
}

fn u64_at(record: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        record
            .get(offset..offset + 8)
            .ok_or("exFAT directory field is truncated.")?
            .try_into()
            .map_err(|_| "exFAT directory field is truncated.")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
        sync::Mutex,
    };

    struct SliceSource(Vec<u8>);

    impl BlockSource for SliceSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            let start = usize::try_from(offset).map_err(std::io::Error::other)?;
            let end = start.checked_add(buffer.len()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "range overflow")
            })?;
            buffer.copy_from_slice(self.0.get(start..end).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short source")
            })?);
            Ok(())
        }
    }

    struct FileSource {
        file: Mutex<File>,
        size: u64,
    }

    impl FileSource {
        fn open(path: &std::path::Path) -> Self {
            let file = File::open(path).expect("open independent exFAT reference image");
            let size = file.metadata().expect("read fixture metadata").len();
            Self {
                file: Mutex::new(file),
                size,
            }
        }
    }

    impl BlockSource for FileSource {
        fn len(&self) -> u64 {
            self.size
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
            let mut file = self
                .file
                .lock()
                .map_err(|_| std::io::Error::other("fixture lock poisoned"))?;
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(buffer)
        }
    }

    fn write_boot_checksum(region: &mut [u8]) {
        let mut checksum = 0_u32;
        for (index, byte) in region[..512 * 11].iter().enumerate() {
            if matches!(index, 106 | 107 | 112) {
                continue;
            }
            checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
        }
        for word in region[512 * 11..512 * 12].chunks_mut(4) {
            word.copy_from_slice(&checksum.to_le_bytes());
        }
    }

    fn fixture() -> SliceSource {
        let sector = 512;
        let mut image = vec![0; 2048 * sector];
        for boot_start in [0, 12 * sector] {
            let region = &mut image[boot_start..boot_start + 12 * sector];
            region[..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
            region[3..11].copy_from_slice(b"EXFAT   ");
            region[72..80].copy_from_slice(&2048_u64.to_le_bytes());
            region[80..84].copy_from_slice(&24_u32.to_le_bytes());
            region[84..88].copy_from_slice(&16_u32.to_le_bytes());
            region[88..92].copy_from_slice(&40_u32.to_le_bytes());
            region[92..96].copy_from_slice(&2008_u32.to_le_bytes());
            region[96..100].copy_from_slice(&2_u32.to_le_bytes());
            region[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
            region[108] = 9;
            region[110] = 1;
            region[112] = 0xff;
            region[510..512].copy_from_slice(&[0x55, 0xaa]);
            for index in 1..=8 {
                let end = (index + 1) * sector;
                region[end - 4..end].copy_from_slice(&[0, 0, 0x55, 0xaa]);
            }
            write_boot_checksum(region);
        }
        let fat_start = 24 * sector;
        for cluster in 2..=4 {
            let at = fat_start + cluster * 4;
            image[at..at + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        }

        let heap_start = 40 * sector;
        let mut root = [0u8; 512];
        root[0] = 0x81;
        root[1] = 0;
        root[20..24].copy_from_slice(&4u32.to_le_bytes());
        root[24..32].copy_from_slice(&251u64.to_le_bytes());
        root[32] = 0x82;
        root[52..56].copy_from_slice(&3u32.to_le_bytes());

        let mut upcase = Vec::new();
        for unit in 0..97u16 {
            upcase.extend_from_slice(&unit.to_le_bytes());
        }
        for unit in b'A' as u16..=b'Z' as u16 {
            upcase.extend_from_slice(&unit.to_le_bytes());
        }
        upcase.extend_from_slice(&0xffffu16.to_le_bytes());
        upcase.extend_from_slice(&65_413u16.to_le_bytes());
        let upcase_checksum = checksum32(&upcase);
        root[36..40].copy_from_slice(&upcase_checksum.to_le_bytes());
        root[52..56].copy_from_slice(&3u32.to_le_bytes());
        root[56..64].copy_from_slice(&(upcase.len() as u64).to_le_bytes());

        let primary = &mut root[64..96];
        primary[0] = 0x85;
        primary[1] = 2;
        primary[4..6].copy_from_slice(&0x20u16.to_le_bytes());
        {
            let stream = &mut root[96..128];
            stream[0] = 0xc0;
            stream[1] = 1;
            stream[3] = 8;
        }
        {
            let filename = &mut root[128..160];
            filename[0] = 0xc1;
            for (index, unit) in "ROOT.TXT".encode_utf16().enumerate() {
                filename[2 + index * 2..4 + index * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        let name_units: Vec<u16> = "ROOT.TXT".encode_utf16().collect();
        let mut name_hash = 0u16;
        for unit in name_units {
            for byte in unit.to_le_bytes() {
                name_hash = name_hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        root[100..102].copy_from_slice(&name_hash.to_le_bytes());
        let set: Vec<[u8; 32]> = root[64..160]
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        let set_checksum = entry_set_checksum(&set);
        root[66..68].copy_from_slice(&set_checksum.to_le_bytes());

        image[heap_start..heap_start + 512].copy_from_slice(&root);
        image[heap_start + 512..heap_start + 512 + upcase.len()].copy_from_slice(&upcase);
        image[heap_start + 2 * 512] = 0b0000_0111;
        SliceSource(image)
    }

    fn test_file_set(
        name: &str,
        attributes: u16,
        first_cluster: u32,
        data_length: u64,
        no_fat_chain: bool,
    ) -> [[u8; 32]; 3] {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut records = [[0u8; 32]; 3];
        records[0][0] = 0x85;
        records[0][1] = 2;
        records[0][4..6].copy_from_slice(&attributes.to_le_bytes());
        records[1][0] = 0xc0;
        records[1][1] = 1 | if no_fat_chain { 2 } else { 0 };
        records[1][3] = units.len() as u8;
        records[1][8..16].copy_from_slice(&data_length.to_le_bytes());
        records[1][20..24].copy_from_slice(&first_cluster.to_le_bytes());
        records[1][24..32].copy_from_slice(&data_length.to_le_bytes());
        records[2][0] = 0xc1;
        let mut name_hash = 0u16;
        for (index, unit) in units.iter().enumerate() {
            records[2][2 + index * 2..4 + index * 2].copy_from_slice(&unit.to_le_bytes());
            let upper = if (b'a' as u16..=b'z' as u16).contains(unit) {
                unit - 0x20
            } else {
                *unit
            };
            for byte in upper.to_le_bytes() {
                name_hash = name_hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        records[1][4..6].copy_from_slice(&name_hash.to_le_bytes());
        let checksum = entry_set_checksum(&records);
        records[0][2..4].copy_from_slice(&checksum.to_le_bytes());
        records
    }

    #[test]
    fn expands_compressed_identity_ranges_to_full_upcase_table() {
        let mut bytes = Vec::new();
        for unit in 0..97_u16 {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        for unit in b'A' as u16..=b'Z' as u16 {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0xffff_u16.to_le_bytes());
        bytes.extend_from_slice(&65_413_u16.to_le_bytes());
        let table = decode_upcase_table(&bytes).unwrap();
        assert_eq!(table.len(), 65_536);
        assert_eq!(table[0], 0);
        assert_eq!(table[1], 1);
        assert_eq!(table[usize::from(b'a')], u16::from(b'A'));
        assert_eq!(table[65_535], 65_535);
    }

    #[test]
    fn accepts_uncompressed_upcase_table_with_literal_final_ffff_mapping() {
        let mut table: Vec<u16> = (0..=u16::MAX).collect();
        for unit in b'a' as usize..=b'z' as usize {
            table[unit] = unit as u16 - 0x20;
        }
        let bytes: Vec<u8> = table.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let decoded = decode_upcase_table(&bytes).unwrap();
        assert_eq!(decoded.len(), 65_536);
        assert_eq!(decoded[usize::from(b'a')], u16::from(b'A'));
        assert_eq!(decoded[65_535], 65_535);
    }

    #[test]
    fn rejects_malformed_compressed_upcase_tables() {
        assert!(decode_upcase_table(&[0xff, 0xff]).is_err());
        assert!(decode_upcase_table(&[0xff, 0xff, 0x00, 0x00]).is_err());
        assert!(decode_upcase_table(&[0x41]).is_err());
        let mut full = vec![0; 65_536 * 2];
        full.extend_from_slice(&[0, 0]);
        assert!(decode_upcase_table(&full).is_err());
    }

    #[test]
    fn verifies_file_entry_set_checksum_using_exfat_rotation() {
        let mut record = [0u8; 32];
        record[0] = 0x85;
        record[4..6].copy_from_slice(&0x20u16.to_le_bytes());
        let checksum = entry_set_checksum(std::slice::from_ref(&record));
        record[2..4].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(entry_set_checksum(std::slice::from_ref(&record)), checksum);
        record[9] ^= 1;
        assert_ne!(entry_set_checksum(std::slice::from_ref(&record)), checksum);
    }

    #[test]
    fn directory_records_stop_at_the_first_end_marker() {
        let mut bytes = vec![0; 96];
        bytes[0] = 0x81;
        bytes[32] = 0;
        bytes[64] = 0x82;
        let records = directory_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][0], 0x81);
    }

    #[test]
    fn opens_valid_volume_and_reads_live_root_entry() {
        let source = fixture();
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let tree = volume.read_tree(&source).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].path, ["ROOT.TXT"]);
        assert_eq!(tree[0].entry.source_offset, 40 * 512 + 64);
        assert_eq!(tree[0].entry.raw_entries.len(), 3);
    }

    #[test]
    fn reads_checksum_valid_deleted_exfat_file_entries_separately() {
        let mut source = fixture();
        let heap_start = 40 * 512;
        let mut deleted = test_file_set("DELETED.TXT", 0x20, 5, 512, true);
        for record in &mut deleted {
            record[0] &= 0x7f;
        }
        for (index, record) in deleted.iter().enumerate() {
            source.0[heap_start + 160 + index * 32..heap_start + 192 + index * 32]
                .copy_from_slice(record);
        }
        source.0[heap_start + 3 * 512..heap_start + 4 * 512].fill(0x5a);

        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let live = volume.read_tree(&source).unwrap();
        let with_deleted = volume.read_tree_with_deleted(&source).unwrap();

        assert_eq!(live.len(), 1);
        assert!(!live[0].entry.deleted);
        assert_eq!(with_deleted.len(), 2);
        assert_eq!(with_deleted[1].path, ["DELETED.TXT"]);
        assert!(with_deleted[1].entry.deleted);
        assert_eq!(with_deleted[1].entry.data_length, 512);
        assert!(with_deleted[1].entry.no_fat_chain);

        source.0[heap_start + 160 + 2 * 32 + 2] ^= 1;
        assert!(volume
            .read_tree_with_deleted(&source)
            .unwrap_err()
            .contains("entry-set checksum is invalid"));
    }

    #[test]
    fn reads_only_free_contiguous_deleted_exfat_data_and_zeroes_uninitialized_tail() {
        let mut source = fixture();
        let heap_start = 40 * 512;
        let mut deleted = test_file_set("RECOVER.BIN", 0x20, 5, 700, true);
        deleted[1][8..16].copy_from_slice(&600_u64.to_le_bytes());
        let checksum = entry_set_checksum(&deleted);
        deleted[0][2..4].copy_from_slice(&checksum.to_le_bytes());
        for record in &mut deleted {
            record[0] &= 0x7f;
        }
        for (index, record) in deleted.iter().enumerate() {
            source.0[heap_start + 160 + index * 32..heap_start + 192 + index * 32]
                .copy_from_slice(record);
        }
        source.0[heap_start + 3 * 512..heap_start + 4 * 512].fill(0x5a);
        source.0[heap_start + 4 * 512..heap_start + 5 * 512].fill(0x6b);

        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let entries = volume.read_tree_with_deleted(&source).unwrap();
        let entry = &entries[1].entry;
        let stream = volume.prepare_deleted_file(&source, entry).unwrap();
        let mut output = vec![0; 700];
        volume
            .read_deleted_file_range(&source, &stream, 0, &mut output)
            .unwrap();
        assert!(output[..512].iter().all(|byte| *byte == 0x5a));
        assert!(output[512..600].iter().all(|byte| *byte == 0x6b));
        assert!(output[600..].iter().all(|byte| *byte == 0));

        source.0[heap_start + 2 * 512] |= 1 << 3;
        assert!(volume
            .prepare_deleted_file(&source, entry)
            .unwrap_err()
            .contains("allocated"));
        source.0[heap_start + 2 * 512] &= !(1 << 3);
        let mut chained_entry = entry.clone();
        chained_entry.no_fat_chain = false;
        assert!(volume
            .prepare_deleted_file(&source, &chained_entry)
            .unwrap_err()
            .contains("changed since it was inventoried"));
    }

    #[test]
    fn legacy_exfat_snapshots_default_to_live_entries() {
        let entry: DirectoryEntry = serde_json::from_str(
            r#"{"source_offset":64,"raw_entries":[],"name":"ROOT.TXT","attributes":32,"first_cluster":0,"valid_data_length":0,"data_length":0,"no_fat_chain":false,"name_hash":4660}"#,
        )
        .unwrap();
        assert!(!entry.deleted);
    }

    #[test]
    fn traverses_nested_directories_after_releasing_parent_buffers() {
        let mut source = fixture();
        let heap_start = 40 * 512;
        let fat_start = 24 * 512;
        let directory = test_file_set("SUBDIR", 0x10, 5, 512, false);
        let child = test_file_set("CHILD.TXT", 0x20, 0, 0, false);
        for (index, record) in directory.iter().enumerate() {
            source.0[heap_start + 64 + index * 32..heap_start + 96 + index * 32]
                .copy_from_slice(record);
        }
        for (index, record) in child.iter().enumerate() {
            source.0[heap_start + 3 * 512 + index * 32..heap_start + 3 * 512 + 32 + index * 32]
                .copy_from_slice(record);
        }
        source.0[fat_start + 5 * 4..fat_start + 5 * 4 + 4]
            .copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        source.0[heap_start + 2 * 512] = 0b0000_1111;

        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let tree = volume.read_tree(&source).unwrap();

        let paths: Vec<Vec<String>> = tree.into_iter().map(|entry| entry.path).collect();
        assert_eq!(
            paths,
            [
                vec!["SUBDIR".to_owned()],
                vec!["SUBDIR".to_owned(), "CHILD.TXT".to_owned()]
            ]
        );
    }

    #[test]
    #[ignore = "requires the hash-pinned independent exFAT reference image"]
    fn reads_independent_exfat_reference_image_inventory() {
        let image_path = std::env::var_os("DAEMONCORE_EXFAT_REFERENCE_IMAGE")
            .expect("set DAEMONCORE_EXFAT_REFERENCE_IMAGE to fs.exfat.raw");
        let source = FileSource::open(std::path::Path::new(&image_path));
        let partition_offset = 2048 * 512;
        let volume =
            Volume::open(&source, partition_offset, source.len() - partition_offset).unwrap();
        let tree = volume.read_tree(&source).unwrap();
        let paths: HashSet<String> = tree.iter().map(|entry| entry.path.join("/")).collect();

        let expected_live_entries = [
            "audio1",
            "audio1/debian.mp3",
            "audio1/debian.ogg",
            "audio1/debian.wav",
            "movie1",
            "movie1/VID_20191220_170832.mp4",
            "pic1",
            "pic1/debian_logo.jpg",
            "pic1/debian_logo.png",
            "pic1/debian.png",
            "pic1/debian.ppm",
            "pic1/debian.xcf",
            "pic1/empty.jpg",
            "pic1/IMG_1054.JPG",
            "pic1/IMG-20191006-WA0002.jpg",
            "pic1/IMG_20200827_231612.jpg",
            "text1",
            "text1/a-text.docx",
            "text1/a-text.odt",
            "text1/a-text-pass-A5d.pdf",
            "text1/a-text-pass-peanuts.pdf",
            "text1/a-text.pdf",
        ];
        for expected in expected_live_entries {
            assert!(
                paths.contains(expected),
                "missing live exFAT entry {expected}"
            );
        }
        assert_eq!(paths.len(), expected_live_entries.len());
        assert!(paths.iter().all(|path| {
            !["audio2", "movie2", "pic2", "text2"]
                .iter()
                .any(|deleted_directory| {
                    path == deleted_directory || path.starts_with(&format!("{deleted_directory}/"))
                })
        }));

        let deleted_inventory = volume.read_tree_with_deleted(&source).unwrap();
        let deleted_paths: HashSet<String> = deleted_inventory
            .iter()
            .filter(|entry| entry.entry.deleted)
            .map(|entry| entry.path.join("/"))
            .collect();
        for expected_deleted in ["audio2", "movie2", "pic2", "text2"] {
            assert!(
                deleted_paths.contains(expected_deleted),
                "missing deleted exFAT metadata lead {expected_deleted}"
            );
        }
    }

    #[test]
    fn accepts_a_valid_empty_directory_without_a_cluster_allocation() {
        let mut source = fixture();
        let primary_offset = 40 * 512 + 64;
        source.0[primary_offset + 4..primary_offset + 6].copy_from_slice(&0x10u16.to_le_bytes());
        let set: Vec<[u8; 32]> = source.0[primary_offset..primary_offset + 96]
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        let checksum = entry_set_checksum(&set);
        source.0[primary_offset + 2..primary_offset + 4].copy_from_slice(&checksum.to_le_bytes());
        let volume = Volume::open(&source, 0, source.len()).unwrap();
        let tree = volume.read_tree(&source).unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].entry.attributes & 0x10, 0x10);
        assert_eq!(tree[0].entry.data_length, 0);
    }
}
