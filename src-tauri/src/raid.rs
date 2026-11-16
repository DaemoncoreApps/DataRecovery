use crate::{destination, storage::Image, Result};
use daemoncore_ntfs_core::storage::BlockSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};

const READ_CHUNK: usize = 1024 * 1024;
const MIN_MEMBERS: usize = 2;
const MAX_MEMBERS: usize = 32;
const MAX_STRIPE_BYTES: u64 = 16 * 1024 * 1024;
const INCOMPLETE_MARKER: &[u8] = b"UNPUBLISHED RAID RECONSTRUCTION: this staged image did not pass all reconstruction and package checks. Do not treat it as a verified image or package.\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaidLevel {
    Raid0,
    Raid1,
    Raid5,
    Raid6,
}

impl RaidLevel {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "raid0" => Ok(Self::Raid0),
            "raid1" => Ok(Self::Raid1),
            "raid5" => Ok(Self::Raid5),
            "raid6" => Ok(Self::Raid6),
            _ => Err(
                "Supported reconstruction levels are RAID 0, RAID 1, and full-member RAID 5/6."
                    .into(),
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Raid0 => "RAID 0",
            Self::Raid1 => "RAID 1",
            Self::Raid5 => "RAID 5",
            Self::Raid6 => "RAID 6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Raid5Layout {
    LeftAsymmetric,
    RightAsymmetric,
    LeftSymmetric,
    RightSymmetric,
}

impl Raid5Layout {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "left_asymmetric" => Ok(Self::LeftAsymmetric),
            "right_asymmetric" => Ok(Self::RightAsymmetric),
            "left_symmetric" => Ok(Self::LeftSymmetric),
            "right_symmetric" => Ok(Self::RightSymmetric),
            _ => Err("Select a supported RAID 5 rotating parity layout.".into()),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::LeftAsymmetric => "left_asymmetric",
            Self::RightAsymmetric => "right_asymmetric",
            Self::LeftSymmetric => "left_symmetric",
            Self::RightSymmetric => "right_symmetric",
        }
    }

    fn parity_member(self, stripe: u64, member_count: usize) -> Result<usize> {
        let rotation = usize::try_from(stripe % member_count as u64)
            .map_err(|_| "RAID 5 stripe index exceeds addressable memory")?;
        Ok(match self {
            Self::LeftAsymmetric | Self::LeftSymmetric => member_count - 1 - rotation,
            Self::RightAsymmetric | Self::RightSymmetric => rotation,
        })
    }

    fn data_member(self, parity_member: usize, data_position: usize, member_count: usize) -> usize {
        match self {
            Self::LeftAsymmetric | Self::RightAsymmetric => {
                if data_position < parity_member {
                    data_position
                } else {
                    data_position + 1
                }
            }
            Self::LeftSymmetric | Self::RightSymmetric => {
                (parity_member + 1 + data_position) % member_count
            }
        }
    }
}

// Linux MD rotates P right-to-left, places Q next to P, then starts data after Q.
fn raid6_left_symmetric_parity_members(stripe: u64, member_count: usize) -> Result<(usize, usize)> {
    let rotation = usize::try_from(stripe % member_count as u64)
        .map_err(|_| "RAID 6 stripe index exceeds addressable memory")?;
    let p = member_count - 1 - rotation;
    let q = (p + 1) % member_count;
    Ok((p, q))
}

fn raid6_left_symmetric_data_members(
    p: usize,
    q: usize,
    member_count: usize,
) -> impl Iterator<Item = usize> {
    (0..member_count)
        .map(move |position| (q + 1 + position) % member_count)
        .filter(move |member| *member != p && *member != q)
}

fn raid6_gf_multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x80 != 0;
        left <<= 1;
        if carry {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    product
}

fn raid6_q_tables(data_members: usize) -> Vec<[u8; 256]> {
    let mut coefficient = 1;
    let mut coefficients = Vec::with_capacity(data_members);
    for _ in 0..data_members {
        coefficients.push(coefficient);
        coefficient = raid6_gf_multiply(coefficient, 2);
    }
    // The Linux MD syndrome generator walks data from the final slot backward;
    // therefore the first logical slot carries the highest alpha coefficient.
    coefficients
        .into_iter()
        .rev()
        .map(|coefficient| std::array::from_fn(|value| raid6_gf_multiply(value as u8, coefficient)))
        .collect()
}

#[derive(Clone, Debug, Serialize)]
struct MemberManifest {
    order: usize,
    path: String,
    image_size_bytes: u64,
    image_sha256: String,
    data_offset_bytes: u64,
    data_size_bytes: u64,
}

#[derive(Serialize)]
struct RaidManifest {
    tool: &'static str,
    version: &'static str,
    package_type: &'static str,
    case_id: i64,
    created_unix_ns: String,
    level: &'static str,
    member_order_is_operator_supplied: bool,
    members: Vec<MemberManifest>,
    data_offset_bytes: u64,
    bytes_per_sector: u32,
    stripe_size_bytes: Option<u64>,
    raid5_layout: Option<&'static str>,
    raid6_layout: Option<&'static str>,
    reconstructed_size_bytes: u64,
    image_name: &'static str,
    image_sha256: String,
    layout_method: &'static str,
    limitations: &'static str,
}

#[derive(Serialize)]
struct Completion {
    state: &'static str,
    image_sha256: String,
    checksums_sha256: String,
}

pub struct RaidPackage {
    pub directory: PathBuf,
    pub image_path: PathBuf,
    pub image_sha256: String,
    pub size_bytes: u64,
    pub level: RaidLevel,
    pub raid5_layout: Option<Raid5Layout>,
    pub raid6_layout: Option<&'static str>,
    pub member_count: usize,
}

pub struct ReconstructionRequest<'a> {
    pub level_name: &'a str,
    pub member_paths: &'a [PathBuf],
    pub data_offset_bytes: u64,
    pub stripe_size_bytes: u64,
    pub raid5_layout: Raid5Layout,
    pub bytes_per_sector: u32,
    pub case_id: i64,
    pub destination: &'a Path,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RaidLayoutInput {
    stripe_size_bytes: u64,
    raid5_layout: String,
}

struct Staging(Option<PathBuf>);

impl Staging {
    fn discard(&mut self) -> Result<()> {
        if let Some(path) = self.0.as_ref() {
            fs::remove_dir_all(path).map_err(crate::err)?;
        }
        self.0 = None;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let image_path = path.join("image.raw");
            if image_path.is_file() {
                if let Ok(image) = File::open(&image_path) {
                    let _ = image.sync_all();
                }
                if let Ok(mut marker) = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join("INCOMPLETE.txt"))
                {
                    let _ = marker.write_all(INCOMPLETE_MARKER);
                    let _ = marker.sync_all();
                }
            } else {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn verify_incomplete_marker(path: &Path) -> std::io::Result<()> {
    let marker_path = path.join("INCOMPLETE.txt");
    let marker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker_path)?;
    marker.sync_all()?;
    drop(marker);
    let contents = fs::read(marker_path)?;
    if contents == INCOMPLETE_MARKER {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "marker contents do not match",
        ))
    }
}

fn failed_staging_message(error: &str, path: &Path) -> String {
    let marker_status = match verify_incomplete_marker(path) {
        Ok(()) => "The incomplete marker was flushed and read back.".to_owned(),
        Err(marker_error) => format!(
            "The incomplete marker could not be validated ({marker_error}); inspect the folder manually."
        ),
    };
    format!(
        "{error} Unpublished RAID reconstruction data may remain at {}. Treat it as unverified; the normal package verifier must pass before use. {marker_status}",
        path.display()
    )
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(crate::err)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(crate::err)?;
    file.sync_all().map_err(crate::err)
}

fn hash_file(path: &Path, mut progress: impl FnMut(u64)) -> Result<String> {
    let mut file = File::open(path).map_err(crate::err)?;
    let expected = file.metadata().map_err(crate::err)?.len();
    let mut read = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    loop {
        let count = file.read(&mut buffer).map_err(crate::err)?;
        if count == 0 {
            break;
        }
        read = read.checked_add(count as u64).ok_or("File size overflow")?;
        digest.update(&buffer[..count]);
        progress(count as u64);
    }
    if read != expected {
        return Err("A RAID package file changed during verification.".into());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_source(
    source: &Image,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<Option<String>> {
    let mut position = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK];
    while position < source.len() {
        if cancel.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let count = (source.len() - position).min(buffer.len() as u64) as usize;
        source
            .read_exact_at(position, &mut buffer[..count])
            .map_err(crate::err)?;
        digest.update(&buffer[..count]);
        position += count as u64;
        progress(count as u64);
    }
    source.verify_unchanged().map_err(crate::err)?;
    Ok(Some(format!("{:x}", digest.finalize())))
}

fn validate_geometry(
    level: RaidLevel,
    members: &[Image],
    offset: u64,
    stripe_bytes: u64,
    sector_bytes: u32,
) -> Result<(u64, u64)> {
    if !(MIN_MEMBERS..=MAX_MEMBERS).contains(&members.len()) {
        return Err(format!(
            "Select between {MIN_MEMBERS} and {MAX_MEMBERS} RAID member images."
        ));
    }
    if !matches!(sector_bytes, 512 | 4096) {
        return Err("Sector size must be 512 or 4096 bytes.".into());
    }
    if !offset.is_multiple_of(u64::from(sector_bytes)) {
        return Err("Data offset must align to the selected sector size.".into());
    }
    let first_length = members[0].len();
    if offset >= first_length {
        return Err("Data offset must be inside every member image.".into());
    }
    let data_size = first_length - offset;
    if !data_size.is_multiple_of(u64::from(sector_bytes))
        || members
            .iter()
            .any(|member| member.len().checked_sub(offset) != Some(data_size))
    {
        return Err(
            "All members must have equal sector-aligned data regions after the offset.".into(),
        );
    }
    match level {
        RaidLevel::Raid0 | RaidLevel::Raid5 | RaidLevel::Raid6 => {
            if level == RaidLevel::Raid5 && members.len() < 3 {
                return Err("RAID 5 requires at least three complete member images; degraded reconstruction is not supported.".into());
            }
            if level == RaidLevel::Raid6 && members.len() < 4 {
                return Err("RAID 6 requires at least four complete member images; degraded reconstruction is not supported.".into());
            }
            if !(512..=MAX_STRIPE_BYTES).contains(&stripe_bytes)
                || !stripe_bytes.is_power_of_two()
                || !stripe_bytes.is_multiple_of(u64::from(sector_bytes))
                || !data_size.is_multiple_of(stripe_bytes)
            {
                return Err("RAID 0/5/6 stripe size must be a 512-byte to 16-MiB power of two, aligned to the sector size, and divide each member data region evenly.".into());
            }
            let parity_members = match level {
                RaidLevel::Raid0 => 0,
                RaidLevel::Raid5 => 1,
                RaidLevel::Raid6 => 2,
                RaidLevel::Raid1 => return Err("RAID 1 does not use striped geometry.".into()),
            };
            let data_members = members.len() - parity_members;
            let output = data_size
                .checked_mul(data_members as u64)
                .ok_or("Reconstructed RAID size overflow")?;
            Ok((data_size, output))
        }
        RaidLevel::Raid1 => Ok((data_size, data_size)),
    }
}

pub fn reconstruct_package(
    request: ReconstructionRequest<'_>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<Option<RaidPackage>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(crate::err)?
        .as_nanos();
    let package_name = format!("DaemonCore-RAID-Reconstruction-{now}");
    let staging_path = request.destination.join(format!(".{package_name}.partial"));
    let final_path = request.destination.join(package_name);
    let result = reconstruct_package_into(
        request,
        cancel,
        &mut progress,
        now,
        &staging_path,
        &final_path,
    );
    match result {
        Err(error) if staging_path.exists() => Err(failed_staging_message(&error, &staging_path)),
        result => result,
    }
}

fn reconstruct_package_into(
    request: ReconstructionRequest<'_>,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(u64, u64),
    now: u128,
    staging_path: &Path,
    final_path: &Path,
) -> Result<Option<RaidPackage>> {
    let ReconstructionRequest {
        level_name,
        member_paths,
        data_offset_bytes,
        stripe_size_bytes,
        raid5_layout,
        bytes_per_sector,
        case_id,
        destination: _,
    } = request;
    let level = RaidLevel::parse(level_name)?;
    if !(MIN_MEMBERS..=MAX_MEMBERS).contains(&member_paths.len()) {
        return Err(format!(
            "Select between {MIN_MEMBERS} and {MAX_MEMBERS} RAID member images."
        ));
    }
    let mut canonical_paths = std::collections::BTreeSet::new();
    let mut members = Vec::with_capacity(member_paths.len());
    for path in member_paths {
        let canonical = path.canonicalize().map_err(crate::err)?;
        if !canonical_paths.insert(canonical.clone()) {
            return Err("The same RAID member image cannot be selected more than once.".into());
        }
        members.push(Image::open(&canonical).map_err(crate::err)?);
    }
    let (member_data_size, output_size) = validate_geometry(
        level,
        &members,
        data_offset_bytes,
        stripe_size_bytes,
        bytes_per_sector,
    )?;
    let member_bytes = members
        .iter()
        .try_fold(0u64, |sum, member| sum.checked_add(member.len()))
        .ok_or("RAID member size overflow")?;
    let total = member_bytes
        .checked_mul(2)
        .and_then(|sum| sum.checked_add(output_size.checked_mul(2)?))
        .and_then(|sum| match level {
            RaidLevel::Raid1 => {
                sum.checked_add(output_size.checked_mul(members.len().saturating_sub(1) as u64)?)
            }
            RaidLevel::Raid5 => sum.checked_add(member_data_size),
            RaidLevel::Raid6 => sum.checked_add(member_data_size.checked_mul(2)?),
            RaidLevel::Raid0 => Some(sum),
        })
        .ok_or("RAID operation progress size overflow")?;
    fs::create_dir(staging_path).map_err(crate::err)?;
    let mut staging = Staging(Some(staging_path.to_path_buf()));

    let mut processed = 0u64;
    progress(processed, total);
    let mut member_hashes = Vec::with_capacity(members.len());
    for member in &members {
        let digest = hash_source(member, cancel, |count| {
            processed = processed.saturating_add(count);
            progress(processed.min(total), total);
        })?;
        let Some(digest) = digest else {
            staging.discard()?;
            return Ok(None);
        };
        member_hashes.push(digest);
    }

    if level == RaidLevel::Raid1 {
        let mut buffer = vec![0; READ_CHUNK];
        let mut comparison = vec![0; READ_CHUNK];
        let mut position = 0u64;
        while position < member_data_size {
            if cancel.load(Ordering::SeqCst) {
                staging.discard()?;
                return Ok(None);
            }
            let count = (member_data_size - position).min(buffer.len() as u64) as usize;
            members[0]
                .read_exact_at(data_offset_bytes + position, &mut buffer[..count])
                .map_err(crate::err)?;
            for mirror in members.iter().skip(1) {
                mirror
                    .read_exact_at(data_offset_bytes + position, &mut comparison[..count])
                    .map_err(crate::err)?;
                if comparison[..count] != buffer[..count] {
                    return Err("RAID 1 member data differs. No mirror was chosen or reconstructed; inspect member offsets and identify the authoritative mirror.".into());
                }
            }
            processed = processed.saturating_add(
                (count as u64).saturating_mul(members.len().saturating_sub(1) as u64),
            );
            progress(processed.min(total), total);
            position += count as u64;
            processed = processed.saturating_add(count as u64);
            progress(processed.min(total), total);
        }
    }

    let image_path = staging_path.join("image.raw");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&image_path)
        .map_err(crate::err)?;
    let mut output_hash = Sha256::new();
    let mut buffer = vec![0; READ_CHUNK.min(stripe_size_bytes as usize).max(512)];
    match level {
        RaidLevel::Raid0 => {
            let stripe_count = member_data_size / stripe_size_bytes;
            for stripe in 0..stripe_count {
                for member in &members {
                    if cancel.load(Ordering::SeqCst) {
                        drop(output);
                        staging.discard()?;
                        return Ok(None);
                    }
                    let mut within = 0u64;
                    while within < stripe_size_bytes {
                        let count = (stripe_size_bytes - within).min(buffer.len() as u64) as usize;
                        let source_offset = data_offset_bytes + stripe * stripe_size_bytes + within;
                        member
                            .read_exact_at(source_offset, &mut buffer[..count])
                            .map_err(crate::err)?;
                        output.write_all(&buffer[..count]).map_err(crate::err)?;
                        output_hash.update(&buffer[..count]);
                        within += count as u64;
                        processed = processed.saturating_add(count as u64);
                        progress(processed.min(total), total);
                    }
                }
            }
        }
        RaidLevel::Raid1 => {
            let mut position = 0u64;
            while position < member_data_size {
                if cancel.load(Ordering::SeqCst) {
                    drop(output);
                    staging.discard()?;
                    return Ok(None);
                }
                let count = (member_data_size - position).min(buffer.len() as u64) as usize;
                members[0]
                    .read_exact_at(data_offset_bytes + position, &mut buffer[..count])
                    .map_err(crate::err)?;
                output.write_all(&buffer[..count]).map_err(crate::err)?;
                output_hash.update(&buffer[..count]);
                position += count as u64;
                processed = processed.saturating_add(count as u64);
                progress(processed.min(total), total);
            }
        }
        RaidLevel::Raid5 => {
            let stripe_count = member_data_size / stripe_size_bytes;
            let mut parity = vec![0; buffer.len()];
            let mut observed_parity = vec![0; buffer.len()];
            for stripe in 0..stripe_count {
                if cancel.load(Ordering::SeqCst) {
                    drop(output);
                    staging.discard()?;
                    return Ok(None);
                }
                let parity_member = raid5_layout.parity_member(stripe, members.len())?;
                let member_offset = data_offset_bytes + stripe * stripe_size_bytes;
                for within in (0..stripe_size_bytes).step_by(buffer.len()) {
                    if cancel.load(Ordering::SeqCst) {
                        drop(output);
                        staging.discard()?;
                        return Ok(None);
                    }
                    let count = (stripe_size_bytes - within).min(buffer.len() as u64) as usize;
                    parity[..count].fill(0);
                    for data_position in 0..members.len() - 1 {
                        let member_index =
                            raid5_layout.data_member(parity_member, data_position, members.len());
                        members[member_index]
                            .read_exact_at(member_offset + within, &mut buffer[..count])
                            .map_err(crate::err)?;
                        for (parity_byte, data_byte) in
                            parity[..count].iter_mut().zip(&buffer[..count])
                        {
                            *parity_byte ^= *data_byte;
                        }
                        output.write_all(&buffer[..count]).map_err(crate::err)?;
                        output_hash.update(&buffer[..count]);
                        processed = processed.saturating_add(count as u64);
                        progress(processed.min(total), total);
                    }
                    members[parity_member]
                        .read_exact_at(member_offset + within, &mut observed_parity[..count])
                        .map_err(crate::err)?;
                    if parity[..count] != observed_parity[..count] {
                        return Err(format!(
                            "RAID 5 XOR parity mismatch at stripe row {stripe}, byte offset {}. Verify member order, stripe size, and data offset; no package was published.",
                            member_offset + within
                        ));
                    }
                    processed = processed.saturating_add(count as u64);
                    progress(processed.min(total), total);
                }
            }
        }
        RaidLevel::Raid6 => {
            let stripe_count = member_data_size / stripe_size_bytes;
            let mut p_parity = vec![0; buffer.len()];
            let mut q_parity = vec![0; buffer.len()];
            let mut observed_p = vec![0; buffer.len()];
            let mut observed_q = vec![0; buffer.len()];
            let data_members = members.len() - 2;
            let q_tables = raid6_q_tables(data_members);
            for stripe in 0..stripe_count {
                if cancel.load(Ordering::SeqCst) {
                    drop(output);
                    staging.discard()?;
                    return Ok(None);
                }
                let (p_member, q_member) =
                    raid6_left_symmetric_parity_members(stripe, members.len())?;
                let member_offset = data_offset_bytes + stripe * stripe_size_bytes;
                for within in (0..stripe_size_bytes).step_by(buffer.len()) {
                    if cancel.load(Ordering::SeqCst) {
                        drop(output);
                        staging.discard()?;
                        return Ok(None);
                    }
                    let count = (stripe_size_bytes - within).min(buffer.len() as u64) as usize;
                    p_parity[..count].fill(0);
                    q_parity[..count].fill(0);
                    for (data_position, member_index) in
                        raid6_left_symmetric_data_members(p_member, q_member, members.len())
                            .enumerate()
                    {
                        members[member_index]
                            .read_exact_at(member_offset + within, &mut buffer[..count])
                            .map_err(crate::err)?;
                        for index in 0..count {
                            p_parity[index] ^= buffer[index];
                            q_parity[index] ^= q_tables[data_position][buffer[index] as usize];
                        }
                        output.write_all(&buffer[..count]).map_err(crate::err)?;
                        output_hash.update(&buffer[..count]);
                        processed = processed.saturating_add(count as u64);
                        progress(processed.min(total), total);
                    }
                    members[p_member]
                        .read_exact_at(member_offset + within, &mut observed_p[..count])
                        .map_err(crate::err)?;
                    members[q_member]
                        .read_exact_at(member_offset + within, &mut observed_q[..count])
                        .map_err(crate::err)?;
                    if p_parity[..count] != observed_p[..count]
                        || q_parity[..count] != observed_q[..count]
                    {
                        return Err(format!(
                            "RAID 6 P/Q parity mismatch at stripe row {stripe}, byte offset {}. Verify member order, stripe size, and data offset; no package was published.",
                            member_offset + within
                        ));
                    }
                    processed = processed.saturating_add((count as u64).saturating_mul(2));
                    progress(processed.min(total), total);
                }
            }
        }
    }
    output.sync_all().map_err(crate::err)?;
    drop(output);
    let observed_hash = format!("{:x}", output_hash.finalize());
    let verified_hash = hash_file(&image_path, |count| {
        processed = processed.saturating_add(count);
        progress(processed.min(total), total);
    })?;
    if observed_hash != verified_hash {
        return Err("Reconstructed image failed destination SHA-256 verification.".into());
    }

    for (member, expected_hash) in members.iter().zip(&member_hashes) {
        let current_hash = hash_source(member, cancel, |count| {
            processed = processed.saturating_add(count);
            progress(processed.min(total), total);
        })?;
        let Some(current_hash) = current_hash else {
            staging.discard()?;
            return Ok(None);
        };
        if current_hash != *expected_hash {
            return Err(
                "A RAID member changed during reconstruction. No output package was published."
                    .into(),
            );
        }
    }
    if cancel.load(Ordering::SeqCst) {
        staging.discard()?;
        return Ok(None);
    }

    let member_manifest = members
        .iter()
        .zip(&member_hashes)
        .enumerate()
        .map(|(order, (member, image_sha256))| MemberManifest {
            order,
            path: member.path.to_string_lossy().into_owned(),
            image_size_bytes: member.len(),
            image_sha256: image_sha256.clone(),
            data_offset_bytes,
            data_size_bytes: member_data_size,
        })
        .collect();
    let manifest = RaidManifest {
        tool: "DaemonCore Data Recovery",
        version: env!("CARGO_PKG_VERSION"),
        package_type: "raid_reconstruction",
        case_id,
        created_unix_ns: now.to_string(),
        level: level.label(),
        member_order_is_operator_supplied: true,
        members: member_manifest,
        data_offset_bytes,
        bytes_per_sector,
        stripe_size_bytes: matches!(level, RaidLevel::Raid0 | RaidLevel::Raid5 | RaidLevel::Raid6)
            .then_some(stripe_size_bytes),
        raid5_layout: (level == RaidLevel::Raid5).then_some(raid5_layout.id()),
        raid6_layout: (level == RaidLevel::Raid6).then_some("left_symmetric"),
        reconstructed_size_bytes: output_size,
        image_name: "image.raw",
        image_sha256: verified_hash.clone(),
        layout_method: match level {
            RaidLevel::Raid0 => "RAID 0 left-symmetric striping in operator-supplied member order",
            RaidLevel::Raid1 => "RAID 1 mirror copy after byte-for-byte agreement across all selected data regions",
            RaidLevel::Raid5 => match raid5_layout {
                Raid5Layout::LeftAsymmetric => "RAID 5 left-asymmetric rotating mapping; member hashes stable and XOR parity matches",
                Raid5Layout::RightAsymmetric => "RAID 5 right-asymmetric rotating mapping; member hashes stable and XOR parity matches",
                Raid5Layout::LeftSymmetric => "RAID 5 left-symmetric rotating mapping; member hashes stable and XOR parity matches",
                Raid5Layout::RightSymmetric => "RAID 5 right-symmetric rotating mapping; member hashes stable and XOR parity matches",
            },
            RaidLevel::Raid6 => "Linux MD RAID 6 left-symmetric P/Q; all complete member data and both parity syndromes verified",
        },
        limitations: "The operator supplied member order, data offset, sector size, stripe size, and parity layout. RAID 5 and RAID 6 require every member image and verify parity, but parity agreement does not prove the selected layout or logical data order is correct. RAID 6 supports only Linux MD left-symmetric rotating P/Q layout. Degraded or missing-member reconstruction is not supported. No on-disk RAID metadata was interpreted. Reconstructed bytes are not a hardware acquisition, do not establish which files were deleted, and are not validated against a vendor-specific array metadata format.",
    };
    write_json(&staging_path.join("manifest.json"), &manifest)?;
    let checksums = format!(
        "{}  image.raw\n{}  manifest.json\n",
        verified_hash,
        hash_file(&staging_path.join("manifest.json"), |_| {})?
    );
    let mut checksum_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging_path.join("checksums.sha256"))
        .map_err(crate::err)?;
    checksum_file
        .write_all(checksums.as_bytes())
        .map_err(crate::err)?;
    checksum_file.sync_all().map_err(crate::err)?;
    drop(checksum_file);
    write_json(
        &staging_path.join("completion.json"),
        &Completion {
            state: "complete",
            image_sha256: verified_hash.clone(),
            checksums_sha256: format!("{:x}", Sha256::digest(checksums.as_bytes())),
        },
    )?;
    destination::publish_new(staging_path, final_path).map_err(crate::err)?;
    staging.0 = None;
    Ok(Some(RaidPackage {
        directory: final_path.to_path_buf(),
        image_path: final_path.join("image.raw"),
        image_sha256: verified_hash,
        size_bytes: output_size,
        level,
        raid5_layout: (level == RaidLevel::Raid5).then_some(raid5_layout),
        raid6_layout: (level == RaidLevel::Raid6).then_some("left_symmetric"),
        member_count: members.len(),
    }))
}

#[tauri::command]
pub async fn pick_raid_members() -> Result<Vec<String>> {
    let files = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("Raw RAID member images", &["img", "dd", "raw", "bin"])
            .pick_files()
    })
    .await
    .map_err(crate::err)?;
    Ok(files
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect())
}

fn activate_reconstructed_image(
    state: &crate::AppState,
    case_id: i64,
    package: &RaidPackage,
) -> Result<()> {
    let image = Arc::new(Image::open(&package.image_path).map_err(crate::err)?);
    let mut prefix = vec![0; image.len().min(512) as usize];
    image.read_exact_at(0, &mut prefix).map_err(crate::err)?;
    let filesystem = crate::detect(&prefix);
    let source_id = state.generation.fetch_add(1, Ordering::SeqCst);
    let path = image.path.to_string_lossy().into_owned();
    let name = image
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let opened_at = crate::audit_timestamp(SystemTime::now())?;
    let mut db = state.db.lock().map_err(crate::err)?;
    if crate::require_audited_active_case(&db)? != case_id {
        return Err("The active case changed while RAID reconstruction was running.".into());
    }
    let evidence_record_id = crate::record_evidence_open(
        &mut db,
        &crate::EvidenceRegistration {
            case_id,
            source_id,
            path: &path,
            name: &name,
            size: package.size_bytes,
            filesystem: &filesystem,
            opened_at: &opened_at,
        },
    )?;
    let tx = db.transaction().map_err(crate::err)?;
    let updated = tx
        .execute(
            "UPDATE evidence_sources SET sha256=?1,status='hashed' WHERE id=?2 AND case_id=?3 AND status='open'",
            rusqlite::params![package.image_sha256, evidence_record_id, case_id],
        )
        .map_err(crate::err)?;
    if updated != 1 {
        return Err("Reconstructed image could not be registered as hashed evidence.".into());
    }
    crate::audit(
        &tx,
        "raid_reconstruction_image_registered",
        &serde_json::json!({
            "case_id":case_id,
            "evidence_record_id":evidence_record_id,
            "source_id":source_id,
            "level":package.level.label(),
            "members":package.member_count,
            "image_sha256":package.image_sha256,
            "size_bytes":package.size_bytes,
            "package_directory":package.directory,
        })
        .to_string(),
    )?;
    tx.commit().map_err(crate::err)?;
    drop(db);
    *state.source.lock().map_err(crate::err)? = Some(crate::Evidence {
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
    *state.scan.lock().map_err(crate::err)? = None;
    *state.carve_scan.lock().map_err(crate::err)? = None;
    *state.fat32_scan.lock().map_err(crate::err)? = None;
    Ok(())
}

#[tauri::command]
pub async fn reconstruct_raid(
    app: tauri::AppHandle,
    state: State<'_, crate::AppState>,
    member_paths: Vec<String>,
    level: String,
    data_offset_bytes: u64,
    layout: RaidLayoutInput,
    bytes_per_sector: u32,
) -> Result<bool> {
    let RaidLayoutInput {
        stripe_size_bytes,
        raid5_layout,
    } = layout;
    let level_value = RaidLevel::parse(&level)?;
    let raid5_layout = Raid5Layout::parse(&raid5_layout)?;
    if !(MIN_MEMBERS..=MAX_MEMBERS).contains(&member_paths.len()) {
        return Err(format!(
            "Select between {MIN_MEMBERS} and {MAX_MEMBERS} RAID member images."
        ));
    }
    let case_id = {
        let db = state.db.lock().map_err(crate::err)?;
        crate::require_audited_active_case(&db)?
    };
    let paths: Vec<PathBuf> = member_paths.iter().map(PathBuf::from).collect();
    let opened: Vec<Image> = paths
        .iter()
        .map(|path| Image::open(path).map_err(crate::err))
        .collect::<Result<_>>()?;
    let (member_data_size, output_size) = validate_geometry(
        level_value,
        &opened,
        data_offset_bytes,
        stripe_size_bytes,
        bytes_per_sector,
    )?;
    drop(opened);
    let destination = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Choose a RAID output folder on a different physical disk")
            .pick_folder()
    })
    .await
    .map_err(crate::err)?;
    let Some(destination) = destination else {
        return Ok(false);
    };
    let mut canonical_members = Vec::with_capacity(paths.len());
    let mut unique = std::collections::BTreeSet::new();
    for path in paths {
        let canonical = path.canonicalize().map_err(crate::err)?;
        if !unique.insert(canonical.clone()) {
            return Err("The same RAID member image cannot be selected more than once.".into());
        }
        destination::check_destination(&canonical, &destination, output_size)?;
        canonical_members.push(canonical);
    }
    let destination = destination.canonicalize().map_err(crate::err)?;
    let total = canonical_members
        .iter()
        .try_fold(0u64, |sum, path| {
            let size = fs::metadata(path).ok()?.len();
            sum.checked_add(size)
        })
        .and_then(|sum| sum.checked_mul(2))
        .and_then(|sum| sum.checked_add(output_size.checked_mul(2)?))
        .and_then(|sum| match level_value {
            RaidLevel::Raid1 => sum.checked_add(
                output_size.checked_mul(canonical_members.len().saturating_sub(1) as u64)?,
            ),
            RaidLevel::Raid5 => sum.checked_add(member_data_size),
            RaidLevel::Raid6 => sum.checked_add(member_data_size.checked_mul(2)?),
            RaidLevel::Raid0 => Some(sum),
        })
        .ok_or("RAID progress size overflow")?;
    {
        let mut job = state.job.lock().map_err(crate::err)?;
        if job.state == "running" {
            return Err(
                "Wait for or cancel the active operation before reconstructing RAID.".into(),
            );
        }
        let db = state.db.lock().map_err(crate::err)?;
        if crate::require_audited_active_case(&db)? != case_id {
            return Err("The active case changed before RAID reconstruction started.".into());
        }
        crate::audit(
            &db,
            "raid_reconstruction_started",
            &serde_json::json!({
                "case_id":case_id,
                "level":level_value.label(),
                "member_paths":canonical_members,
                "data_offset_bytes":data_offset_bytes,
                "stripe_size_bytes":if matches!(level_value, RaidLevel::Raid0 | RaidLevel::Raid5 | RaidLevel::Raid6) { Some(stripe_size_bytes) } else { None },
                "raid5_layout":if level_value == RaidLevel::Raid5 { Some(raid5_layout.id()) } else { None },
                "raid6_layout":if level_value == RaidLevel::Raid6 { Some("left_symmetric") } else { None },
                "bytes_per_sector":bytes_per_sector,
                "member_data_size_bytes":member_data_size,
                "reconstructed_size_bytes":output_size,
                "destination":destination,
                "member_order_is_operator_supplied":true,
            })
            .to_string(),
        )?;
        state.cancel.store(false, Ordering::SeqCst);
        *job = crate::Job {
            state: "running".into(),
            kind: "raid_reconstruction".into(),
            total,
            message: Some(format!(
                "Reconstructing {} from {} ordered members",
                level_value.label(),
                canonical_members.len()
            )),
            ..crate::Job::default()
        };
    }

    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<crate::AppState>();
        let outcome = reconstruct_package(
            ReconstructionRequest {
                level_name: &level,
                member_paths: &canonical_members,
                data_offset_bytes,
                stripe_size_bytes,
                raid5_layout,
                bytes_per_sector,
                case_id,
                destination: &destination,
            },
            &state.cancel,
            |processed, total| {
                if let Ok(mut job) = state.job.lock() {
                    job.processed = processed.min(total);
                    job.total = total;
                    job.message = Some(format!("Reconstructing and validating {} image", level_value.label()));
                }
            },
        );
        match outcome {
            Ok(Some(package)) => {
                let finalization = (|| -> Result<()> {
                    let db = state.db.lock().map_err(crate::err)?;
                    if crate::require_audited_active_case(&db)? != case_id {
                        return Err("The active case changed during RAID reconstruction. Preserve the output package and inspect the audit log.".into());
                    }
                    crate::audit(
                        &db,
                        "raid_reconstruction_published",
                        &serde_json::json!({
                            "case_id":case_id,
                            "level":package.level.label(),
                            "raid5_layout":package.raid5_layout.map(Raid5Layout::id),
                            "raid6_layout":package.raid6_layout,
                            "members":package.member_count,
                            "image_sha256":package.image_sha256,
                            "size_bytes":package.size_bytes,
                            "output_directory":package.directory,
                        })
                        .to_string(),
                    )
                })();
                let finalization = finalization.and_then(|()| activate_reconstructed_image(&state, case_id, &package));
                if let Ok(mut job) = state.job.lock() {
                    let completed = finalization.is_ok();
                    job.state = if completed { "completed" } else { "failed" }.into();
                    job.error = finalization.err();
                    job.message = Some(if completed {
                        "RAID image reconstructed, verified, and registered to the active case".into()
                    } else {
                        "The package was published, but case registration failed. Review the error and audit log before using it.".into()
                    });
                    job.output_directory = Some(package.directory.to_string_lossy().into_owned());
                    job.sha256 = Some(package.image_sha256);
                    job.processed = job.total;
                }
                Ok(true)
            }
            Ok(None) => {
                let audit_result = (|| -> Result<()> {
                    let db = state.db.lock().map_err(crate::err)?;
                    crate::audit(
                        &db,
                        "raid_reconstruction_cancelled",
                        &serde_json::json!({"case_id":case_id,"level":level_value.label()}).to_string(),
                    )
                })();
                if let Ok(mut job) = state.job.lock() {
                    job.state = if audit_result.is_ok() { "cancelled" } else { "failed" }.into();
                    job.error = audit_result.as_ref().err().cloned();
                    job.message = Some(if audit_result.is_ok() {
                        "RAID reconstruction cancelled; unpublished staging data removed".into()
                    } else {
                        "RAID reconstruction stopped, but cancellation could not be recorded in the audit log.".into()
                    });
                }
                audit_result.map(|()| false)
            }
            Err(error) => {
                let audit_result = (|| -> Result<()> {
                    let db = state.db.lock().map_err(crate::err)?;
                    crate::audit(
                        &db,
                        "raid_reconstruction_failed",
                        &serde_json::json!({"case_id":case_id,"level":level_value.label(),"error":error}).to_string(),
                    )
                })();
                let error = match audit_result {
                    Ok(()) => error,
                    Err(audit_error) => format!("{error}; failure was not recorded in the audit log: {audit_error}"),
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
            if let Ok(mut job) = state.job.lock() {
                job.state = "failed".into();
                job.error = Some(format!(
                    "RAID reconstruction worker stopped unexpectedly: {error}"
                ));
            }
            Err(format!(
                "RAID reconstruction worker stopped unexpectedly: {error}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!(".raid-test-{}-{id}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn write_member(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn failed_reconstruction_reports_when_incomplete_marker_cannot_be_validated() {
        let root = root();
        let staging_path = root.join("failed.partial");
        fs::create_dir(&staging_path).unwrap();
        fs::write(staging_path.join("image.raw"), b"partial image").unwrap();
        fs::create_dir(staging_path.join("INCOMPLETE.txt")).unwrap();

        let staging = Staging(Some(staging_path.clone()));
        drop(staging);
        assert!(staging_path.join("image.raw").exists());
        let message = failed_staging_message("Injected reconstruction error.", &staging_path);

        assert!(message.contains("Treat it as unverified"));
        assert!(message.contains("incomplete marker could not be validated"));
        assert!(message.contains(&staging_path.to_string_lossy().to_string()));
        assert!(verify_incomplete_marker(&staging_path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn raid5_members() -> [Vec<u8>; 3] {
        // Three stripe rows exercise a complete left-symmetric parity
        // rotation from member 2 through member 1 to member 0.
        let a = 0x12;
        let b = 0x24;
        let c = 0x48;
        let d = 0x81;
        let e = 0x96;
        let f = 0xa5;
        [
            [vec![a; 512], vec![d; 512], vec![e ^ f; 512]].concat(),
            [vec![b; 512], vec![c ^ d; 512], vec![e; 512]].concat(),
            [vec![a ^ b; 512], vec![c; 512], vec![f; 512]].concat(),
        ]
    }

    fn reference_gf_multiply(value: u8, coefficient: u8) -> u8 {
        let mut left = u16::from(value);
        let mut right = coefficient;
        let mut product = 0u16;
        while right != 0 {
            if right & 1 != 0 {
                product ^= left;
            }
            right >>= 1;
            left <<= 1;
            if left & 0x100 != 0 {
                left ^= 0x11d;
            }
        }
        product as u8
    }

    #[test]
    fn reconstructs_linux_md_raid6_left_symmetric_and_checks_both_syndromes() {
        let root = root();
        let q_tables = raid6_q_tables(2);
        assert_eq!(q_tables[0][1], 2);
        assert_eq!(q_tables[1][1], 1);
        let member_count = 5;
        let stripe_rows = 11;
        let mut member_bytes = vec![Vec::new(); member_count];
        let mut expected = Vec::new();

        for row in 0..stripe_rows {
            let p = member_count - 1 - row % member_count;
            let q = (p + 1) % member_count;
            let mut disk = (q + 1) % member_count;
            let mut data_members = Vec::new();
            while data_members.len() < member_count - 2 {
                if disk != p && disk != q {
                    data_members.push(disk);
                }
                disk = (disk + 1) % member_count;
            }
            let blocks: Vec<Vec<u8>> = (0..data_members.len())
                .map(|slot| {
                    (0..512)
                        .map(|offset| (row * 41 + slot * 67 + offset * 13 + 3) as u8)
                        .collect()
                })
                .collect();
            let mut p_block = vec![0; 512];
            let mut q_block = vec![0; 512];
            for (slot, block) in blocks.iter().enumerate() {
                let exponent = data_members.len() - 1 - slot;
                let coefficient = (0..exponent).fold(1, |value, _| reference_gf_multiply(value, 2));
                for index in 0..512 {
                    p_block[index] ^= block[index];
                    q_block[index] ^= reference_gf_multiply(block[index], coefficient);
                }
                expected.extend_from_slice(block);
                member_bytes[data_members[slot]].extend_from_slice(block);
            }
            member_bytes[p].extend_from_slice(&p_block);
            member_bytes[q].extend_from_slice(&q_block);
        }

        let paths: Vec<PathBuf> = (0..member_count)
            .map(|member| root.join(format!("member{member}.raw")))
            .collect();
        for (path, bytes) in paths.iter().zip(&member_bytes) {
            write_member(path, bytes);
        }
        let mut final_progress = (0, 0);
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid6",
                member_paths: &paths,
                data_offset_bytes: 0,
                stripe_size_bytes: 512,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |processed, total| final_progress = (processed, total),
        )
        .unwrap()
        .unwrap();

        assert_eq!(fs::read(&package.image_path).unwrap(), expected);
        assert_eq!(package.size_bytes, expected.len() as u64);
        assert_eq!(package.level, RaidLevel::Raid6);
        assert_eq!(package.raid6_layout, Some("left_symmetric"));
        assert_eq!(final_progress.0, final_progress.1);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(package.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["raid6_layout"], "left_symmetric");
        let verification = crate::recovery_verify::verify_package(&package.directory).unwrap();
        assert_eq!(verification.package_type, "raid_reconstruction");
        assert_eq!(verification.state, "complete");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_raid6_p_or_q_mismatch_and_retains_marked_staging() {
        let root = root();
        for corrupted_member in [0, 3] {
            let case_root = root.join(format!("corrupt-{corrupted_member}"));
            fs::create_dir(&case_root).unwrap();
            let member_count = 4;
            let mut member_bytes = vec![vec![0; 512]; member_count];
            // Row zero of Linux MD RAID 6 left-symmetric: P=3, Q=0, data=1,2.
            for index in 0..512 {
                let left = (index * 3 + 1) as u8;
                let right = (index * 7 + 2) as u8;
                member_bytes[1][index] = left;
                member_bytes[2][index] = right;
                member_bytes[3][index] = left ^ right;
                member_bytes[0][index] = reference_gf_multiply(left, 2) ^ right;
            }
            member_bytes[corrupted_member][0] ^= 1;
            let paths: Vec<PathBuf> = (0..member_count)
                .map(|member| case_root.join(format!("member{member}.raw")))
                .collect();
            for (path, bytes) in paths.iter().zip(&member_bytes) {
                write_member(path, bytes);
            }
            let outcome = reconstruct_package(
                ReconstructionRequest {
                    level_name: "raid6",
                    member_paths: &paths,
                    data_offset_bytes: 0,
                    stripe_size_bytes: 512,
                    raid5_layout: Raid5Layout::LeftSymmetric,
                    bytes_per_sector: 512,
                    case_id: 7,
                    destination: &case_root,
                },
                &AtomicBool::new(false),
                |_, _| {},
            );
            let error = match outcome {
                Err(error) => error,
                Ok(_) => panic!("corrupt P or Q parity must fail reconstruction"),
            };
            assert!(error.contains("P/Q parity mismatch"));
            let staging = fs::read_dir(&case_root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.extension().is_some_and(|ext| ext == "partial"))
                .unwrap();
            assert!(verify_incomplete_marker(&staging).is_ok());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconstructs_full_raid5_left_symmetric_layout_and_checks_parity() {
        let root = root();
        let members = raid5_members();
        let paths = [
            root.join("member0.raw"),
            root.join("member1.raw"),
            root.join("member2.raw"),
        ];
        for (path, bytes) in paths.iter().zip(&members) {
            write_member(path, bytes);
        }
        let data = [
            vec![0x12; 512],
            vec![0x24; 512],
            vec![0x48; 512],
            vec![0x81; 512],
            vec![0x96; 512],
            vec![0xa5; 512],
        ]
        .concat();
        let mut final_progress = (0, 0);
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid5",
                member_paths: &paths,
                data_offset_bytes: 0,
                stripe_size_bytes: 512,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |processed, total| final_progress = (processed, total),
        )
        .unwrap()
        .unwrap();

        assert_eq!(fs::read(&package.image_path).unwrap(), data);
        assert_eq!(package.size_bytes, 3072);
        assert_eq!(package.level, RaidLevel::Raid5);
        assert_eq!(final_progress.0, final_progress.1);
        let verification = crate::recovery_verify::verify_package(&package.directory).unwrap();
        assert_eq!(verification.package_type, "raid_reconstruction");
        assert_eq!(verification.records, 3);
        assert_eq!(verification.state, "complete");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconstructs_all_linux_md_raid5_rotating_layouts() {
        let root = root();
        let data = [[0x11, 0x22], [0x33, 0x44], [0x55, 0x66]];
        let cases = [
            (
                Raid5Layout::LeftAsymmetric,
                [2, 1, 0],
                [[0, 1], [0, 2], [1, 2]],
            ),
            (
                Raid5Layout::RightAsymmetric,
                [0, 1, 2],
                [[1, 2], [0, 2], [0, 1]],
            ),
            (
                Raid5Layout::LeftSymmetric,
                [2, 1, 0],
                [[0, 1], [2, 0], [1, 2]],
            ),
            (
                Raid5Layout::RightSymmetric,
                [0, 1, 2],
                [[1, 2], [2, 0], [0, 1]],
            ),
        ];

        for (layout, parity_members, data_order) in cases {
            let case_root = root.join(layout.id());
            fs::create_dir(&case_root).unwrap();
            let mut member_bytes: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
            for row in 0..3 {
                let data_bytes = data[row].map(|value| vec![value; 512]);
                let parity_byte = data[row][0] ^ data[row][1];
                for member in 0..3 {
                    let block = if member == parity_members[row] {
                        vec![parity_byte; 512]
                    } else {
                        let logical_index = data_order[row]
                            .iter()
                            .position(|candidate| *candidate == member)
                            .expect("each data member occurs once in the row");
                        data_bytes[logical_index].clone()
                    };
                    member_bytes[member].extend(block);
                }
            }
            let paths = [
                case_root.join("member0.raw"),
                case_root.join("member1.raw"),
                case_root.join("member2.raw"),
            ];
            for (path, bytes) in paths.iter().zip(&member_bytes) {
                write_member(path, bytes);
            }
            let package = reconstruct_package(
                ReconstructionRequest {
                    level_name: "raid5",
                    member_paths: &paths,
                    data_offset_bytes: 0,
                    stripe_size_bytes: 512,
                    raid5_layout: layout,
                    bytes_per_sector: 512,
                    case_id: 7,
                    destination: &case_root,
                },
                &AtomicBool::new(false),
                |_, _| {},
            )
            .unwrap()
            .unwrap();

            let expected = data
                .iter()
                .flat_map(|row| row.iter().flat_map(|value| vec![*value; 512]))
                .collect::<Vec<_>>();
            assert_eq!(
                fs::read(&package.image_path).unwrap(),
                expected,
                "{}",
                layout.id()
            );
            let manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(package.directory.join("manifest.json")).unwrap())
                    .unwrap();
            assert_eq!(manifest["raid5_layout"], layout.id());
            assert!(manifest["limitations"]
                .as_str()
                .unwrap()
                .contains("parity agreement does not prove the selected layout"));
            crate::recovery_verify::verify_package(&package.directory).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconstructs_raid5_across_supported_member_widths_and_parity_cycles() {
        let root = root();
        let layouts = [
            Raid5Layout::LeftAsymmetric,
            Raid5Layout::RightAsymmetric,
            Raid5Layout::LeftSymmetric,
            Raid5Layout::RightSymmetric,
        ];

        for member_count in [3, 4, 5, 8, MAX_MEMBERS] {
            for layout in layouts {
                let case_root = root.join(format!("{}-{member_count}", layout.id()));
                fs::create_dir(&case_root).unwrap();
                let stripe_rows = member_count * 2 + 1;
                let mut member_bytes = vec![Vec::new(); member_count];
                let mut expected = Vec::new();

                for row in 0..stripe_rows {
                    let parity_member = match layout {
                        Raid5Layout::LeftAsymmetric | Raid5Layout::LeftSymmetric => {
                            member_count - 1 - row % member_count
                        }
                        Raid5Layout::RightAsymmetric | Raid5Layout::RightSymmetric => {
                            row % member_count
                        }
                    };
                    let data_members: Vec<usize> = match layout {
                        Raid5Layout::LeftAsymmetric | Raid5Layout::RightAsymmetric => (0
                            ..member_count)
                            .filter(|member| *member != parity_member)
                            .collect(),
                        Raid5Layout::LeftSymmetric | Raid5Layout::RightSymmetric => (1
                            ..member_count)
                            .map(|position| (parity_member + position) % member_count)
                            .collect(),
                    };
                    let mut parity = vec![0u8; 512];

                    for (data_position, member_index) in data_members.iter().copied().enumerate() {
                        let block: Vec<u8> = (0..512)
                            .map(|offset| {
                                (member_count * 71 + row * 37 + data_position * 19 + offset * 11)
                                    as u8
                            })
                            .collect();
                        for (parity_byte, data_byte) in parity.iter_mut().zip(&block) {
                            *parity_byte ^= *data_byte;
                        }
                        expected.extend_from_slice(&block);
                        member_bytes[member_index].extend_from_slice(&block);
                    }
                    member_bytes[parity_member].extend_from_slice(&parity);
                }

                let paths: Vec<PathBuf> = (0..member_count)
                    .map(|member| case_root.join(format!("member{member}.raw")))
                    .collect();
                for (path, bytes) in paths.iter().zip(&member_bytes) {
                    write_member(path, bytes);
                }
                let package = reconstruct_package(
                    ReconstructionRequest {
                        level_name: "raid5",
                        member_paths: &paths,
                        data_offset_bytes: 0,
                        stripe_size_bytes: 512,
                        raid5_layout: layout,
                        bytes_per_sector: 512,
                        case_id: 7,
                        destination: &case_root,
                    },
                    &AtomicBool::new(false),
                    |_, _| {},
                )
                .unwrap()
                .unwrap();

                assert_eq!(fs::read(&package.image_path).unwrap(), expected);
                crate::recovery_verify::verify_package(&package.directory).unwrap();
            }
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires the independently generated Linux MD RAID 5 reference array"]
    fn reconstructs_independent_linux_md_raid5_reference_array() {
        let fixture = std::env::var_os("DAEMONCORE_RAID5_REFERENCE_DIR")
            .map(PathBuf::from)
            .expect("reference fixture directory is required");
        let member_paths =
            ["member0.raw", "member1.raw", "member2.raw"].map(|name| fixture.join(name));
        let expected = fs::read(fixture.join("logical-image.raw")).unwrap();
        assert_eq!(expected.len(), 16 * 1024 * 1024);
        assert_eq!(
            format!("{:x}", Sha256::digest(&expected)),
            "ae6018b38e30a433a0505035cf4df582da77c7ef92c269245232686e541e97c8"
        );
        assert_eq!(
            member_paths
                .iter()
                .map(|path| fs::metadata(path).unwrap().len())
                .collect::<Vec<_>>(),
            vec![8 * 1024 * 1024; 3]
        );

        let root = root();
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid5",
                member_paths: &member_paths,
                data_offset_bytes: 0,
                stripe_size_bytes: 64 * 1024,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap()
        .unwrap();

        assert_eq!(fs::read(&package.image_path).unwrap(), expected);
        assert_eq!(package.size_bytes, expected.len() as u64);
        let verification = crate::recovery_verify::verify_package(&package.directory).unwrap();
        assert_eq!(verification.package_type, "raid_reconstruction");
        assert_eq!(verification.state, "complete");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires the independently generated Linux MD RAID 6 reference array"]
    fn reconstructs_independent_linux_md_raid6_reference_array() {
        let fixture = std::env::var_os("DAEMONCORE_RAID6_REFERENCE_DIR")
            .map(PathBuf::from)
            .expect("reference fixture directory is required");
        let member_paths: Vec<PathBuf> = (0..4)
            .map(|index| fixture.join(format!("member{index}.raw")))
            .collect();
        let expected = fs::read(fixture.join("logical-image.raw")).unwrap();
        assert_eq!(expected.len(), 16 * 1024 * 1024);
        assert_eq!(
            format!("{:x}", Sha256::digest(&expected)),
            "ae6018b38e30a433a0505035cf4df582da77c7ef92c269245232686e541e97c8"
        );
        assert_eq!(
            member_paths
                .iter()
                .map(|path| fs::metadata(path).unwrap().len())
                .collect::<Vec<_>>(),
            vec![8 * 1024 * 1024; 4]
        );

        let root = root();
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid6",
                member_paths: &member_paths,
                data_offset_bytes: 0,
                stripe_size_bytes: 64 * 1024,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap()
        .unwrap();

        assert_eq!(fs::read(&package.image_path).unwrap(), expected);
        assert_eq!(package.size_bytes, expected.len() as u64);
        let verification = crate::recovery_verify::verify_package(&package.directory).unwrap();
        assert_eq!(verification.package_type, "raid_reconstruction");
        assert_eq!(verification.state, "complete");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_raid5_parity_mismatch_and_retains_marked_staging() {
        let root = root();
        let mut members = raid5_members();
        members[2][0] ^= 1;
        let paths = [
            root.join("member0.raw"),
            root.join("member1.raw"),
            root.join("member2.raw"),
        ];
        for (path, bytes) in paths.iter().zip(&members) {
            write_member(path, bytes);
        }
        let error = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid5",
                member_paths: &paths,
                data_offset_bytes: 0,
                stripe_size_bytes: 512,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .err()
        .expect("mismatched parity must not publish a RAID 5 image");

        assert!(error.contains("RAID 5 XOR parity mismatch at stripe row 0"));
        let partial = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir() && path.join("image.raw").exists())
            .expect("failed reconstruction staging remains available");
        assert!(error.contains(&partial.to_string_lossy().to_string()));
        assert!(fs::read_to_string(partial.join("INCOMPLETE.txt"))
            .unwrap()
            .contains("UNPUBLISHED RAID RECONSTRUCTION"));
        assert!(crate::recovery_verify::verify_package(&partial).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconstructs_raid0_using_operator_member_order_and_stripe_size() {
        let root = root();
        let a = root.join("a.raw");
        let b = root.join("b.raw");
        let mut a_bytes = vec![b'A'; 512];
        a_bytes.extend(vec![b'B'; 512]);
        let mut b_bytes = vec![b'1'; 512];
        b_bytes.extend(vec![b'2'; 512]);
        write_member(&a, &a_bytes);
        write_member(&b, &b_bytes);
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid0",
                member_paths: &[a, b],
                data_offset_bytes: 0,
                stripe_size_bytes: 512,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        );
        let package = package.unwrap().unwrap();
        let image = fs::read(&package.image_path).unwrap();
        assert_eq!(&image[..512], &vec![b'A'; 512]);
        assert_eq!(&image[512..1024], &vec![b'1'; 512]);
        assert_eq!(&image[1024..1536], &vec![b'B'; 512]);
        assert_eq!(&image[1536..], &vec![b'2'; 512]);
        assert_eq!(package.size_bytes, 2048);
        let verification = crate::recovery_verify::verify_package(&package.directory).unwrap();
        assert_eq!(verification.package_type, "raid_reconstruction");
        assert_eq!(verification.state, "complete");
        fs::write(package.image_path, vec![0; 2048]).unwrap();
        assert!(crate::recovery_verify::verify_package(&package.directory)
            .unwrap_err()
            .contains("image size or SHA-256"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconstructs_and_verifies_matching_raid1_mirrors() {
        let root = root();
        let a = root.join("a.raw");
        let b = root.join("b.raw");
        let data = vec![0x29; 512];
        write_member(&a, &data);
        write_member(&b, &data);
        let package = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid1",
                member_paths: &[a, b],
                data_offset_bytes: 0,
                stripe_size_bytes: 0,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap()
        .unwrap();
        assert_eq!(fs::read(&package.image_path).unwrap(), data);
        assert_eq!(
            crate::recovery_verify::verify_package(&package.directory)
                .unwrap()
                .package_type,
            "raid_reconstruction"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_mismatched_raid1_members_instead_of_selecting_a_mirror() {
        let root = root();
        let a = root.join("a.raw");
        let b = root.join("b.raw");
        write_member(&a, &vec![0x11; 512]);
        write_member(&b, &vec![0x22; 512]);
        let result = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid1",
                member_paths: &[a, b],
                data_offset_bytes: 0,
                stripe_size_bytes: 0,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(false),
            |_, _| {},
        );
        assert!(result.err().unwrap().contains("member data differs"));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancels_without_publishing_a_raid_package() {
        let root = root();
        let a = root.join("a.raw");
        let b = root.join("b.raw");
        write_member(&a, &vec![0x11; 512]);
        write_member(&b, &vec![0x11; 512]);
        let result = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid1",
                member_paths: &[a, b],
                data_offset_bytes: 0,
                stripe_size_bytes: 0,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &AtomicBool::new(true),
            |_, _| {},
        )
        .unwrap();
        assert!(result.is_none());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_after_output_begins_removes_raid_staging() {
        let root = root();
        let a = root.join("a.raw");
        let b = root.join("b.raw");
        let data = vec![0x11; 4096];
        write_member(&a, &data);
        write_member(&b, &data);
        let cancel = AtomicBool::new(false);
        let result = reconstruct_package(
            ReconstructionRequest {
                level_name: "raid1",
                member_paths: &[a, b],
                data_offset_bytes: 0,
                stripe_size_bytes: 0,
                raid5_layout: Raid5Layout::LeftSymmetric,
                bytes_per_sector: 512,
                case_id: 7,
                destination: &root,
            },
            &cancel,
            |processed, _| {
                if processed > 16_384 {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        )
        .unwrap();

        assert!(result.is_none());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
