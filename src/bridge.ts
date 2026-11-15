import { invoke } from "@tauri-apps/api/core";
export interface Source {
  id: number;
  case_id: number;
  evidence_record_id: number;
  name: string;
  size: number;
  filesystem: string;
  sha256: string | null;
}
export interface Job {
  kind:
    | "hash"
    | "ntfs_scan"
    | "fat32_scan"
    | "exfat_scan"
    | "fat32_recovery_export"
    | "carving_scan"
    | "carving_export"
    | "recovery_export"
    | "evidence_reopen"
    | "case_report_export"
    | "disk_acquisition"
    | "raid_reconstruction";
  discovered: number;
  message: string | null;
  output_directory: string | null;
  state: string;
  processed: number;
  total: number;
  sha256: string | null;
  error: string | null;
}
export interface PhysicalDevice {
  number: number;
  size_bytes: number;
  bytes_per_sector: number;
  vendor: string | null;
  product: string | null;
  revision: string | null;
  serial_number: string | null;
  bus_type: number | null;
  identity_error: string | null;
}
export interface NtfsBoot {
  offset: number;
  sector_size: number;
  cluster_size: number;
  record_size: number;
  volume_size: number;
  mft_offset: number;
  serial: string;
}
export interface ScanSummary {
  scan_session_id: number;
  source_id: number;
  boot: NtfsBoot;
  records: number;
  skipped: number;
  found: number;
  limited: boolean;
  cancelled: boolean;
  source_sha256: string;
}
export interface CaseEvidenceRecord {
  id: number;
  case_id: number;
  path: string;
  name: string;
  size_bytes: number;
  filesystem: string;
  opened_at: string;
  sha256: string | null;
  status: "open" | "hashed" | "compromised";
}
export interface CaseScanSession {
  id: number;
  evidence_id: number;
  case_id: number;
  volume_offset: string;
  source_sha256: string;
  completed_at: string;
  records: number;
  skipped: number;
  found: number;
  limited: boolean;
}
export interface RecoveryCandidate {
  id: number;
  name: string;
  parent_record: number;
  parent_path: { record: number; name: string }[] | null;
  filename_references: {
    name: string;
    attribute_record: number;
    attribute_record_sequence: number;
    parent_record: number;
    parent_sequence: number;
    namespace: number;
    attribute_id: number;
  }[];
  size: number;
  deleted: boolean;
  storage: string;
  allocation: string;
  exportable: boolean;
  notes: string[];
  fingerprint: string;
  created_filetime: string | null;
  modified_filetime: string | null;
}
export interface RecoveryPage {
  total: number;
  rows: RecoveryCandidate[];
}
export interface Fat32TreeEntry {
  path: string[];
  entry: {
    source_offset: number;
    raw_record: number[];
    short_name: number[];
    long_name: string | null;
    deleted: boolean;
    attributes: number;
    first_cluster: number;
    size: number;
  };
}
export interface Fat32Page {
  total: number;
  rows: Fat32TreeEntry[];
}
export interface ExfatTreeEntry {
  path: string[];
  entry: {
    source_offset: number;
    raw_entries: number[][];
    name: string;
    deleted: boolean;
    attributes: number;
    first_cluster: number;
    valid_data_length: number;
    data_length: number;
    no_fat_chain: boolean;
    name_hash: number;
  };
}
export interface ExfatPage {
  total: number;
  rows: ExfatTreeEntry[];
}
export interface ExfatScanSummary {
  scan_session_id: number;
  source_id: number;
  source_sha256: string;
  volume_offset: string;
  entries: number;
}
export interface ExfatCaseScanSession {
  id: number;
  evidence_id: number;
  case_id: number;
  volume_offset: string;
  source_sha256: string;
  completed_at: string;
  records: number;
}
export interface Fat32ScanSummary {
  scan_session_id: number;
  source_id: number;
  volume_offset: string;
  source_sha256: string;
  entries: number;
  deleted_entries: number;
}
export interface Fat32CaseScanSession {
  id: number;
  evidence_id: number;
  case_id: number;
  volume_offset: string;
  source_sha256: string;
  completed_at: string;
  records: number;
  found: number;
  deleted: number;
}
export interface CarvedCandidate {
  id: number;
  offset: number;
  length: number;
  format: string;
  sha256: string;
  validation: string;
}
export interface CarvePage {
  scan_session_id: number;
  total: number;
  scanned_bytes: number;
  source_sha256: string;
  candidates_limited: boolean;
  rows: CarvedCandidate[];
}
export interface RecoveryExportVerification {
  package_type: string;
  case_id: number | null;
  evidence_record_id: number | null;
  scan_session_id: number | null;
  records: number;
  exported: number;
  failed: number;
  cancelled: boolean;
  state: "complete" | "partial";
  checksums_sha256: string;
}
export interface Case {
  id: number;
  title: string;
  examiner: string;
  integrity: "audit_matched" | "legacy_unverified";
}
export interface CaseReportExport {
  case_id: number;
  path: string;
  sha256: string;
  bytes: number;
  scans: number;
  candidates: number;
  fat32_scans: number;
  directory_entries: number;
  exfat_scans: number;
  exfat_entries: number;
  carve_scans: number;
  carved_candidates: number;
  imaging_and_raid_operations: number;
  recovery_operations: number;
}
export interface ActiveCaseState {
  case_id: number | null;
  audit_matched: boolean;
}
export interface Partition {
  index: number;
  type_id: string;
  unique_guid: string | null;
  start_lba: number;
  end_lba: number;
  size_bytes: number;
  bootable: boolean;
  filesystem_hint: string | null;
}
export interface PartitionReport {
  scheme: string;
  sector_size: number;
  primary_gpt_valid: boolean | null;
  backup_gpt_valid: boolean | null;
  partitions: Partition[];
  warnings: string[];
}
export interface AuditVerification {
  valid: boolean;
  records_checked: number;
  first_invalid_record: number | null;
  head_sha256: string;
  anchor_match: boolean | null;
}
export interface AuditCheckpoint {
  directory: string;
  records: number;
  head_sha256: string;
  checksums_sha256: string;
  anchor_status: string;
}
export interface AuditCheckpointVerification {
  records: number;
  head_sha256: string;
  anchor_match: boolean | null;
}
export const native = "__TAURI_INTERNALS__" in window;
export function command<T>(
  name: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (!native)
    return Promise.reject(
      new Error(
        "Open the Windows desktop application to access the native evidence engine.",
      ),
    );
  return invoke<T>(name, args);
}
