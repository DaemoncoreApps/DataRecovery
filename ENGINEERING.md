# Current engineering plan

The visual foundation is established. The next work is ordered around actual
recovery correctness and complete user workflows.

## Architecture

`storage.rs` owns a locked evidence handle and independent-position bounded reads.
`SourceCursor` adapts that source for the partition parser without sharing offsets.
`ntfs.rs` validates image metadata and constructs recoverable unnamed streams.
`recovery.rs` stages and verifies outputs. `destination.rs` queries Windows volume
identity/capacity and publishes without replacement. `recovery_commands.rs` owns
scan/result/export commands, bounded job state, and source-bound result sessions.
React never supplies source paths or byte extents for extraction: it selects IDs
from a native scan. Windows pickers authorize source/destination paths.

## Current recovery increment

- Real MFT parsing and update-sequence validation, runlist reconstruction,
  deleted-file discovery, sparse/uninitialized bytes and allocation checks.
- Bounded resident and nonresident `$ATTRIBUTE_LIST` parsing for unnamed `$DATA`
  extents, including list continuation in referenced extension records; extension
  references are checked against MFT sequence numbers and base-record references,
  and VCN coverage must be contiguous. Limits are 256 extension records and 16 MiB
  of list data.
- Paged results with supported/blocked states and evidence notes.
- Safe selection, separate-physical-disk checks, no-overwrite outputs,
  streaming SHA-256 round-trip verification, cancellation and audit events.
- Mandatory full-image SHA-256 before scanning, full-source rechecks after scans,
  and full-source verification before and after extraction. Recovery manifests
  bind the source path, digest, volume geometry and selected MFT record fingerprints;
  checksum and completion files identify complete versus partial output folders.
- Verified audit checkpoints can be exported to a different physical disk. The
  checkpoint is unsigned and unanchored until an examiner preserves it in an
  independently controlled system. The desktop app can verify the package's
  checksums and event chain, but cannot establish authenticity without that anchor.
  Export exclusively creates a sibling staging directory, verifies the files
  from disk, then publishes the complete folder without replacing an existing
  destination. Cleanup only owns a staging directory after exclusive creation.
- Independent mkntfs/ntfs-3g fixture plus controlled deleted-file images.
- Actual native picker, scan, blocked selection, result filter and same-disk
  refusal exercised through the Windows app.

## Next acceptance gates

1. Add independently formatted attribute-list continuation/corruption fixtures,
   then add named-stream extraction and `$I30` index reconstruction.
2. Persist cases, source identities, scans, bookmarks, inventories and queues in
   SQLite; make long-running jobs safely restartable with source-bound checkpoints.
3. Implement validated FAT32/exFAT engines and export through the same protections.
4. Add format validation and carving, with bounded candidates and honest confidence.
5. Implement raw image acquisition and source/destination verification before
   integrating any physical disk helper.
6. Add tested RAID 0/1 read mappings and advanced hex inspection.
7. Complete reports, settings, accessibility and large-dataset performance.
8. Resolve Store/helper/MSIX policy, signing and packaged restricted-account tests.

CAPABILITIES.md is the current support matrix. Passing current tests does not make
unfinished modules operational or establish production readiness.

## Primary references checked

- https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
- https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
- https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry
- https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table
- https://learn.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumenameforvolumemountpointw
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilew
- https://github.com/ColinFinck/ntfs/tree/master/testdata
