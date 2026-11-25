# DaemonCore: Data Recovery

Windows image-analysis and NTFS metadata-recovery application built with React 19,
TypeScript, Vite, Tauri 2, Rust and SQLite. Production development is ongoing.
This build provides a working recovery path for supported NTFS image layouts;
it is not yet the complete recovery suite described in the product brief.

## Run and build

Requires Windows x64, Node.js 22+, Rust/MSVC, Visual Studio C++ Build Tools and
Microsoft WebView2.

```powershell
npm ci
npm run desktop
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
npm run tauri build -- --no-bundle
npm run tauri build
```

`npm run validate` runs the TypeScript/Vite build, Rust formatting check, offline
Rust test suite and Clippy with warnings denied as one repeatable local gate.
`npm run package:windows` runs that gate, then builds the standalone executable
and offline NSIS installer in a fresh isolated
`src-tauri/target/p<revision><unique build ID>` directory and writes a
`SHA256SUMS.txt` manifest. It requires a clean Git worktree and reports the full
source commit with the artifact hashes. A fresh directory keeps builds from
trying to replace an executable that may still be running while keeping Windows
linker paths short.
The build downloads Tauri-pinned NSIS tools and the WebView2 offline runtime, so
build-time internet access is required. It does not install, launch, or sign the
package and does not use GitHub Actions. Use
`npm run package:windows -- -SkipValidation` only after validation has already
passed for the exact source revision.
`npm run tauri build -- --no-bundle` produces the standalone executable;
`npm run tauri build` also produces the configured Windows NSIS installer with
the WebView2 runtime embedded for offline installation. The offline runtime
adds roughly 127 MB to the setup package; the latest package is about 289 MiB.
It is unsigned and is not a production release artifact.

`npm run dev` is a browser preview. Evidence operations require the native app.
No sample scan records are inserted into the application.

## Recover from a raw NTFS image

1. Open an IMG, DD, RAW or BIN working copy. The source is opened read only with
   Windows write/delete sharing denied. In **Device Explorer**, calculate its full
   SHA-256. The native recovery scan remains unavailable until this finishes.
2. Open **Recovery Workspace**. For a whole-disk image, use **Read partition table**
   and select the NTFS partition start. For a volume image, the byte offset is 0.
3. Start **Scan deleted records**. The native worker reads actual MFT structures,
   then rehashes the complete source. Results are retained only when the hash still
   matches. A mismatch invalidates the source digest and discards the scan.
4. Inspect the results. Resident data is distinguished from nonresident extents.
   Currently allocated/reused extents are blocked. Unallocated extents can still
   have been overwritten, discarded by TRIM, or corrupted; allocation state is not
   a guarantee of original content integrity. Unknown allocation is labeled.
5. Select supported candidates and choose a folder on a **different physical disk**.
   Windows volume disk extents are compared; unknown topology and shared physical
   disks are rejected. Available capacity is checked before starting.
6. Each export gets a new `DaemonCore-Recovery-*` folder. Files are staged as
   `.partial`, flushed, independently rehashed, and published without replacement.
   The source hash is checked before any output is created and again before
   completion. A mismatch prevents a completion
   marker. Cancellation removes the active partial file; already verified files
   remain. Review `manifest.json`, `inventory.jsonl`, `summary.json`, and
   `checksums.sha256`. `completion.json` binds the checksum-list digest and labels
   the package complete or partial. These files are not digitally signed or
   externally anchored. After a crash, a missing completion marker means incomplete.

Export verification establishes that destination bytes match the reconstructed
stream. It does not certify that the original file content survived intact.
Recovered executables and active document content are never launched or previewed.
The desktop app can re-open an export folder to verify every listed file hash,
the output inventory, and the complete/partial marker. Verification is recorded
in the local audit log. It establishes internal package consistency only; the
export is not digitally signed or externally anchored.

## Implemented

- Supplied original in-app branding and alien Windows icon, with premium native UI.
- Read-only, independent-position storage reads; hashing and hex inspection no
  longer share a mutable stream cursor. Source size/timestamp changes fail jobs;
  opening also fails if the filesystem cannot provide the timestamp used by that
  stability check. The held handle denies normal write, rename, and delete access.
- MBR/GPT analysis, CRCs, backup-table fallback, bounded EBR traversal and warnings.
- NTFS boot geometry, MFT update-sequence checks, bounded attributes, resident data,
  signed relative data runs, fragmented/sparse streams, filename/timestamp metadata,
  deleted records, alternate-stream detection, current-allocation checks, and bounded
  resident plus limited nonresident `$ATTRIBUTE_LIST` resolution for unnamed `$DATA`
  extents with sequence-checked extension records.
- Filtered, paginated recovery results, metadata inspection, bulk selection,
  background extraction, destination hash verification and cancellation.
- Transactional local case register and chained audit events, including scan,
  export, rejection and failure outcomes. Each new audit write verifies the
  existing chain and blocks evidence-changing operations when tampering is found.
  Internal chain verification is available; the log remains unsigned and has no
  external trust anchor. Recovery start/finish events bind the source path and
  digest to selected MFT record fingerprints, sizes, destination and outcome.
  SQLite is configured for FULL synchronous commits, and pre-epoch system clocks
  fail audit writes instead of producing misleading zero timestamps.
- Verified audit checkpoint export to a different physical disk includes JSONL
  events, a checkpoint head, checksums and a completion marker. It remains unsigned
  and externally unanchored; preserve the checkpoint independently to make it useful
  as an external reference.
- Checkpoint folders can be independently checked in the desktop app for package
  checksums, event order, chain links, event hashes, record IDs and checkpoint head.
  This proves internal consistency only; it does not establish who created the
  checkpoint or detect a complete rewrite without an independently preserved anchor.
  Verification bounds the event stream to 64 MiB and each metadata file to 1 MiB.
  Export preflights database text sizes and caps the exact JSONL serialization to
  that same event-stream limit, so it cannot create a checkpoint the verifier
  will refuse to read.
- Recovery export folders can be checked for the exact package contents, file hashes,
  inventory-to-manifest consistency, and complete/partial state. Results and failures
  are added to the local audit chain. Hashing large exports has no progress or cancel
  control yet; the verifier holds read-only file handles and no-delete-share directory
  handles (up to 4,096 directories) during verification, but cannot take an atomic
  filesystem snapshot. It does not provide an external signature or trust anchor.
- FAT32 examination can export selected deleted short-name entries only when their
  assumed contiguous cluster range remains free in the active or mirrored FAT copies.
  Recovery packages include the source and scan identity, raw directory-record digest,
  layout assumption, per-file result, destination hashes, checksums, and completion
  state. Overlap checks cover the selected entries only. FAT32 does not preserve a
  deleted file's former chain, so fragmented files can be reconstructed incorrectly;
  destination hash verification does not establish original-content integrity. Adjacent deleted LFN slots may expose an unverified, possibly partial name lead when their checksum can be tied to the short-name record; the lead is not used as the path or export filename.

## Current limits

Compressed/encrypted streams, named-stream export, automatic content validation and
scan resume are not implemented. Physical-device imaging can resume from a marked staging folder after validating its checkpoint and matching every committed byte against the selected source. Abrupt power-loss and forced-process termination are not yet qualified. Attribute-list resolution is limited to unnamed
`$DATA` extents with verified extension-record identity and contiguous VCN coverage.
Resident lists and bounded nonresident lists are supported, including list
continuations in referenced extension records, up to 256 extension records and 16
MiB. Nonresident list data must be fully initialized, uncompressed, non-sparse, and
have consistent allocation metadata. Inconsistent or ambiguous references fail
closed. Independently formatted continuation fixtures are still needed; this is not
complete NTFS attribute-list support. Directory-tree export is restored only when
each parent reference and MFT sequence number can be verified. Unverified or
overlong paths export flat with the decision recorded in package metadata.

Scans are capped at 1,000,000 MFT records and 10,000 candidates, with partial-scan
warnings. Runlists are capped at 4,096 runs, result pages at 200 entries, and exports
at 1,000 selected files. Large operations use bounded buffers and one active worker.
The selected case is persisted. Opened source images and completed scan
candidate snapshots are stored in the local case database and shown in Case
Management; recovery manifests and audit records carry the persistent evidence
and scan identifiers. Archived candidates can be paged and reviewed after restart;
they remain read-only snapshots and cannot be exported until the source is reopened
and a fresh scan is completed.

FAT32 live/deleted short-entry review and exFAT live-directory inventory are available
in limited scope. The exFAT inventory has been checked against one independent volume
fixture; broader volume compatibility and damaged-media behavior are not qualified.
General FAT32 allocation-history analysis, verified deleted-LFN recovery beyond the unverified name lead, and exFAT deleted-file
recovery remain pending. Physical-device acquisition and operator-configured RAID
0/1/full-member RAID 5 reconstruction are available in limited scope: member identity, layout, degraded-array
handling, and hardware qualification remain explicit release gates. PNG carving
validates chunk CRCs and decodes complete images; JPEG carving validates bounded
marker/scan structure and decodes pixels; BMP carving checks header, geometry,
and pixel-array bounds; GIF carving validates its block structure and decodes all
frames within explicit size and frame limits. All four formats can export selected
candidates to audited, checksummed packages; carving cannot infer original names,
deletion state, or allocation, and the recovery workspace can verify those packages'
inventories, output hashes, and completion markers. GIF is a Service Mark of
CompuServe Incorporated. PDF/Office formats and archive-time candidate review
remain pending. FAT32
deleted-file export is limited to a contiguous-cluster assumption and cannot establish
original-content integrity. Report generation is available as unsigned, unanchored
JSON v6 with case-linked evidence, scan, recovery, acquisition, RAID, and audit data;
PDF/HTML/CSV exports, signed or externally anchored reports, editable persistent settings,
advanced hex analysis, and Microsoft Store release remain pending. The current Tauri
Store route uses a signed EXE or MSI installer
linked from an unpackaged app listing; this project currently builds an unsigned
NSIS EXE and does not produce MSIX. Store signing, updater policy and submission
are not configured. See CAPABILITIES.md and ENGINEERING.md for release gates.

The application cannot provide hardware write protection. Use validated working
copies and a hardware write blocker where appropriate. Windows disk identities
reflect the OS-visible storage topology; they are not an attestation of underlying
virtualization, storage arrays, or physical isolation. Unsupported destinations
fail closed. No automatic forensic certification or legal admissibility is claimed.

SQLite is stored in per-user local application data (`com.daemoncore.datarecovery`).
Audit chains have no external trust anchor: rewriting the entire database is not
prevented. Evidence processing is local, with no telemetry or upload code.

## Validation and delivery

Synthetic NTFS fixtures cover deleted resident, fragmented, sparse, encrypted,
continued and reused extents. A separately formatted NTFS image from ColinFinck/ntfs
checks known resident/nonresident/sparse file contents; its license and origin are
included under `src-tauri/tests/fixtures`. A separate synthetic test covers a deleted
file split between a base and extension record, verifies the reconstructed output,
and rejects a stale extension base sequence. No fixture is loaded automatically.

See VERIFICATION.md for the exact checks performed and remaining validation gaps.
The production gate audit records which checks remain incomplete. A successful local
build or validation run does not qualify the Windows installer, establish forensic
fitness, or replace independent laboratory testing.
