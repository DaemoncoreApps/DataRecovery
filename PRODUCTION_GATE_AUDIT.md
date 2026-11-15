# Production acceptance audit

This audit maps the original product brief's 16 acceptance criteria to current
evidence. A partial result means the evidence proves only the stated scope; it
does not satisfy the full criterion. Release readiness requires every criterion
to be independently verified for the shipped package.

| # | Acceptance criterion | Status | Current evidence and remaining work |
|---:|---|---|---|
| 1 | Reliable launch on supported Windows | Partial | Earlier smoke builds launched, rendered the dashboard/logo, opened Evidence Vault, and verified 27 internally consistent records. The staged Tauri r50 executable also launched and rendered Dashboard and Reports; see `VERIFICATION.md`. No independent audit head was compared in that check. Installer lifecycle, clean-account/configuration, and broader startup tests remain open. |
| 2 | Supplied logo appears above the sidebar | Partial | The prior native smoke screenshot showed the supplied data recovery logo above navigation. Verify sizing, transparency, high-DPI scaling, and collapsed-sidebar behavior in the packaged app. |
| 3 | Accurate physical devices and supported images | Partial | Disk Imaging enumerates readable `PhysicalDrive` devices, queries geometry and Windows storage identity descriptors (vendor/product/revision/serial/bus), exposes those values in the UI, and offers acquisition-package verification. Geometry parsing now requires the complete 32-byte `DISK_GEOMETRY_EX` prefix, including all eight disk-size bytes; tests reject 31-byte responses, truncated length records, and inconsistent geometry. Acquisition reopens the selected device after destination selection and compares its complete reported descriptor and geometry with the exact row selected in the UI, rejecting replacement or changed devices before reading; regression tests cover changed serial and geometry. Windows media-changed, no-media, reinitialization-required, and disconnected-device errors now stop acquisition instead of being mapped as unreadable sectors; tests distinguish these from generic I/O device errors that can represent a localized bad sector. Devices that do not report identity remain labeled with the query limitation. Stable identity behavior without a device-reported serial, refresh UX during hot-plug, device-specific fixtures, and representative physical-device validation remain open. |
| 4 | Source evidence is not modified | Partial | Image access uses a read-only handle with write/delete sharing denied, checks image stability, and rehashes around operations. Physical acquisition opens the source with read access only and requires operator attestation to an offline source and validated hardware write blocker; synthetic acquisition tests cover complete, partial, and cancelled output. Physical write-blocker qualification, hostile/restricted-account tests, and hardware-level validation remain absent. |
| 5 | NTFS deleted-file recovery on verified images | Partial | Synthetic tests verify resident, fragmented, sparse, and independently formatted NTFS fixture contents and hashes. Two hosted Linux campaigns completed 1,000,000 `parse_record` inputs and about 485,000 whole-image scans each within their time limits without a reported crash; the latter covers resident, nonresident, and continued-attribute-list seed images validated through the application scan path. Run IDs and coverage details are in `VERIFICATION.md`. These bounded runs do not qualify sustained campaigns or independent-volume behavior; broader deleted-volume, damaged-volume, overwrite/TRIM, hard-link, compression, ADS, and scale coverage remains required. |
| 6 | Controlled FAT32 and exFAT recovery | Incomplete | FAT32 BPB geometry, FAT capacity, cluster bounds, and declared backup-sector consistency are checked. The core crate has a read-only volume mapper with mirrored-FAT consistency checks, fragmented range reads, cycle and bad-chain rejection, and bounded mapping. Its bounded directory-tree enumerator preserves raw records and offsets, validates live LFN sequences, detects cycles/cross-links, and can expose deleted short-name records. A deleted-file mapping is offered only for an expected contiguous run whose clusters all remain free; the API marks contiguity as an assumption, and this is not full allocation analysis. Deleted-LFN recovery is absent. Hosted run [41364446590](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41364446590) passed a bounded partition-image fuzz campaign that traverses a virtual FAT32 tree and attempts deleted-file mapping. The native app provides read-only FAT32 directory examination, source-bound snapshot/audit persistence, archived review, and limited deleted short-name export. The Linux-generated deleted FAT32 fixture was restored on Windows and passed end-to-end native deleted-file export and package verification on run 43666164749, matching the independently generated expected bytes. exFAT has bounded boot-copy, allocation-bitmap, up-case table, file entry-set, stream allocation, and live directory validation; independent image `fs.exfat.raw` now validates the expected 22 live paths and excludes the deleted `*2` directories. That fixture exposed and fixed an incorrect extended-boot signature and valid up-case table edge case; this proves one independently formatted volume inventory, not broad compatibility. The Filesystem Analysis UI performs a source rehash and audited persistence; Case Management provides archived review with audit-chain and snapshot verification; reports include exFAT snapshots. The partition-image fuzzer now constructs a valid minimal exFAT volume, mutates boot/FAT/root/bitmap/up-case structures, and invokes the volume tree walker; the expanded exFAT fuzz campaign also passed on run 43666164749. Deleted exFAT recovery, packaged archive UI test, damaged-media fuzzing, and additional independent volumes remain open. Partition parsing and GPT validation remain in the reusable core crate. The core FAT32 walker also passes against the published UVA CS 4414 testdisk1 image and separate expected-content dump. Historical fragmentation, deleted-LFN recovery, independent additional volumes, and controlled damaged-media behavior remain unverified. |
| 7 | Real raw carving with validation | Partial | Full-image PNG/BMP/JPEG scanning requires a recorded source SHA-256. PNG chunks and CRCs are checked and decoded; BMP candidates pass bounded header/geometry/pixel-array checks and a 256 MiB-capped pixel decode through a source-range reader; JPEG candidates pass bounded marker/scan parsing and pixel decoding. The scan tracks progress/cancellation and transactionally stores an audited SHA-bound snapshot. Candidates retain exact offsets and hashes; original names, allocation state, and deletion status are unknown. Package verification checks carving manifests, selected-candidate inventory, output hashes, checksum coverage, and completion/source-digest consistency. The PNG/JPEG carver now has a pinned independent exFAT image check requiring exact byte lengths and upstream SHA-256 matches; it does not establish deleted status or qualify broad media compatibility. A separately Pillow-encoded 16 × 12 BMP is accepted only after native decode and exact length/SHA-256 comparison; it is a controlled fixture, not an external corpus. PDF/Office and additional independently validated formats, external carving corpora, and large-image benchmarks remain open. |
| 8 | Recovery exports actual reconstructed data | Partial | NTFS export tests compare recovered bytes with known fixture contents and verify hashes. Synthetic FAT32 exporter tests compare exact output bytes and reject currently allocated clusters. PNG/BMP/JPEG carving tests verify format validation, boundary discovery, corruption/bounds rejection, selected-file output hashes, and native package verification including modified-output rejection. Independent FAT32 deletion fixtures, exFAT recovery, additional carving formats, damaged media, and production-scale exports remain open. |
| 9 | Independently verifiable imaging and hashing | Partial | Streaming SHA-256 of selected raw images and Windows physical-device acquisition are implemented. Failed reads retry with binary subdivision through the reported sector size; disconnected-device or changed-media errors stop acquisition without publishing or zero-filling unreadable ranges. After ordinary errors, written staging data is retained, an `INCOMPLETE.txt` marker is attempted, and the job error includes its path; it is not a resumable or package-verifiable acquisition. Complete acquisition packages include bounded error maps, read-back hashing, no-replace publication, and a verifier for image, manifest, checksums, completion, and sector-aligned error ranges. A regression verifies that a one-sector unreadable range can be exported as partial and pass package verification. Resume/split imaging, abrupt power-loss recovery, independent implementation cross-checks, external hash anchoring, and physical-device qualification remain open. |
| 10 | Progress reflects real engine activity | Partial | NTFS scan and hash operations report processed bytes and discoveries from native work. Multi-stage scan status, throughput, ETA, device errors, and coverage visualization are not implemented. |
| 11 | Safe cancellation and interrupted-operation recovery | Partial | Archived evidence can now be reopened only from its selected case's verified scan record, after matching the recorded size and full SHA-256; a mismatch marks the evidence record compromised and is audited. The reopened source still requires a fresh scan. User-cancelled physical acquisitions remove unpublished staging; ordinary acquisition errors retain staged bytes and include the path in the job error; a marker is attempted, and the package verifier rejects unfinalized staging. This does not resume the operation or qualify abrupt crashes. Scan resume/checkpoints, abrupt-crash recovery, and process-kill testing remain open. |
| 12 | Responsive operation during large scans | Unverified | No million-record fixture, representative large-image benchmark, memory budget test, or UI responsiveness benchmark is recorded. |
| 13 | Reports reflect completed operations | Partial | Native JSON case report v6 and print-friendly HTML with a complete JSON appendix include the verified case/evidence register, archived NTFS candidates, FAT32 and exFAT directory snapshots, validated PNG/BMP/JPEG carving snapshots, case-scoped recovery export/package verification events, per-case physical acquisition/RAID audit events with their event hashes, snapshot hashes, and the locally verified audit-chain head. Each scan records whether its source digest matches the current case evidence digest. Export stages and syncs the file, publishes without replacing an existing path, and audits preparation/completion with the report hash and family counts. HTML escapes untrusted text and sets a restrictive content security policy. The Reports UI binds its result to a case ID and clears it when active-case or audit-match state changes. Report operation records are copies of local audit data, not independent proof of acquisition conditions or array geometry; the chain is unanchored and report content does not establish recovered-content integrity. Tests cover populated export, returned case ID, audit tampering, no-replace, digest mismatch, exFAT snapshot inclusion, case-scoped recovery and imaging event inclusion, and HTML escaping. Actual JSON/HTML generation still needs native UI smoke coverage. PDF, CSV, signing, external anchoring, independent device/array validation, and acquisition hardware evidence remain open. |
| 14 | Unsupported features are clearly identified | Partial | Unsupported routes render the `NOT AVAILABLE` state and disclose that no results are generated. Route review corrected “Filesystem Analysis” so it no longer opens the NTFS-only recovery view and renamed metadata-only “Partition Recovery” to “Partition Analysis.” `npm run validate` passed after the route change. Packaged UI review and a complete audit of labels, actions, settings, and reports remain open. |
| 15 | Windows package follows declared security and privilege model | Incomplete | Current Tauri configuration targets NSIS. A local offline-setup build reproduced `makensis.exe` failure with Windows error 623, but hosted `Stage unsigned Windows installer` runs subsequently built and uploaded staging artifacts for commits `64a4a13` and `6257d91`; run IDs, artifact digests, and verification limits are in `VERIFICATION.md`. The staging workflow records installer SHA-256 and Authenticode status in a provenance manifest; the newest artifact has not been unpacked locally, and no installer has passed install/update/uninstall testing or publisher signing. Historical MSI output remains unqualified: WiX ICE57 flagged mixed per-user/per-machine shortcut registry state, with ICE40/ICE61 warnings and generated same-version upgrade behavior. Microsoft Store submission, signing, and privileged-helper review remain open. Current support is image-only without a privileged helper. |
| 16 | No simulated or fabricated forensic results | Partial | Tests use explicit synthetic fixtures with known contents; unsupported pages disclose their status. Verify packaged runtime paths end-to-end, and audit all result, confidence, progress, preview, and report surfaces for fabricated or unsupported conclusions. |

## Newly connected, limited workflows

The RAID Reconstruction route produces read-only-derived packages for operator-configured RAID 0, byte-identical RAID 1, and full-member left-symmetric RAID 5 with rotating XOR parity verification. RAID 5 requires every member image and fails closed on parity mismatch; if image data has been written, failed output is retained, a marker is attempted, and the path is surfaced in the job error. Degraded or missing-member reconstruction is not supported. It requires an audited active case, explicit member order/data offset/sector geometry/stripe size, hashes members before and after reconstruction, rereads and hashes the output, publishes without replacing an existing package, registers the image as evidence, and records outcomes in the audit chain. Seven runnable synthetic tests cover RAID 0 ordering/package verification, RAID 1 matching and mismatch rejection, RAID 5 rotating parity and output ordering, parity-mismatch rejection with marked unverified staging, progress accounting, and cancellation cleanup. The Linux CI fixture job creates a loop-backed MD RAID 5 array and pins a known logical image; an ignored integration test reconstructs from its captured member data in Windows CI and compares exact bytes. Hosted run 43666164749 passed the Linux-to-Windows reference reconstruction and exact logical-byte comparison. The mapping follows the Linux MD reference implementation: parity rotates left by stripe row, and data order starts after the parity member ([kernel implementation](https://linux.googlesource.com/linux/kernel/git/torvalds/linux/%2B/6c790212c588fddeb0d852f2790840753bb604b1/drivers/md/raid5.c), [layout names](https://www.kernel.org/doc/html/v6.11/admin-guide/device-mapper/dm-raid.html)). Vendor metadata detection, degraded arrays, RAID 6, alternate layouts and physical-array qualification remain open; this feature is not production-qualified.

## Current package evidence

The earlier packaged unsigned Windows x64 executable is
`DaemonCore-Data-Recovery-Windows-0.1.0-filename-provenance-r40-unsigned.exe`
(SHA-256 `c84dd31f2c13368fc3b2d15f4ea0f5179d1f527bc132c504490fde1ac68f57c3`).
The offline NSIS setup is
`DaemonCore-Data-Recovery-Windows-0.1.0-filename-provenance-offline-setup-unsigned.exe`
(SHA-256 `8f84c33a1242c481d502d8fd94c3c3c8474c7c482203bfe6e4aed44c921833bc`).
Both signatures report `NotSigned`. NSIS generated the setup and emitted its
documented compatibility fallback warning 6040. The installer has not been
installed or removed. Hashes are listed in the adjacent `SHA256SUMS.txt`
distribution manifest.

The freshly rebuilt r45 NSIS installer is
`DaemonCore-Data-Recovery-Windows-0.1.0-downgrade-guard-r45-unsigned.exe`
(SHA-256 `5d9a6144fc01b9212448eadf0737d5d6ad9ce69abe8f2ce34f72512f2e6ba07c`).
Its packaged executable has SHA-256
`c84dd31f2c13368fc3b2d15f4ea0f5179d1f527bc132c504490fde1ac68f57c3` and remains
unsigned. That exact executable was launched once and its Evidence Vault
verified the local chain as internally consistent across 27 records; no
independent chain-head comparison was supplied. Installer install/update/
uninstall tests remain outstanding.

The previous native-smoke executable at
`DataRecovery/src-tauri/target/release/daemoncore.pre-nsis.exe` was
12,969,472 bytes, unsigned, and SHA-256
`5a7075617143cefc1b74783ba57930f05c6d0086e0ee282d935e0916db73f35d`. That
exact binary launched: dashboard/logo and Evidence Vault rendered, and the
local verifier checked 27 internally consistent records. No independent head
hash was supplied.

The latest Tauri CLI `custom-protocol` build is staged as
`DaemonCore-Data-Recovery-Windows-0.1.0-ntfs-core-r47-unsigned.exe`
(12,969,472 bytes, SHA-256
`3f3e4ae4228a2c3634ee976c0279c2f3e42c32a220ddfd6ab41d2c3fc98cdfb0`,
Authenticode `NotSigned`). That exact staged file launched after approval; the
dashboard/logo rendered, Evidence Vault opened, and its verifier checked 27
internally consistent records with the same chain head. No independent head
was supplied. The matching offline NSIS setup was not produced: the staged
`makensis.exe` fails to start on this Windows host with system error 623
(`ERROR_ILLEGAL_DLL_RELOCATION`).
The same error was reproduced by the official NSIS 3.13 compiler after its ZIP
matched the NSIS release dataset's SHA-256. The exact Windows error is defined
by [Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d); NSIS 3.13 release provenance is listed by
[SourceForge](https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/).
The offline WebView2 runtime itself was fetched and its Authenticode status is
`Valid` (215,017,168 bytes). No installer was staged, installed, or launched.
Signing, installer lifecycle, and all other open acceptance criteria remain
release gates.

The packaging configuration now disallows older application versions, but the
generated WiX authoring still permits same-version MSI upgrades. Its MSI build
reports ICE40 (`REINSTALLMODE`), ICE57 (mixed per-user/per-machine shortcut
registry state), and ICE61 (same-version upgrade range). This MSI is not a
release candidate. The new NSIS/MSI outputs from this packaging run are also
unsigned; they have not been installed or launched.

Test totals and detailed scope are recorded in `VERIFICATION.md`; capability
boundaries and hard release gates are maintained in `CAPABILITIES.md`. This
audit is a status ledger, not a substitute for the missing tests or evidence.

## Hosted validation update — 2026-11-15

On [run 43663379647](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43663379647),
the Linux FAT32 fixture was generated, independently checked with Sleuth Kit, and
matched against the core deleted-file mapper's expected bytes. The independent
exFAT reference-volume inventory passed. Linux MD created the RAID 5 reference array
and verified the known logical-image hash. GitHub rejected both cross-job fixture
uploads because the repository's Actions artifact storage quota was exhausted, so
the dependent Windows FAT32 export and RAID reconstruction checks were skipped.
The MFT record fuzz campaign passed on run 43663566673; the whole-image and
partition-image campaigns were still running when this update was written. These
Linux checks do not establish the missing Windows end-to-end behavior.

On [run 43664981029](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43664981029)
for commit `ed69228`, the decoupled Windows validation job completed successfully,
including `npm run validate`, the independent multi-cluster FAT32 image test, and
the independent exFAT carving-content test. The MFT, whole-image NTFS scan, and
partition-image fuzz campaigns all completed successfully. Linux independently
formatted and checked the FAT32 deleted-file fixture, and the core mapper matched
its known bytes; Linux MD created the RAID 5 reference array and matched its
known logical-image hash. Uploading those two fixtures failed at the Actions
artifact storage quota, so the separate Windows RAID reconstruction and FAT32
package-export checks were skipped. The workflow's overall conclusion is
therefore failure even though its baseline Windows and parser-fuzz jobs passed.
This improves visibility of test outcomes but does not close the two Windows
reference gates.

On [run 43666164749](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43666164749)
for commit `be2e820`, all six workflow jobs passed. The per-run, per-attempt
cross-OS cache restored both Linux-generated fixture sets on Windows and their
SHA-256 checks passed. Windows reconstructed the Linux MD RAID 5 fixture and
matched exact logical bytes; it also exported the deleted FAT32 file and matched
the Sleuth Kit expected bytes. Baseline Windows validation, independent FAT32
multi-cluster reading, exFAT validation/carving, and the three bounded parser
fuzz campaigns passed. This closes the artifact-quota fixture-transfer blocker
and the hosted FAT32/RAID reference checks. Physical-device qualification,
degraded RAID, sustained fuzzing, crash/resume, large-image performance, trusted
installer signing/lifecycle, and other release criteria remain open.
