# Production acceptance audit

This audit maps the original product brief's 16 acceptance criteria to current
evidence. A partial result means the evidence proves only the stated scope; it
does not satisfy the full criterion. Release readiness requires every criterion
to be independently verified for the shipped package.

| # | Acceptance criterion | Status | Current evidence and remaining work |
|---:|---|---|---|
| 1 | Reliable launch on supported Windows | Partial | Earlier smoke builds launched, rendered the dashboard/logo, opened Evidence Vault, and verified 27 internally consistent records. The staged Tauri r50 executable also launched and rendered Dashboard and Reports; see `VERIFICATION.md`. No independent audit head was compared in that check. Installer lifecycle, clean-account/configuration, and broader startup tests remain open. |
| 2 | Supplied logo appears above the sidebar | Partial | The prior native smoke screenshot showed the supplied data recovery logo above navigation. Verify sizing, transparency, high-DPI scaling, and collapsed-sidebar behavior in the packaged app. |
| 3 | Accurate physical devices and supported images | Incomplete | The source page is labeled “Image Workspace” and accepts raw image files only. There is no physical device discovery, device capability inventory, hot-plug handling, or validated virtual disk support. |
| 4 | Source evidence is not modified | Partial | Image access uses a read-only handle with write/delete sharing denied, checks image stability, and rehashes around operations. Hardware write blocking, raw-device access guarantees, and restricted-account tests are absent. |
| 5 | NTFS deleted-file recovery on verified images | Partial | Synthetic tests verify resident, fragmented, sparse, and independently formatted NTFS fixture contents and hashes. Two hosted Linux campaigns completed 1,000,000 `parse_record` inputs and about 485,000 whole-image scans each within their time limits without a reported crash; the latter covers resident, nonresident, and continued-attribute-list seed images validated through the application scan path. Run IDs and coverage details are in `VERIFICATION.md`. These bounded runs do not qualify sustained campaigns or independent-volume behavior; broader deleted-volume, damaged-volume, overwrite/TRIM, hard-link, compression, ADS, and scale coverage remains required. |
| 6 | Controlled FAT32 and exFAT recovery | Incomplete | FAT32 BPB geometry, FAT capacity, cluster bounds, and its declared backup boot sector are checked. The core crate has a read-only volume mapper with mirrored-FAT consistency checks, fragmentation-aware range reads, cycle and bad-chain rejection, and bounded mapping. It enumerates live directory records with bounded cluster and entry traversal, retains each short-name record and source offset, and reconstructs LFN names only from complete, sequence-checked, checksum-matching UTF-16 records; invalid sequences fall back to the short name. Deleted entries are skipped. It is not connected to Tauri scan persistence, UI, or export. exFAT main and backup boot-region checksums and volume geometry are validated against the Microsoft specification, including backup fallback. Partition parsing now lives in the reusable core crate. GPT parsing rejects unsupported revisions, nonzero reserved fields, zero disk GUIDs, incorrect primary/backup header references, out-of-image usable LBA ranges, invalid entry dimensions, unsafe table placement, and reports zero or duplicated unique partition GUIDs. Primary/backup headers are compared for disk identity, usable bounds, and entry dimensions, and arrays must appear on the correct side of usable space; valid backups remain available for fallback. Synthetic regressions and hosted fuzzing exercise GPT structures and valid entry arrays with recomputed CRCs. Recursive traversal, deleted-entry recovery, allocation analysis, Tauri integration, export, independently formatted FAT32/exFAT fixtures, and controlled damaged-volume tests remain unimplemented. |
| 7 | Real raw carving with validation | Incomplete | No operational carving engine or validated signature registry exists. The UI marks unsupported operations unavailable. |
| 8 | Recovery exports actual reconstructed data | Partial | NTFS export tests compare recovered bytes with known fixture contents and verify hashes. Coverage is limited to supported NTFS streams; FAT32, exFAT, carving, damaged media, and production-scale exports remain unverified. |
| 9 | Independently verifiable imaging and hashing | Partial | Streaming SHA-256 of a selected raw image is implemented and tested. Device acquisition, range imaging, retry/error maps, resume, and independent acquisition verification are absent. |
| 10 | Progress reflects real engine activity | Partial | NTFS scan and hash operations report processed bytes and discoveries from native work. Multi-stage scan status, throughput, ETA, device errors, and coverage visualization are not implemented. |
| 11 | Safe cancellation and interrupted-operation recovery | Partial | Archived evidence can now be reopened only from its selected case's verified scan record, after matching the recorded size and full SHA-256; a mismatch marks the evidence record compromised and is audited. The reopened source still requires a fresh scan. Cancellation, scan resume/checkpoints, crash recovery, and process-kill testing remain open. |
| 12 | Responsive operation during large scans | Unverified | No million-record fixture, representative large-image benchmark, memory budget test, or UI responsiveness benchmark is recorded. |
| 13 | Reports reflect completed operations | Partial | A native JSON case report now includes the verified case/evidence register, archived NTFS scan summaries and candidate snapshots, snapshot hashes, and the locally verified audit-chain head. Each scan explicitly records whether its source digest matches the current case evidence digest, so a later rehash discrepancy remains visible. Export stages and syncs the file, publishes without replacing an existing path, and audits preparation and completion with the report hash. It discloses that the chain is not externally anchored and that the report does not establish acquisition provenance or recovered-content integrity. Populated-export, audit-tamper, no-replace and digest-mismatch tests pass. The r50 packaged Reports screen rendered and correctly disabled export with no case selected; actual report generation was not exercised in that UI check. This does not yet provide PDF, HTML, or CSV reports, a signed report, or acquisition/device logs. |
| 14 | Unsupported features are clearly identified | Partial | Unsupported routes render the `NOT AVAILABLE` state and disclose that no results are generated. Route review corrected “Filesystem Analysis” so it no longer opens the NTFS-only recovery view and renamed metadata-only “Partition Recovery” to “Partition Analysis.” `npm run validate` passed after the route change. Packaged UI review and a complete audit of labels, actions, settings, and reports remain open. |
| 15 | Windows package follows declared security and privilege model | Incomplete | Current Tauri configuration targets NSIS. A local offline-setup build reproduced `makensis.exe` failure with Windows error 623, but hosted `Stage unsigned Windows installer` runs subsequently built and uploaded staging artifacts for commits `64a4a13` and `6257d91`; run IDs, artifact digests, and verification limits are in `VERIFICATION.md`. The staging workflow records installer SHA-256 and Authenticode status in a provenance manifest; the newest artifact has not been unpacked locally, and no installer has passed install/update/uninstall testing or publisher signing. Historical MSI output remains unqualified: WiX ICE57 flagged mixed per-user/per-machine shortcut registry state, with ICE40/ICE61 warnings and generated same-version upgrade behavior. Microsoft Store submission, signing, and privileged-helper review remain open. Current support is image-only without a privileged helper. |
| 16 | No simulated or fabricated forensic results | Partial | Tests use explicit synthetic fixtures with known contents; unsupported pages disclose their status. Verify packaged runtime paths end-to-end, and audit all result, confidence, progress, preview, and report surfaces for fabricated or unsupported conclusions. |

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
