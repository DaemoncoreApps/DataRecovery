Warning: truncated output (original token count: 28560)
Total output lines: 1447

# Recovery validation — 2026-10-31

## Full-volume exFAT parser fuzz coverage — 2026-11-02

Extended the bounded partition-image fuzz target beyond exFAT boot-region
recognition. Each fuzz input now exercises `Volume::open` and, when opening
succeeds, the live directory-tree walker against a generated valid minimal
exFAT volume. Mutations target the boot region, FAT chains, root entry sets,
allocation bitmap, and up-case bytes; dependent boot, entry-set, and up-case
checksums are recomputed where needed so malformed cases can reach deeper
validation stages. The existing hosted 120-second `partition_image` campaign
will run this expanded harness and retain its evolving corpus and artifacts.
No hosted result exists for this change yet. This checks parser robustness;
it does not establish media compatibility or recovery accuracy.

## Independent FAT32 deleted-file package export — 2026-11-02

Extended the independent FAT32 fixture workflow through the native recovery
package writer and verifier. The Linux job formats, copies, and deletes the
fixture with `dosfstools` and `mtools`; Sleuth Kit (`fls`/`icat`) must list the
deleted entry and recover bytes equal to the original 65,536-byte file (SHA-256
`7daca2095d0438260fa849183dfc67faa459fdf4936e1bc91eec6b281b27e4c2`). It
uploads the image and expected contents as a short-lived artifact. The Windows
job verifies both hashes, then the app-level test rediscovers the deleted
short entry, exports it using the production FAT32 package path, runs the
native package verifier, and compares output byte for byte with the
independent expected content. The hosted test has not run yet; this adds the
executable qualification to CI but is not evidence of a passing hosted result.
It covers one contiguous deleted-file case and does not validate historical
fragmentation, deleted long names, or general FAT32 forensic compatibility.

## Case report recovery-operation provenance — 2026-11-02

Case report schema v6 now includes case-scoped, hash-chained audit events for
NTFS, FAT32, and carving exports, plus successful package verification. The
export summary and prepared/completed report audit records include the
recovery-operation count. A regression verifies NTFS and carving export events
for the report's case are included, another case's FAT32 export is excluded,
and the emitted event retains its audit-record hash. Reports continue to state
that audit records are locally chained copies, not independent proof of the
operator's acquisition conditions or recovered-file integrity. Packaged report
generation remains to be exercised in the native UI.

## Physical acquisition selected-device binding — 2026-11-02

Physical acquisition now receives the complete device row selected in the UI.
After the operator chooses a destination, the native layer opens the requested
device and compares its number, geometry, and full reported Windows storage
descriptor with that selected row. It refuses to start if the device was
replaced or any reported identity/geometry field changed while the dialog was
open. Regression tests accept an unchanged descriptor and reject changed
serial and disk geometry. This closes the stale-device-number case when the
device exposes distinguishing identity fields; it cannot establish identity
when the hardware reports none, and it does not replace write-blocker or
physical-device qualification.

## Independent real-image file-carving validation — 2026-11-02

The Windows validation workflow now runs the PNG/JPEG carver over the
hash-pinned 50 MiB exFAT reference image described below. It requires exact
matches for upstream `IMG_1054.JPG` (689,275 bytes,
`76204f90870d97c2d462c58e113f8a90f2edf4b6fbd95ac2f0f876bb4e61b311`) and
`debian.png` (83,972 bytes,
`a331c17e8e1c28e734937353b633708b8e0c0816ee5ff1926e89cff957a68f08`). The
check validates byte recovery from a real independently generated filesystem
image against known source-file hashes; it does not determine deletion status,
original path metadata, or performance on large images. Local focused test
passed in 19.74 seconds. Hosted result remains pending until the workflow runs.
Fixture sources and licensing notes are in
[`src-tauri/tests/fixtures/README.md`](src-tauri/tests/fixtures/README.md).

## Independent exFAT volume validation — 2026-11-02

- Added a reproducible CI job for the independent exFAT image published by
  [eribertomota/forensics-samples](https://github.com/eribertomota/forensics-samples)
  at commit `b938bbea0d8bec5c1795433cf6227bedd9623532`. The archive SHA-256 is
  `6aa8868301b0288cd3f9d751c1779fd79570f7cb1bb9568d70d0a27d74c00d70`; the
  decompressed 50 MiB image SHA-256 is
  `98d518601199a32054158bb3a759e12b554fd2ebcc5960541caf9e1a907198d0`.
  The upstream README identifies filesystem images as MIT licensed and asks
  users to preserve its 2019-2020 copyright notice; the image is downloaded in
  CI and not redistributed in this repository.
- The first independent run failed and exposed two parser defects: the eight
  Extended Boot Sectors were checked against the wrong byte sequence, and a
  valid up-case table ending with the literal U+FFFF identity mapping was
  interpreted as a truncated compression marker. Both behaviors are corrected
  against the [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification).
- The fixture-specific test now opens the partition at byte offset 1,048,576,
  validates both boot copies, allocation bitmap, up-case table, entry sets,
  and allocated streams, then checks all 22 documented live paths and confirms
  deleted directories (`audio2`, `movie2`, `pic2`, `text2`) are not reported as
  live. The focused test passed locally against the hash-verified image. The
  full `npm run validate` then passed the frontend build, Rust format checks,
  54 core tests, 109 desktop tests, and Clippy with warnings denied (six
  environment/fixture-dependent tests are ignored by the base suite). The
  independent exFAT image test is a separate focused run and is enabled in the
  new hosted workflow job; its hosted result is still pending.
- Physical device geometry parsing now requires all 32 bytes through the end
  of the `DISK_GEOMETRY_EX.DiskSize` field and checks agreement with the length
  IOCTL, sector bounds, and sector alignment. Two unit tests cover the exact
  31/32-byte truncation boundary plus inconsistent size/sector and truncated
  length responses. The focused tests and Windows Clippy check passed locally;
  no physical device was accessed during validation.
- The Reports screen now clears its prior export result when the active case or
  case-audit match changes. `CaseReportExport` includes the case ID and the UI
  only presents a result for that same active case. The report publication test
  asserts the returned case ID. `npm run validate` passed after these changes:
  frontend build, Rust formatting, 54 core tests, 111 desktop tests, and Clippy
  with warnings denied; three environment/fixture-dependent tests in each
  suite remain ignored. Native UI report generation is still not smoke tested.

## Current workspace validation and fuzz evidence

- Archived case scans now have an explicit **Verify and reopen source** action.
  It checks the audit-validated scan and evidence linkage, requires the case's
  stored evidence record to remain hashed at the original size/digest, then
  reopens the recorded path and hashes the full image before activation. A
  changed size or digest marks that evidence record compromised and adds an
  audit event; attempts also record a start event. Reopened evidence has no
  active scan cache; a fresh scan is required before recovery. The focused
  archived-source test checks acceptance of the matching record, rejection of
  compromised evidence, and atomic audit/status recording on a digest mismatch.
  The review UI shows the recorded filename, path, and expected scan digest;
  reopening is disabled unless the case evidence row is still hashed to that
  same digest.
- After this change, `npm run validate` passed: frontend TypeScript/Vite
  production build, Rust formatting, 4 NTFS core tests, 80 application tests
  passed, 0 failed, 3 ignored, and Clippy with warnings denied. Windows
  incremental compilation emitted its known hard-link fallback warning and
  copied cache files successfully. This validates code and tests; the newly
  built packaged UI has not received a native smoke run.
- Hosted Actions run `41265328618` passed on commit
  `2c5d5eb4bc6bca9f2dadd5ff150396725b68c606` ([run details](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41265328618)).
  The Windows job passed all validation steps, including 4 core tests, 80 app
  tests (3 ignored), and Clippy with warnings denied. Linux fuzzing completed
  1,000,000 record-parser executions (435 coverage counters, 536 features,
  426 MiB peak RSS) and 439,589 whole-image scans in 121 seconds (1,394
  counters, 4,203 features, 455 MiB peak RSS), with no reported crashes. The
  scan corpus reached 325 inputs (19 MiB). GitHub retained artifact
  `ntfs-fuzz-results-41265328618` (482,394 bytes, SHA-256
  `4fad346554603758e9d9a410d01707e1af3368799687e0c7334a89054c2d4821`) until
  2026-11-15. The follow-up local validation and mismatch-audit regression
  changes are not part of this hosted run.

- `npm run validate` passed after extracting the shared NTFS parser core:
  TypeScript/Vite production build, Rust format checks, 4 core tests, 79
  application tests passed, 0 failed, 2 ignored, and Clippy with warnings
  denied. Windows incremental compilation emitted a hard-link fallback warning;
  it copied cache files and all commands completed successfully.
- The parser now lives in `ntfs-core`, consumed by both the Tauri application
  and the standalone cargo-fuzz crate. This keeps the fuzzer on the same parser
  implementation as the app.
- Coverage-guided run completed in a Linux container with Rust nightly,
  `cargo-fuzz 0.13.2`, and Clang:
  `cargo +nightly fuzz run ntfs_parse_record --jobs 1 --target-dir /work/src-tauri/target/linux-fuzz -- -runs=1000000 -max_total_time=120 -max_len=1024`.
  It completed 1,000,000 executions in 16 seconds, reported 401 coverage
  counters and 506 features, and produced no crash artifact. The checked-in
  corpus has the seed records and coverage-increasing inputs.
- Scope limitation: this target calls `parse_record` on 1024-byte records. It
  does not exercise `read_record`, `$ATTRIBUTE_LIST` resolution, on-disk
  geometry parsing, or application workflows. Sustained fuzz campaigns,
  corpus review, independent real-world fixtures, and broader platform and
  release qualification remain open. The native Windows cargo-fuzz build was
  not usable with the installed MSVC sanitizer toolchain, so this run used the
  Linux container.
- A second fuzz target, `ntfs_scan_image`, now feeds bounded (4 MiB maximum)
  volume images through the shared `scan` API. This reaches boot-sector parsing,
  MFT record reads, resident and nonresident `$ATTRIBUTE_LIST` resolution, and
  extension records. Its corpus includes three controlled regression images
  covering resident, nonresident, and continued nonresident lists. These are
  synthetic seeds, not independent-volume fixtures. The native Windows
  libFuzzer build remains unusable with the installed MSVC toolchain, and
  Docker/WSL access is denied in this session; hosted Linux Actions now runs
  the target instead.
- Earlier on 2026-10-31, before hosted fuzzing was added, the three checked-in scan seeds each passed the new
  `whole_image_fuzz_seeds_scan_and_resolve_attribute_lists` regression. Fresh
  `npm run validate` passed: frontend build, Rust format checks, 4 NTFS core
  tests, 80 application tests, 0 failures, 3 ignored, and Clippy with warnings
  denied. Cargo metadata lists both `ntfs_parse_record` and `ntfs_scan_image`
  targets. The Windows `cargo check` attempt for the fuzzer could not complete:
  MSVC's librarian failed to overwrite libFuzzer's intermediate archive
  (LNK1114/access denied). No coverage-guided run has yet exercised
  `ntfs_scan_image`.
- Added `.github/workflows/validate.yml` for Windows `npm run validate` and
  bounded Linux campaigns of both fuzz targets. The workflow fetches each
  locked Rust dependency graph before running the offline validation command,
  uses read-only repository permissions, pins its GitHub actions to commit
  SHAs, and stores the resulting fuzz corpus/artifacts for 14 days. Markdown-
  only changes do not trigger the build/fuzz jobs.
- Hosted Actions run `41263131573` passed on commit
  `6a1447e4dba032beed057cc90a915d13a629f49f`. The Windows validation job passed
  the frontend build, formatting, 4 NTFS core tests, 80 application tests, and
  Clippy with warnings denied (3 tests ignored). On Ubuntu 24.04, the
  `ntfs_parse_record` target completed 1,000,000 executions in 12 seconds
  (444 coverage counters, 565 features, 422 MiB peak RSS). The
  `ntfs_scan_image` target completed 482,601 executions in 121 seconds before
  its 120-second time limit (1,408 coverage counters, 4,156 features, 457 MiB
  peak RSS). Neither campaign reported a crash. The scan corpus grew from 3
  seeds to 330 inputs (20 MiB) during the run.
- Follow-up Actions run `41263922574` passed on commit
  `fc2e61c353700c2012f9d9a148499eba7aa50f32`, using Node 24 compatible, SHA-
  pinned workflow actions. Windows validation again passed with 4 core tests
  and 80 application tests (3 ignored). Linux fuzzing completed 1,000,000
  record-parser inputs in 10 seconds (446 counters, 551 features, 425 MiB peak
  RSS) and 484,757 whole-image scans in 121 seconds (1,412 counters, 4,317
  features, 459 MiB peak RSS); neither reported a crash. The scan corpus
  reached 336 inputs (20 MiB). GitHub retained the success artifact
  `ntfs-fuzz-results-41263922574` (492,928 bytes, SHA-256
  `90fdad262bc14e8b9a8c4b8048fb3d010737a0b26980a0a6f1f84c46ec8d06bc`) until
  2026-11-15. These are initial bounded campaigns with synthetic seeds, not
  sustained or independent-volume qualification.
- The previous refactored Windows release executable was rebuilt using the
  warm workspace target and launched once after approval. It is 12,969,472
  bytes, SHA-256 `5a7075617143cefc1b74783ba57930f05c6d0086e0ee282d935e0916db73f35d`,
  and not Authenticode signed. The dashboard/logo rendered, Evidence Vault
  opened, and the verifier reported 27 internally consistent records with
  chain head `10669c0ef2dafbf6dd162190df847de7545441c32926f1746820bba4748b06a0`.
  No independent head hash was compared.
- `npm run tauri -- build --bundles nsis --verbose` rebuilt the Tauri
  `custom-protocol` release executable and staged a copy at
  `outputs/DaemonCore-Data-Recovery-Windows-0.1.0-ntfs-core-r47-unsigned.exe`:
  12,969,472 bytes, SHA-256
  `3f3e4ae4228a2c3634ee976c0279c2f3e42c32a220ddfd6ab41d2c3fc98cdfb0`,
  Authenticode `NotSigned`. The staged copy was launched once after approval;
  the dashboard/logo rendered, Evidence Vault opened, and the verifier reported
  27 internally consistent records with chain head
  `10669c0ef2dafbf6dd162190df847de7545441c32926f1746820bba4748b06a0`. No
  independent head was compared.
- The configured offline NSIS package step downloaded the 215,017,168-byte
  Microsoft WebView2 offline runtime; its Authenticode status is `Valid`.
  NSIS then failed to start with Windows system error 623
  (`ERROR_ILLEGAL_DLL_RELOCATION`). The same failure reproduced when invoking
  the local Tauri-bundled NSIS compiler directly and the official NSIS 3.13
  compiler. The downloaded NSIS 3.13 ZIP matched the official release dataset
  SHA-256 `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`.
  The offline setup was not produced; no installer was installed or launched.
  See [Microsoft's definition of error 623](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d) and the [official NSIS releases](https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/).

## Automated checks

- Fresh `npm run validate` on 2026-10-31 passed: TypeScript/Vite production
  build, Rust format check, 83 tests passed, 0 failed, 2 ignored, and Clippy
  with warnings denied. Cargo emitted only the known incremental-cache
  hard-link fallback warning.
- Unified `npm run validate` gate: passed (TypeScript/Vite, Rust format, tests, Clippy).
- Latest `npm run validate` on 2026-10-31 passed: TypeScript/Vite production build, Rust format check, 76 Rust tests passed, 0 failed, 2 ignored, and Clippy with warnings denied.
- Cargo reported that incremental-cache hard links were unavailable and copied cache files instead; the validation command still exited successfully.
- Checkpoint and recovery verifiers reject symlink entries and reparse-point package roots, retain Windows share-read handles for each opened file, and retain no-delete-share handles for plain package directories during verification and final tree checks (maximum 4,096 directories). Windows tests confirm file writes/renames and directory renames fail while the respective handles are retained; directory enumeration and child creation remain possible. The final tree check detects persistent entry changes, but path-based traversal cannot provide an atomic snapshot or rule out transient child add/remove events or a path swap before a child directory is first locked.
- Latest full `npm run validate` after retained-file verification: 76 Rust tests passed, 0 failed, 2 ignored; frontend build, Rust format, and Clippy with warnings denied passed.
- After directory-handle verification hardening on 2026-10-31, `npm run validate` passed: TypeScript/Vite production build, Rust format check, 77 Rust tests passed, 0 failed, 2 ignored, and Clippy with warnings denied.
- The Windows directory-handle regression test confirms that a retained plain-directory handle blocks rename while still allowing enumeration and child creation. The recovery verifier now retains each traversed directory handle through its final tree scan, and the audit checkpoint verifier holds its selected root directory during verification. This narrows path replacement races without claiming an atomic filesystem snapshot.
- The optimized Windows executable built after directory-handle hardening has SHA-256 `b51cf6d9c2d6acbb760150f93067abc816c5623b8adb8ca658a129adcfa231cc`; its Authenticode status is `NotSigned`. The matching offline NSIS setup is 222,182,507 bytes with SHA-256 `f0173fb4caae611595b586517abbd6dea04f90ae231e711edf1736f8cd668689`; it is also unsigned. The setup was built but not installed or launched.
- Packaging configuration now blocks older versions from replacing newer installs. A fresh Tauri bundle build completed for NSIS and MSI with offline WebView2 embedded. NSIS emitted warning 6040. MSI emitted WiX ICE40 (`REINSTALLMODE`), ICE57 (shortcut component mixes per-user HKCU registry state with a per-machine package), and ICE61 (same-version upgrades are allowed in generated `MajorUpgrade` authoring). Treat MSI as unqualified until these authoring warnings are resolved. Both new bundles are unsigned and have not been installed or launched.
- The release `daemoncore.exe` launched successfully once after approval. The Evidence Vault's local audit verifier reported 27 internally consistent records and displayed the chain head. No independent head hash was provided, so this did not rule out full-database replacement. The UI rendered the supplied logo and the audit disclosure correctly. The executable remains unsigned; no installer was launched.
- Windows same-physical-disk rejection test: explicitly rerun on 2026-10-31 and passed (1 passed, 0 failed); its temporary source file was confined to ignored `src-tauri/target/test-temp`.
- Controlled fixture writer: run explicitly with a task-owned output file and passed.
- Clippy with warnings denied: passed.
- TypeScript/Vite production build: passed.
- Recovery export verification tests cover complete and partial packages, output tampering, and unexpected files. A controlled NTFS export is also passed directly through the verifier and accepted with all three known output files.
- NTFS path-resolution tests validate each directory's sequence reference, reject stale MFT-slot reuse, conflicting `$FILE_NAME` parents, cycles, and ancestry deeper than 256 directories; the synthetic scan fixture resolves a nested parent chain.
- Controlled extraction restores a sequence-verified nested directory, hashes its relative output path, and passes the recursive package verifier; unverified and overlong paths fall back to generated flat names with the decision recorded in package metadata.
- The recovery verifier rejects unlisted empty directories as well as unlisted files, and hashes nested outputs by their normalized relative paths.
- Recovery package verification rejects a mismatched parent sequence even when inventory, checksums, and completion hashes are recomputed; legacy packages without the newer parent-reference metadata remain verifiable.
- Audit tests cover checkpoint size bounds, internal package integrity, live/checkpoint head matching, mismatches, malformed operator input, and tampered live chains. Exports cannot exceed the verifier's 64 MiB input cap.
- Windows debug executable build: passed; full native workflow exercised below.
- Optimized Windows executable: built with checkpoint export, offline and live
  audit-head comparison, recovery export verification, fail-closed audit-integrity
  checks, SQLite startup quick-check, and stale-result clearing; SHA-256 recorded
  in `outputs/SHA256SUMS.txt`.

## Recovery correctness

Controlled NTFS volume fixtures contain known deleted resident, fragmented, sparse,
reused, encrypted and continued streams. The tests compare reconstructed output
bytes to known source contents, check output hashes/inventory, block reused extents,
check safe names and nonreplacement, and check cancellation cleanup. Torn records,
invalid run offsets, negative LCNs, malformed geometry and near-valid record byte
mutations are exercised. Randomized-input smoke tests are not a substitute for a
long-running coverage-guided fuzzing campaign.

The native stream reader also has a regression test that crosses fragmented and
sparse 4 KiB clusters; this exercises extraction geometry beyond the 512-byte-cluster
synthetic image.

Recovery now requires a full source SHA-256 before scanning, rechecks it after
scanning, and checks it before and after extraction. A controlled mutation test
confirms a changed source is rejected before creating a recovery folder. Export
folders include source identity and selected-record fingerprints, a checksum list,
and a completion marker. These local files have no digital signature or external
trust anchor.

Recovery-start and recovery-finish audit events now bind the source path and full
source digest to each selected MFT record fingerprint and size; the finish event
also records the export outcome and output directory. A unit test checks these
payload fields. This improves internal traceability but does not create an external
trust anchor.

Audit timestamps now reject a system clock before the Unix epoch instead of silently
writing a zero timestamp. SQLite audit storage explicitly uses `synchronous=FULL`;
tests verify both behaviors.

Case context is persisted as the active case. Opening a source requires a selected
case; evidence insertion and its audit event commit in one transaction. Hash
completion updates the evidence record and audit event together. Successful NTFS
scans persist their summary, boot metadata, source digest, and candidate snapshot
with a linked audit record in one transaction. Case Management lists evidence and
completed scan inventory. Recovery manifests and export audit events bind the
persistent evidence and scan IDs. Tests cover atomic evidence insertion and scan
snapshot persistence, including rollback when the audit chain is invalid. Archived
candidates are now integrity checked and paged for read-only review after restart;
they are not reactivated for export, which still requires reopening the source and
completing a fresh scan.
The verifier continues to accept legacy recovery manifests without a case ID;
those packages are audited with a null case association.

The archived-results build stages persistent source records, auditable hash state,
completed scan snapshots, snapshot digest reconciliation, and a paginated read-only
viewer for previously saved candidates. Its optimized Windows executable and package
checksums are recorded in `outputs/SHA256SUMS.txt`.
The optimized archived-results build also passed a native startup/navigation smoke
check, documented below; recovery export was separately exercised with a controlled
fixture.

The audit checkpoint writer is covered by a bundle-format test for its event stream,
chain head, checksums and completion marker. Audit writes also verify the existing
chain and fail closed on detected tampering; a regression test confirms a rejected
write does not append another event. The offline package verifier rejects unknown fields, invalid export timestamps and unlisted folder entries in addition to checking file
checksums, completion metadata, event order from record 1, record IDs, chain links, event hashes,
and checkpoint head with bounded file reads; tests cover a valid package, oversized
files, and event tampering even after package checksums are recomputed. The native
exporter now preflights database text sizes and caps the exact JSONL event stream
to that same verification limit before creating a package. The native
picker accepted a valid synthetic package and rejected a tampered one. After a
valid verification, a second verification of a tampered package replaced the
success panel with the hash error and cleared the previous chain head. The latest
`DaemonCore-Data-Recovery-Windows-checkpoint-schema-hardening.exe` passed this
valid-then-tampered sequence. The latest
`DaemonCore-Data-Recovery-Windows-checkpoint-folder-integrity.exe` rejected an
extra unlisted package file, then accepted the clean package after the test file
was removed and cleared the earlier error. The current
`DaemonCore-Data-Recovery-Windows-checkpoint-prefix-validation.exe` also rejected
a checksummed, self-consistent package beginning at record 2. A successful
separate-volume checkpoint export and native verification has since been
completed as recorded below.
The recovery-folder verifier checks strict metadata, exact folder contents, checksum manifest, output hashes, selected-record inventory, and complete/partial state. Its tests cover valid output, tampering, and unlisted files. The source-hash gate and NTFS scan were exercised through an earlier optimized
Windows UI run; the checkpoint UI smoke test is described above.

A separate 2 MiB NTFS image generated upstream with mkntfs/ntfs-3g is included with
its license and source attribution. Resident `12345`, a 1,000-byte nonresident file,
and a 500,005-byte sparse file all match the upstream script's specified content.
Fixture SHA-256: e3612c182b8010e3599b5eb93bff427c7d824e85bdc2ddbe46e378e3ba814eb9.

## Actual native UI check

The Windows app was operated through the computer-use skill:

1. Selected the task-created controlled NTFS image through the native picker.
2. Confirmed the source SHA-256 was required and the recovery scan control was
   disabled before hashing.
3. Calculated the full-image digest in the native app and confirmed the digest
   appeared beside the source and the scan control became available.
4. Ran a real metadata scan; it confirmed 48 records examined, 6 deleted-file
   candidates and 0 skipped records, then completed the source recheck.
5. Confirmed resident, fragmented and sparse candidates were selectable; reused,
   encrypted and continued candidates were blocked.
6. Selected a candidate and chose a task-owned folder on the same physical disk.
   The real native command rejected the destination with a clear source-protection
   error; no recovery folder was created.
7. Searched for `fragment` and obtained exactly the expected single candidate.
8. Closed the test instance. No fixture records are loaded automatically by the app.

`DaemonCore-controlled-NTFS-scan.jpg` is a screenshot of this controlled native
scan, not sample evidence inserted into the product.

An earlier verifier-only smoke build displayed the recovery-folder verification
panel and opened its native folder picker. That picker was cancelled without
selecting a package.

The current optimized Windows build was then exercised with the controlled
64 KiB NTFS fixture at a C: workspace path. The native UI calculated the source
SHA-256, scanned 48 records, found 6 deleted-file candidates, and exported the
3 safe resident/fragmented/sparse fixture files to a dedicated Z: test folder.
The physical-disk extent guard accepted the destination; all 3 outputs were
rehash-verified with 0 failures. The native package verifier then reported
3 records, 3 files verified, 0 failures, and checksum-list SHA-256
`3439f4dbbbafab3531186824b1e9c5149e6a22550625810655b0efd8ef89d0a3`.
The exported bytes were independently compared with the fixture's known resident,
fragmented, and sparse contents, and the source image still matched its recorded
SHA-256 `990d1964d12d746964ce316a756de226c4648a827af723d3799f03e1b59018ab`.
This establishes the controlled GUI round trip only, not recovered-content
integrity for arbitrary evidence or independent forensic validation.
The current optimized Windows build exported an 18-event audit checkpoint to the
separate Z: test volume and verified that folder in the native app. The verifier
reported the package internally consistent and the same chain head as the export.
The exported head was
`93c387388920d2c2a35eefedfc3f9f3f0033e48b454ed2a12df0dff8bc437018`; the bundle
checksum digest was
`ad6d7c104366914f86a551e07f7ce932f2c157955a593d37836389dff6770911`.
After the export event was appended, the live local chain verified with 19 records.
These test operations are recorded in this workstation's persistent local audit
chain as software-validation activity. The checkpoint remains unsigned and
externally unanchored.

### Latest versioned build

The optimized `DaemonCore-Data-Recovery-Windows-0.1.0-unsigned.exe` was launched
and exercised through the native UI after the source-bound recovery audit change.
The 64 KiB controlled image matched SHA-256
`990d1964d12d746964ce316a756de226c4648a827af723d3799f03e1b59018ab`; the app
scanned 48 records, found 6 candidates, skipped 0, and exported the known resident,
fragmented and sparse records to
`Z:\CodexBuilds\DaemonCore-ProductionSmoke\DaemonCore-Recovery-1793131186677915800`.
The native verifier reported 3 records, 3 files verified and 0 failures. Each output
was independently compared byte-for-byte with the test fixture; all three matched.
The checksum-list SHA-256 was
`5fecb219490756d04623acd49622d54205b1a0aa8bd7f85e40a621433476a46e`. The live
local audit chain then verified with 27 records. The recovery audit payload's source
digest and selected-record fingerprints are also checked by a Rust unit test.

The staged executable matches the optimized build; its SHA-256 is
`f16e248f0b7c1cb03abd69a64e23656944ba4337fdf58f6e52c5360a0589ddc0`. Authenticode
reports `NotSigned`.

The current audit-durability build was launched after configuring explicit SQLite
`synchronous=FULL` and rejecting pre-epoch audit timestamps. The native app opened
normally and verified the existing 27-record local event chain as internally
consistent. The automated suite passed 46 tests with 2 manual/environment tests
ignored; dedicated tests cover FULL synchronous mode and pre-epoch rejection.

### Source-handle stability hardening

The Windows source handle now requires the filesystem to return modification-time
metadata. If that query fails, opening the evidence image fails instead of treating
two missing timestamps as proof that the source stayed unchanged. The handle-lock
regression test checks that a second writer, rename, and delete are denied while the
evidence is open, then confirms the held image still passes the stability check.
`npm run validate` passed after this change: TypeScript/Vite build, Rust format check,
58 Rust tests passed, 2 manual/environment tests ignored, and Clippy with warnings
denied. Cargo's feature graph confirms the default `custom-protocol` feature is
enabled. `npm exec -- tauri build --no-bundle` completed in optimized release mode;
its build-script output did not set Tauri's `dev` cfg. The executable contains the
current Vite asset references, and the packaged executable hash matches that build.
The rebuilt executable has not had a native UI smoke check yet. It remains unsigned.
The ignored Windows same-physical-disk destination test was explicitly run on this
workstation with its temporary fixture directed to the task workspace; it passed.

Active case changes now share the evidence workspace locks, refuse to run during an
active job, commit the selected case and audit event together, then clear the open
image, scan cache, and job state. Image selection reads the active case only after it
holds those locks, preventing a stale case selection from attaching new evidence to
the wrong case. The UI clears cached hex and case review data immediately, and ignores
late source-status responses from the prior context. Tests cover transactional case
selection, invalid case rollback, audit-chain preservation, and the running-job guard.
The latest optimized Tauri executable was rebuilt after this change.

The case register now reconciles creation-audited title/examiner values to the
current database rows and fails closed on changed or missing audited cases. Rows
from pre-audit databases remain visible with a `LEGACY · UNVERIFIED` label. Tests
cover valid reconciliation, edited row rejection, orphaned creation-event rejection,
and preservation of explicitly legacy rows. The earlier optimized executable passed
the native startup/navigation check below; the current head-hash comparison UI still
needs a smoke check.

The active-case setting is now reconstructed from selected-case creation and
active-case-change audit events. A mismatched or unaudited persisted pointer is
shown as requiring reconfirmation and cannot open evidence. Reselecting a case
appends a correction event recording the previous pointer and whether it matched
its prior audit history. The operator can resolve a mismatch by reselecting an
existing case or creating a new one; both paths record the prior state. Malformed
stored pointer values remain recoverable through these explicit actions, and the
raw previous value is retained in the audit event. Tests alter SQLite directly to
verify mismatches block opening, malformed pointers are repairable, and correction
events preserve the discrepancy while restoring a matched state.

Prior native smoke check of the optimized Windows executable: the app opened to the
workspace, Case Management navigation rendered the empty case register, and the
Evidence Vault audit verifier reported 27 records internally consistent. The
verifier also correctly stated that no external anchor is configured, so full
database replacement cannot be detected. This was a UI startup/navigation and
persisted-chain check, not an install, tamper-injection, or external-anchor test.

Live audit verification and checkpoint verification accept an optional chain-head
SHA-256 retained outside the database/package. They report a match only after
validating internal integrity and comparing the computed head with the supplied
value. Tests cover a valid match, mismatch, malformed input, and an internally
tampered chain. This validates consistency with the supplied value but cannot
prove who created or preserved it. The comparison controls have not yet had a
native UI smoke check on the current build.

Database startup now runs SQLite `quick_check` before enabling WAL or applying
schema changes. A regression test feeds a corrupt database file, verifies startup
rejects it, and confirms the original bytes remain unchanged. This checks SQLite
page/index consistency; it does not authenticate the application database or
replace the audit-chain and independent-anchor checks.

NTFS scan bounds now use only complete records within the MFT stream's initialized
size. The parser rejects zero, unaligned, over-volume, or out-of-stream MFT sizes
before scanning, avoiding treating uninitialized allocation tail as file records.
Regression tests cover the initialized record count and malformed boundaries.
The prior optimized executable included this parser change and passed the native
startup/navigation smoke check above.
The configured NSIS installer was also attempted with `npm exec -- tauri build
--no-sign`. The optimized executable built, but Tauri could not download its NSIS
3.13 tool because DNS/network access was unavailable; no installer was generated.
Installer packaging, signing, and install/uninstall testing remain release gates.

### Current offline Windows package and native audit smoke check

The offline NSIS build completed on 2026-10-31 with WebView2 embedded. The staged
standalone executable is 12,878,848 bytes with SHA-256
`05f454fd727871f040a3d8c548b293c87e2dbf71f669692abe4a8412bf25abf1`. The offline
setup is 222,183,617 bytes with SHA-256
`bdb39591c6badf0b24c9303f09d92a4d49bc32160f86b5309cb5400258b7ca83`. Both report
`NotSigned` under Windows Authenticode inspection.

With explicit approval, the optimized executable was launched once for a native
smoke check. The workspace opened, Evidence Vault loaded, and **Verify audit log**
reported 27 records internally consistent. No independently retained head hash
was entered; the UI correctly warned that a complete database rewrite cannot be
detected without one. This checked startup and the read-only audit screen only; it
did not test the installer, evidence acquisition, or recovery export in this run.

For Microsoft Store planning, current Tauri v2 guidance says the Store flow uses a
signed EXE or MSI installer linked from an unpackaged app listing, and requires an
offline WebView2 installer. It does not generate an MSIX package. This project has
the offline WebView2 and distinct publisher settings, but lacks trusted signing,
updater configuration, and Store submission. See the [Tauri Microsoft Store
guide](https://v2.tauri.app/distribute/microsoft-store/) and [Windows code signing
guide](https://v2.tauri.app/distribute/sign/windows/). The current unsigned NSIS
artifact is not a production release.

## Not yet verified for release

The extraction/output implementation itself is exercised against actual temporary
Windows files, including independent destination rehashing and no-overwrite moves.
Restricted accounts, installers/MSIX, signed binaries, device helpers, real damaged
media, representative large disks, full accessibility and broad performance are
still release gates. FAT32/exFAT recovery and other unfinished capabilities are
listed in CAPABILITIES.md. This application is not production-ready yet.


### Latest nested-path build smoke check

After the nested recovery-path changes, `npm run validate` passed with 68 Rust tests passed, 0 failed, and 2 ignored; the TypeScript/Vite build, Rust format check, and Clippy with warnings denied also passed. The optimized Windows executable at `src-tauri/target/release/daemoncore.exe` has SHA-256 `0CE7235A831D3A8FDFF8530DC689F194798F53EEE3CCAE9A5E41561645FE541F` and is not Authenticode signed.

That executable launched successfully in the native UI. The Evidence Vault's read-only verifier checked the workstation's 27-event audit chain and reported it internally consistent. It also stated that no independently retained chain-head hash was compared, so a full database rewrite or replacement is not detectable from this check. This smo…8560 tokens truncated…bde838ab5776399df9cf7a44bc7aeb77da9a48ceec0d672`,
expiring 2026-11-15. These results apply to `e295fbb`; the role-specific
partition-array placement checks described below are a subsequent local change
and still require hosted validation.

The primary partition-entry array must follow the primary header and end before
the first usable LBA; the backup array must follow the last usable LBA and end
before the backup header, as required by the
[UEFI GPT disk layout](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html).
The parser now enforces those role-specific boundaries. Two regressions move a
CRC-valid primary or backup array to the wrong side of the usable range and
verify fallback to the correctly placed copy. `npm run validate` passed locally
with 32 core tests, 75 desktop tests (3 ignored), formatting, and Clippy with
warnings denied. Hosted CI run
[41277014866](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41277014866)
for commit `05f2ba5212f0a0e1d9b2b056ac5b2c4d2fab33fe` also passed Windows
validation with 32 core tests, 75 desktop tests (3 ignored), formatting, and
Clippy with warnings denied, plus all three bounded fuzz campaigns. Its retained
fuzz archive is
[13071069195](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41277014866/artifacts/13071069195),
512,458 bytes, SHA-256
`2dbcad538ecbaccb98d29a0d9913ea4b42342edf9f3debc3ff4d5cd15983d7b8`,
expiring 2026-11-15.

The partition report now includes each used GPT entry's unique partition GUID.
Zero and repeated identifiers remain visible in the table and produce explicit
warnings, rather than being silently treated as valid unique IDs. Regression
fixtures cover zero and duplicate identifiers with valid recomputed array and
header CRCs. This follows the [UEFI GPT entry definition](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html),
which defines a unique GUID for every partition entry and zero type GUIDs for
unused entries. The production build, 34 core tests, 75 desktop tests (3
ignored), formatting, and Clippy with warnings denied passed locally. Hosted
validation for this follow-up is pending.

GPT entry sizes are now restricted to the UEFI-defined 128 × 2ⁿ sequence within
the parser's existing 4 MiB safety limit. A regression gives the primary header
a CRC-valid 136-byte entry size and confirms that it is rejected while the
valid backup table remains usable. This rule follows the
[UEFI GPT header definition](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html).
`npm run validate` passed locally with 35 core tests, 75 desktop tests (3
ignored), formatting, and Clippy with warnings denied. Hosted validation for
this additional change is pending.

Partition overlap warnings now identify only the affected partition indexes;
they no longer claim an MBR overlap is a GPT finding. A synthetic MBR regression
confirms the warning text. `npm run validate` passed locally with 36 core tests,
75 desktop tests (3 ignored), formatting, and Clippy with warnings denied.
Hosted CI run
[41278490909](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41278490909)
for commit `50e12fd5c0582556a1497d97651674cdc9b82f66` passed Windows
validation (36 core tests, 75 desktop tests with 3 ignored, production build,
formatting, and Clippy with warnings denied) and all three bounded fuzz
campaigns. The retained fuzz archive is
[13071754522](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41278490909/artifacts/13071754522),
485,276 bytes, SHA-256
`4aa9940a959542bd38177b8392f51c1783f15f8fba7461af36e1bdb573dcbb7b`,
expiring 2026-11-15. These hosted results apply to `50e12fd`; the subsequent
GPT header consistency change below still requires hosted validation.

When both GPT headers and arrays pass their CRCs, the parser now also compares
the disk GUID, usable-LBA bounds, partition count, and entry size. A disagreement
is disclosed without hiding the otherwise usable table. A primary header that
points to a nonterminal backup LBA is rejected, with valid backup fallback
preserved. Regressions independently change the backup disk GUID, usable bound,
entry dimensions, and primary backup reference while preserving valid header/
array CRCs. `npm run validate` passed locally with 38 core tests, 75 desktop
tests (3 ignored), formatting, and Clippy with warnings denied. Hosted CI run
[41359888423](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41359888423)
for commit `471d8c9a17eba8b99d764a5b625d18af47c45a68` passed Windows validation
(38 core tests, 75 desktop tests with 3 ignored, production build, formatting,
and Clippy with warnings denied) and all three bounded fuzz campaigns. The
retained fuzz archive is
[13104514952](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41359888423/artifacts/13104514952),
474,257 bytes, SHA-256
`c1eaa2f7945fc222420382152b9d9eae6472e731a2e51c9490b607aeed2abbd4`,
expiring 2026-11-15.

The parser now rejects a primary GPT header whose last usable LBA lies outside
the image. A CRC-valid malformed-header regression confirms rejection while
retaining valid backup fallback. The local `npm run validate` passed with 39
core tests, 75 desktop tests (3 ignored), formatting, and Clippy with warnings
denied. Hosted CI run
[41360879156](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41360879156)
for commit `43bec04506a3f688068cc93fea2a2345ad9c3251` passed Windows validation
(39 core tests, 75 desktop tests with 3 ignored, production build, formatting,
and Clippy with warnings denied) and all three bounded fuzz campaigns. Its
retained fuzz archive is
[13104879644](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41360879156/artifacts/13104879644),
538,886 bytes, SHA-256
`ee93626cc5c10b90e20bab929e206d1eee0fc77ef3e87b1b5f7180a6d843e098`,
expiring 2026-11-15.

The NTFS core crate now also contains an unexposed FAT32 volume mapper and
bounded live-directory enumerator. It validates partition bounds and FAT32
geometry, resolves fragmented cluster chains, rejects cycles, free/reserved/bad
clusters, insufficient chains, and disagreement between mirrored FAT copies,
and reads requested file ranges without buffering whole files. Directory
enumeration retains each raw short-name record and its source offset, and
reconstructs an LFN only when its sequence, checksum, and UTF-16 contents
validate. `Volume::open` now uses the same FAT32 BPB checks as partition analysis
and rejects an invalid or metadata-conflicting declared backup boot sector.
Bounded live tree traversal reconstructs validated long names and rejects
directory cross-links. A separate API exposes deleted short-name records while
keeping the default live-tree scan unchanged. The contiguous deleted-file
mapper verifies every expected cluster is still free in all mirrored FATs and
returns an explicit `ContiguousAssumed` layout marker; this is not a full FAT
allocation map. When mirroring is disabled, the declared active FAT is used,
and the primary and backup boot records must agree on those FAT-selection
flags. FAT32 is still not integrated with Tauri scan persistence, UI, or export.
Synthetic 65,525-cluster images verify fragmented reads, malformed
chains, nested live/deleted entries, LFN checksum/order fallback, deleted-LFN
isolation, conservative contiguous mapping, active-FAT selection, and
invalid/conflicting backup sectors. `npm run validate` passed locally with 47
core tests, 75 desktop tests (3 ignored), frontend production build, formatting,
and Clippy with warnings denied. Hosted run
[41364446590](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/41364446590)
passed all three parser fuzz campaigns on commit `7bf9c4202adea91c502830537280825c42a13f57`.
The partition-image campaign now traverses a virtual FAT32 directory tree and
attempts deleted-file mapping while mutating entry records and mirrored FAT
metadata. Windows validation passed for that same commit, including the
frontend production build, Rust tests, formatting, and Clippy. The complete
workflow concluded successfully.

## 2026-11-01 native FAT32 directory examination

Connected the bounded read-only FAT32 directory walker to the native case workflow. Scans require an active hashed evidence source and audited active case, recheck the source hash after enumeration, and transactionally store the boot-sector metadata, raw-provenance directory snapshot, counts, snapshot digest, and corresponding audit event. Archived rows are returned only after validating the complete audit chain, snapshot digest, offsets, counts, and one-to-one row/audit relationships. Active paged results are rebound to the currently open source ID, case, and digest. Snapshot JSON is capped at 48 MiB before persistence. The UI reports that FAT32 results are inventory only, file recovery/export is not available, and cancellation becomes available during the complete-source recheck after directory enumeration.

Case report schema is now `daemoncore-case-report-v2`; it includes verified FAT32 directory snapshots and source-digest comparison, and report prepare/complete audit events include FAT32 scan and directory-entry counts. This report version change is explicit so consumers can distinguish the added schema. Legacy database migration coverage checks creation of the FAT32 snapshot table.

Added coverage for atomic scan/audit persistence, snapshot tampering, duplicate/orphan audit references, report inclusion, and legacy database migration. Focused tests passed. Full `npm run validate` passed locally on Windows: frontend production build, 47 core tests, 79 desktop tests (3 ignored), formatting, and Clippy with warnings denied. Rust emitted only the host's existing incremental-cache hard-link fallback warning.

This does not qualify FAT32 file recovery, exFAT directories/recovery, independent formatted FAT32/exFAT images, representative large-volume performance, or the Windows installer. The app was not relaunched, this build was not signed or packaged, and this change is not production qualification.
The optimized Windows Rust application also built successfully for this commit with `cargo build --manifest-path src-tauri/Cargo.toml --release --offline`. The resulting `src-tauri/target/release/daemoncore.exe` is 13,473,280 bytes, SHA-256 `77a58a7a0bff779b085bed0f98e314de902d2ad2d43bef5bfbda58504bd6c1fa` (the executable was not launched or signed).

## 2026-11-01 published FAT32 reference image

Added an opt-in core regression using the University of Virginia CS 4414 Spring 2022 `testdisk1.raw` image and its separate expected-file dump. The published assignment describes its multi-cluster root, nested folders, contiguous `GAMECOPY.TXT`, and noncontiguous `GAMEFRAG.TXT`; the test confirms 1,000+ root entries, reads those files and nested `A99/CONGRATS.TXT`, compares exact bytes to the separate expected dump, and checks contiguous versus fragmented cluster mappings. The local test passed against the downloaded artifacts.

Pinned provenance and hashes are recorded in `src-tauri/tests/fixtures/FAT32-UVA-REFERENCE.md`. The CI workflow downloads the two source archives, verifies both archive SHA-256 values and the extracted 256,098,304-byte image hash, then runs the ignored reference regression. The raw image and expected dump are not committed. The assignment does not state formatter provenance or a separate license for the artifacts; this is useful independent reader validation, not proof of deleted-file recovery or broad media qualification.
## 2026-11-02 limited FAT32 deleted-file export

Connected selected FAT32 deleted short-name entries to the existing destination safety checks, recovery package writer, audit log, progress/cancellation monitor, and recovery-package verifier. Export requires the currently hashed source and the exact active scan, re-reads and compares each selected directory record, uses only a contiguous cluster range whose current allocation entries are free, rejects overlapping ranges among the selected entries, rehashes the full source before and after the export, stages files as new partials, verifies destination SHA-256 before no-replace publication, and writes manifest/inventory/summary/checksum/completion files. The manifest records the raw directory-record digest and explicitly marks the cluster layout as contiguous-assumed. The UI warns that FAT32 discards deleted chain history, that fragmented files may be reconstructed incorrectly, and that selected-set overlap checking is not exhaustive across unselected deleted entries. The existing package verifier now validates FAT32-specific geometry and provenance claims.

Three deterministic native regressions pass: exact bytes are recovered into a package accepted by the independent package verifier; a candidate whose clusters are allocated is not exported and yields a partial package; and two selected deleted entries that claim overlapping free clusters are both rejected. `npm run validate` passed on Windows with the frontend production build, 47 core tests (2 ignored), 82 desktop tests (3 ignored), formatting, and Clippy with warnings denied. Rust emitted the existing incremental-cache hard-link fallback warnings only.

This is limited FAT32 deleted short-name recovery, not general FAT32 recovery. The exporter has not yet been exercised with an independently formatted/deleted image or through the packaged native UI; the separate ignored mtools/Sleuth Kit regression currently validates core cluster mapping only. It does not recover deleted long names, reconstruct historical fragmented chains, or establish original file-content integrity. exFAT recovery, signature carving, physical-device acquisition, RAID reconstruction, independently anchored reports, and production qualification remain open.

## 2026-11-02 audited hex pattern search

Expanded the read-only Hex Inspector from single-page byte reads to operator-scoped hexadecimal pattern searches. Searches require a previously hashed evidence source, validate the requested range against image bounds, cap each operation at 1 GiB and 10,000 reported matches, and use a linear-time matcher across 1 MiB read boundaries. The audit chain records the source/range, pattern digest, match count, digest of the complete ordered offset list, and up to the first 100 offsets. A changed source is marked compromised. The UI presents result offsets as direct links to the 512-byte hex view.

Two native regressions cover overlapping matches, a pattern split at the read-block boundary, invalid patterns, and out-of-bounds ranges. `npm run validate` passed on Windows with the frontend production build, 47 core tests (2 ignored), 84 desktop tests (3 ignored), formatting, and Clippy with warnings denied. This validates the search implementation against synthetic data; it is not a packaged UI smoke test or large-image performance qualification. Search cancellation/resume, annotations, comparison, and export are still open.

## 2026-11-02 validated PNG carving and case-report v3

Added a whole-image PNG carving path that requires the active evidence record to have a persisted SHA-256. The scanner hashes the complete source while reporting real byte progress and honoring cancellation, detects PNG signatures across read-block boundaries, bounds each candidate to 128 MiB and each chunk to 64 MiB, validates chunk CRCs and PNG chunk order, and decodes the image with a 256 MiB decoded-output limit. It retains up to 10,000 candidates while continuing source coverage, marks a capped candidate set incomplete, and does not claim the file was deleted or recover its original path or metadata. Completed scans persist their candidate JSON, source digest, coverage count, and snapshot hash transactionally with the chained audit event; report generation cross-checks those records and now emits `daemoncore-case-report-v3` with carving snapshots.

Selected candidates can be exported to a different physical disk. Export rechecks the complete source digest, revalidates each PNG against the scan record, writes offset-derived names to a new package using no-replace publication, hashes staged and published bytes, and records a completion marker plus a checksummed inventory. Synthetic regressions exercise decoded PNG detection across the 1 MiB scan boundary, CRC corruption rejection, cancellation without partial results, no-replace export and hashes, and audited report inclusion.

## 2026-11-02 PNG carving package verification

Extended the native recovery-package verifier to recognize signature-carving packages. It validates the strict manifest schema and source/candidate metadata, requires inventory rows to match selected offsets and source digests, checks successful output size and hashes, rejects missing or unlisted files, verifies the checksum-list digest and completion state, and requires the before/after source digest to agree for completed exports. The existing recovery workspace folder-verification action now accepts these carving packages as well as filesystem recovery packages. The carver integration test verifies a newly exported PNG package, then changes the recovered output and confirms verification fails.

`npm run validate` passed on Windows: frontend build, 47 core tests (2 ignored), 89 desktop tests (3 ignored), formatting, and Clippy with warnings denied. Remaining carving work includes PDF/JPEG/Office formats, unallocated-region classification, deleted-file determination, original metadata reconstruction, independent carving corpora, and representative large-image performance. The UI was built but not run in the packaged native application; this validation does not qualify a production release.

## 2026-11-02 bounded BMP carving

Extended the full-image scanner to recognize BMP files alongside PNG. BMP validation is deliberately structural: it accepts supported Windows DIB headers, bounds file size and pixel count, validates dimensions/planes/bit depth/compression, checks row-stride and pixel-array arithmetic, and requires palette/mask metadata and declared pixels to fit the file. It does not decode BMP pixels, and unsupported compression or headers are rejected. BMP candidates retain offsets, lengths, and SHA-256 through persisted scans, reports, export manifests, and native package verification.

The synthetic regression places a BMP signature across the 1 MiB scan boundary, verifies export bytes and the native package, and rejects zero-width and truncated files. `npm run validate` passed on Windows with the frontend build, 47 core tests (2 ignored), 90 desktop tests (3 ignored), formatting, and Clippy with warnings denied. This adds one bounded format; it does not qualify external carving performance or broader format coverage.

## 2026-11-02 physical-device identity and acquisition lifecycle

The Windows Disk Imaging panel is connected to raw physical-device acquisition. Device enumeration reads drive geometry and queries the bounded Windows storage-device descriptor for vendor, product, revision, serial, and bus type. Missing or malformed identity data is disclosed in the device row and retained as an identity-query limitation in the manifest; `PhysicalDriveN` is not presented as a stable identity. Acquisition requires an audited active case, operator attestation of an offline source and validated hardware write blocker, and a destination proven to be on a different physical disk. Complete images are hashed on write and re-read, then registered as case evidence and activated; read-error images contain zero-filled unreadable ranges and are explicitly marked partial and not activated. Audit events bind the device descriptor and acquisition outcome. The built-in package verifier re-hashes the image, validates the manifest/checksum/completion relationship, checks ordered aligned error ranges against image geometry, and rejects missing or unlisted package entries. The Disk Imaging panel exposes this verifier and indicates while image and package records are being checked.

Eight focused Windows tests passed for descriptor parsing and malformed offsets, complete package bytes and hashes, partial-image error mapping/zero fill, cancellation cleanup, complete/partial package verification, rejection of a modified image, extra package files, and forged out-of-bounds error ranges with rebuilt checksums. `npm run validate` passed on Windows with the frontend production build, 47 core tests (2 ignored), 98 desktop tests (3 ignored), formatting, and Clippy with warnings denied. These synthetic tests do not exercise real device IOCTLs, hot-plug races, an external write blocker, destination disk topology on representative hardware, crash recovery, or an independently implemented acquisition-package verifier. Physical acquisition is not production-qualified.

## 2026-11-02 operator-configured RAID 0/1 reconstruction

The RAID Reconstruction sidebar route is connected to a bounded native workflow. Operators select member images and their logical order, data offset, sector size, and (for RAID 0) stripe size. The engine rejects duplicate members, unsupported levels/geometries, unequal member data regions, and RAID 1 members whose selected regions do not match exactly. It opens source images read only, hashes members before and after reconstruction, writes a derived `image.raw` into a staging package, reads back and hashes the output, writes manifest/checksum/completion records, and publishes without replacing an existing package. The command requires an audit-matched active case and a destination separate from every member, audits start/cancel/failure/publication, then registers the output as case evidence. Package verification checks manifest geometry, output digest, checksums, completion, and exact inventory; successful verification is recorded as `raid_package_verified`.

Four synthetic tests cover RAID 0 member order and stripe layout plus package tamper detection, matching and mismatching RAID 1 data, and cancellation cleanup. `npm run validate` passed for this slice: frontend production build, 47 core tests (2 ignored), 102 desktop tests (3 ignored), formatting checks, and Clippy with warnings denied. This is not physical-array qualification: metadata auto-detection, RAID 4/5/6 parity, degraded/stale mirror selection, independent implementation comparisons, packaged native UI smoke, and representative array validation remain open. The feature is limited and is not production-qualified.

## 2026-11-02 report imaging and RAID provenance

Case report v4 now includes the case's physical-device acquisition and RAID audit events with audit record ID, timestamp, event name, record hash, and original JSON payload. It scopes inclusion by the payload's case ID and has limits of 2,000 included events, 1 MiB per event, and 16 MiB combined operation payload. The Reports screen describes this scope and the limitation: these copied local audit records do not independently prove device identity, write-blocker conditions, array geometry, or recovery correctness. This closes the prior report gap where imaging/RAID work could occur without appearing in the case report, but report signatures/external anchoring and independent hardware/array qualification remain open.

The focused case-report suite passes 7 tests, including a new regression that includes acquisition/RAID events for the selected case and excludes another case's operation. `npm run validate` passed on Windows after the change: frontend production build, 47 core tests (2 ignored), 105 desktop tests (3 ignored), formatting checks, and Clippy with warnings denied. No new packaged UI smoke test has been performed.

## 2026-11-02 bounded JPEG carving and verified export

The full-image scanner now recognizes JPEG SOI markers, parses bounded marker segments and entropy-coded scans through EOI, rejects malformed/truncated structures, and requires successful JPEG pixel decoding before registering a candidate. Width/height limits, decoded-output limits, 128 MiB candidate bounds, and a 1,000-scan cap constrain work. The JPEG candidate retains exact offset, encoded length, and SHA-256. Selected export revalidates the source candidate and decoder result, then publishes into the same no-replace hashed package flow; the native verifier accepts the JPEG-specific validation claim and `.jpg` name.


## 2026-11-02 acquisition terminal audit outcomes

Physical imaging now records hash-chained terminal events for cancellation, capture failure, and failures after package publication. Post-publication failures include the image digest, package path, read-error count, and whether publication itself was audited, distinguishing a case-registration problem from a publication-audit problem. If the blocking worker terminates unexpectedly, the event explicitly states that publication state is unknown. If writing these events also fails, the command returns that audit failure with the original error and sets the job to failed rather than reporting cancellation/success. Case reports include these terminal events.

A native regression writes cancellation, failure, and finalization-failure events through the production event recorder and verifies the resulting audit chain. `npm run validate` passed on Windows: frontend build, 47 core tests (2 ignored), 106 desktop tests (3 ignored), formatting checks, and Clippy with warnings denied. Hardware acquisition and post-publication failure injection remain untested on physical devices.

## 2026-11-02 exFAT live directory analysis

The core now validates exFAT main/backup boot regions, active FAT and allocation bitmap metadata, the compressed up-case table, entry-set checksums, filename hashes, and allocated streams before enumerating live files and directories. It handles zero-length directories and contiguous directory allocations while retaining source offsets and raw entry sets. The Filesystem Analysis screen accepts a volume byte offset, runs the native read-only inventory, rehashes the complete source before committing, and stores the snapshot and audit event. Case Management now lists completed exFAT scans and provides read-only archived paging after verifying the audit chain, snapshot digest, and matching audit record. Case report v5 includes exFAT snapshots and verifies their digest/audit association. This is live directory inventory only: deleted exFAT recovery, independent exFAT media validation, damaged-volume fuzzing, and packaged native UI verification remain incomplete.

The controlled synthetic exFAT image test opens a valid volume and reads a root file entry; focused tests also cover compressed up-case decoding, malformed tables, checksums, end markers, and empty directories. Backend regressions verify archived snapshots and reject modified content and orphan audit records. `npm run validate` passed on Windows after the initial integration: frontend build, 53 core tests (2 ignored), 107 desktop tests (3 ignored), formatting checks, and Clippy with warnings denied. This does not qualify the implementation for forensic casework until independent media fixtures and packaged operation tests pass.

## 2026-11-02 archived exFAT scan review

Case Management now loads audited exFAT scan sessions on case selection and renders read-only, paginated entry snapshots with the recorded source digest and evidence-match status. The backend verifies the complete audit chain, matches every persisted snapshot to exactly one audit record, recomputes snapshot digests, and refuses orphan audit records or tampered database contents before returning a saved page. Regression tests cover valid archive listing, snapshot tampering, and orphan records. `npm run validate` passed after this change: frontend build, 53 core tests (2 ignored), 109 desktop tests (3 ignored), formatting checks, and Clippy with warnings denied. This still needs independent exFAT media and packaged native UI qualification.


## BMP pixel decoding hardening — 2026-11-02

BMP carving now requires a successful pixel decode after header, geometry,
mask, palette, and pixel-array bounds checks. The decoder reads through a
bounded source-range reader, limits dimensions to 32,768 pixels per side, and
rejects decoded buffers above 256 MiB before allocation. Source I/O errors
propagate as scan failures instead of being treated as invalid candidates. A
regression fixture with valid geometry but missing bitfield masks is rejected;
the existing valid BMP scan-boundary/export/package-verification test remains
the positive path. Older persisted BMP snapshots retain compatibility with
their original validation label; export revalidates their bytes through the new
decoder. A Pillow 11.3.0-generated 16 × 12 BMP fixture is independently
decoded by Pillow and checked by the carver against an exact 630-byte
length and SHA-256. The missing-bitfield and independent-fixture focused
tests passed; Windows `npm run validate` passed with 116 desktop tests and 5 intentionally ignored. This
closes the BMP decode gap, but broader BMP corpus and performance
qualification remain open.


## Full-member RAID 5 parity validation — 2026-11-02

RAID Reconstruction now supports operator-configured full-member RAID 5 using the
left-symmetric layout. Every stripe row identifies the rotating parity member,
places data in logical order beginning after parity, recomputes XOR parity, and
refuses publication if parity differs. This does not rebuild a missing member or
identify on-disk vendor metadata; the operator must provide the correct member
order, data offset, sector size, and stripe size.

The mapping matches Linux MD's reference formula: parity index is
`data_disks - (stripe_row mod raid_disks)`, and left-symmetric data starts after
the parity member. The package manifest records this layout and parity check. The
recovery package verifier checks RAID 5 member count, geometry, stripe size, output
size, and layout declaration. Synthetic regressions cover a complete three-row parity rotation,
logical data order, exact output size, progress totals, package verification, parity
mismatch rejection, and removal of unpublished staging output. Independent array
fixture validation is now part of the Windows/Linux workflow: Linux MD creates a
loop-backed array, writes and reads a known logical image, and pins its SHA-256.
Windows CI reconstructs from the captured member data and compares exact bytes.
Hosted run [43666164749](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43666164749)
passed the independent Linux MD fixture reconstruction and byte comparison. The
fixture validates data layout only; it strips metadata outside the captured
component extents. Vendor metadata discovery and degraded reconstruction remain
open.

## Disk acquisition sector-level retry

Failed 1 MiB reads now retry three times, then split into smaller sector-aligned
reads down through the device-reported sector size. Only sectors still
unreadable after retries are zero-filled and recorded; adjacent failures with
the same error are coalesced. Windows `ERROR_NOT_READY`, `ERROR_DEV_NOT_EXIST`,
`ERROR_DEVICE_UNREACHABLE`, and `ERROR_DEVICE_NOT_CONNECTED` stop acquisition and remove unpublished
staging data rather than treating a disconnected source as unreadable media
([Microsoft error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499/), [device error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299/)). Regressions verify
readable sectors around a bad sector are preserved, the bad sector is mapped
precisely, a disconnected source publishes no image, and the package verifier
accepts the updated acquisition-method declaration. These simulated faults do
not qualify physical media behavior or write-blocker hardware.

## Partial acquisition package verification — 2026-11-15

The acquisition verifier previously required every unreadable range to start on
a 1 MiB boundary and span the full capture chunk. That rejected correctly
captured partial images when only an interior sector was unreadable. It now
accepts non-overlapping ranges aligned to the device sector size, bounded to one
capture chunk and the image extent; sector geometry is constrained to the
supported 512–65,536 byte range. The regression captures a 1 MiB fixture with a
single unreadable 512-byte sector, confirms surrounding bytes remain intact,
then verifies the published package as partial with one failed range.

`npm run validate` passed: frontend build, formatting, 54 core tests passed (3
ignored), 123 desktop tests passed (6 ignored), and both Clippy checks completed.
These are local Windows fixture tests, not physical-device qualification.

Hosted run [43664566586](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43664566586)
for commit `f1a477b` confirmed the independent exFAT validation and Linux FAT32
fixture generation/mapping steps passed. The FAT32 and Linux MD RAID fixture
artifact uploads failed because the repository Actions artifact storage quota
was exhausted; dependent Windows integration checks were skipped. Linux MD
array creation and known-image hash checks passed. At the time of this record,
the parser fuzz campaigns were still running, so the hosted run does not prove
all validation gates.

## Hosted baseline validation after fixture-job split — 2026-11-15

Run [43664981029](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43664981029)
used commit `ed69228`. The regular Windows job no longer waits on generated
fixture uploads; it completed `npm run validate`, the independent multi-cluster
FAT32 image test, and the independent exFAT carving-content test. ExFAT volume
inventory and the three MFT, whole-image NTFS, and partition-image fuzz campaigns
also passed.

The Linux FAT32 deletion fixture was independently checked with Sleuth Kit and
matched the core mapper's expected bytes. Linux MD created the RAID 5 reference
array and verified its known logical-image hash. Both fixture uploads failed
because the Actions artifact storage quota was exhausted; the dedicated Windows
reference job was skipped. The overall workflow therefore concluded failure,
and Windows package export against the deleted FAT32 fixture and Windows RAID 5
reconstruction against Linux MD member data remain unverified. Splitting the jobs
keeps ordinary Windows validation visible but does not replace those reference
checks.

## Cross-OS forensic reference fixtures — 2026-11-15

Run [43666164749](https://github.com/DaemoncoreApps/DataRecovery/actions/runs/43666164749)
passed all six jobs. The independently generated FAT32 deleted-file fixture and
Linux MD RAID 5 reference members were saved under run-and-attempt-scoped GitHub
Actions cache keys, restored by Windows with cross-OS archives enabled, then
checked against their expected SHA-256 values before use. This avoids the
exhausted workflow-artifact quota while retaining an exact-hash gate on the
transferred data.

The Windows reference job reconstructed the Linux MD RAID 5 logical image and
matched exact bytes. It also exported the FAT32 deleted file and matched the
independent Sleuth Kit expected bytes. Baseline Windows validation, independent
FAT32 multi-cluster reading, exFAT inventory and carving checks, and all three
bounded parser fuzz campaigns passed in the same workflow. This closes the
cross-platform reference fixture handoff gate; physical-device acquisition,
degraded RAID, installer lifecycle/signing, large-scale performance, and broader
damaged-media qualification remain open.

## 2026-11-14 printable case report and acquisition failure retention

The Reports export now offers JSON and a print-friendly HTML rendition. The HTML
contains a human-readable evidence and audit summary plus the complete canonical
JSON report, escapes case-controlled text, applies a restrictive content
security policy, and uses the existing staged no-replace publication and audit
hash path. Eleven case-report Rust tests pass, including a malicious-title
escaping check; the frontend production build passes. Native Windows save-dialog
and generated-file viewing checks remain outstanding.

Acquisition staging is retained after an ordinary error once image output has
started, receives an `INCOMPLETE.txt` warning, and its path is returned in the
job error; the normal package verifier rejects this unpublished folder. User
cancellation continues to remove staging. All twelve acquisition tests pass.
This does not provide resume support or guarantee recovery of bytes after abrupt
power loss.

RAID reconstruction now follows the same failure rule: if a failed reconstruction
has written image bytes, the staged image is retained, a clear incomplete marker
is attempted and read back, and marker validation failures are disclosed with the
staging path. The ordinary package verifier rejects the staged directory. User
cancellation explicitly removes staging, including when cancellation occurs after
output writing begins. Eight RAID tests pass, with the independent Linux MD
reference test skipped locally because its fixture is provided by hosted CI.

NTFS and FAT32 package export errors now include the path when a recovery folder
was created, and label that output unverified until the package verifier accepts
it. This makes interrupted or failed workspace exports locatable while keeping
their existing incomplete manifest and completion-marker rules. Seven recovery
tests pass, including path reporting and rejection of an empty incomplete folder.

Carving export failures follow the same operator-facing rule: if a package
folder was created, the error includes its location and requires verification
before retained output is used. The regression confirms the incomplete folder
fails package verification.
An additional integration regression injects a failure during the final source
stability recheck after a real carved file has been written; the export error
includes the actual staged package path, and the verifier rejects that package.

The full-image carving loop now reuses its 1 MiB read buffer and signature
window across chunks to avoid repeated large allocations. All 12 runnable
carving tests pass, including signatures split across a chunk boundary. This
reduces allocation churn; representative large-image throughput and memory
benchmarks remain open.

Physical acquisition errors now check whether the best-effort `INCOMPLETE.txt`
marker can be read back as valid before presenting the retained staging path.
When marker creation is deliberately blocked, the operator error explicitly
reports that condition, and the ordinary verifier rejects the staging folder.
The full `npm run validate` passes on Windows: frontend typecheck/build, 54
core tests (3 ignored), 129 desktop tests (6 ignored), formatting, and Clippy
with warnings denied.

The exFAT directory walker now enforces estimated 128 MiB per-directory parse,
256 MiB complete-tree result, and 2,000,000 visited-cluster limits. It releases
parent directory buffers before visiting child directories. A nested-directory
regression verifies path reconstruction through the deferred traversal. The
full `npm run validate` passes on Windows: frontend build, 55 core tests (3
ignored), 129 desktop tests (6 ignored), formatting, and Clippy with warnings
denied. The independent exFAT volume test remains available in hosted CI.

RAID reconstruction now verifies the retained incomplete marker after an operation error. If it is missing, unreadable, or does not match the expected warning, the returned error explicitly tells the operator and includes the staging path. An injected marker-path obstruction regression passes. The full `npm run validate` passes on Windows: frontend typecheck/build, 55 core tests (3 ignored), 130 desktop tests (6 ignored), formatting, and Clippy with warnings denied. This confirms error reporting only; abrupt power-loss durability and process-kill recovery remain unqualified.
