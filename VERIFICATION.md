# Recovery validation — 2026-10-31

## Automated checks

- Unified `npm run validate` gate: passed (TypeScript/Vite, Rust format, tests, Clippy).
- Latest `npm run validate` on 2026-10-31 passed: TypeScript/Vite production build, Rust format check, 76 Rust tests passed, 0 failed, 2 ignored, and Clippy with warnings denied.
- Cargo reported that incremental-cache hard links were unavailable and copied cache files instead; the validation command still exited successfully.
- Checkpoint and recovery verifiers reject symlink entries and reparse-point package roots, retain Windows share-read handles for each opened file through verification, and rescan package entries before success. Windows tests cover reparse rejection and confirm concurrent writes and renames fail while a file handle is retained. A directory-handle share restriction did not prevent child creation, so path-based traversal still cannot exclude a transient intermediate-directory swap-and-restore race.
- Latest full `npm run validate` after retained-file verification: 76 Rust tests passed, 0 failed, 2 ignored; frontend build, Rust format, and Clippy with warnings denied passed.
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

That executable launched successfully in the native UI. The Evidence Vault's read-only verifier checked the workstation's 27-event audit chain and reported it internally consistent. It also stated that no independently retained chain-head hash was compared, so a full database rewrite or replacement is not detectable from this check. This smoke check did not use evidence media or exercise recovery export in the current executable; the controlled recovery round trip above was run on an earlier optimized build. Installers, signing, broad forensic validation and the release gates below remain outstanding.

### Unicode recovery-path regression

The nested-path round-trip fixture now includes Japanese characters, a supplementary-plane emoji, and a decomposed combining character in a deleted filename. The Windows test requires the Unicode name to survive NTFS parsing and recovered-file creation, checks the generated nested output path and `path_restored` inventory field, confirms that exact relative path appears in `checksums.sha256`, and runs the recursive package verifier. `npm run validate` passed after this test change: 68 passed, 0 failed, and 2 ignored, with the frontend build, Rust format check, and Clippy with warnings denied also passing. This covers selected Unicode cases; it does not establish broad Unicode or long-path compatibility.

### NTFS resident attribute-list reconstruction

The NTFS reader now parses bounded resident `$ATTRIBUTE_LIST` values and follows unnamed `$DATA` extents into referenced extension MFT records. It checks the list entry's sequence number, the extension record's sequence number and base-record reference, verifies the base record's listed extents, rejects ambiguous extent matches and VCN gaps, and enforces limits of 4,096 list entries, 256 extension records, and 65,536 data runs per stream. Nonresident attribute lists and inconsistent references remain blocked; this is not full NTFS attribute-list support.

A controlled MFT fixture places a 700-byte deleted file across a base record and an extension record. The regression test exports and re-verifies the exact expected bytes, then mutates the extension base sequence, list-entry sequence, VCN, and list form to verify fail-closed behavior. `npm run validate` passed after this work: 69 passed, 0 failed, 2 ignored; the TypeScript/Vite build, Rust format check, and Clippy with warnings denied passed. `npm exec -- tauri build --no-bundle` completed successfully. The optimized executable was staged as `DaemonCore-Data-Recovery-Windows-0.1.0-attribute-list-unsigned.exe`; SHA-256 is `160e7ca06d545a3032fc4bc07ca30fdac9b81a4d084a20a9952a08c9031e3528`. Authenticode reports `NotSigned`. The fixture is synthetic rather than an independently formatted attribute-list image.

The same optimized executable launched in the native Windows UI. The dashboard rendered in read-only mode, and Evidence Vault verification reported 27 records internally consistent. No independent head hash was supplied, so this does not detect replacement or a complete rewrite of the local database. The smoke check did not mount evidence media or run a recovery export.

The refreshed source archive includes the latest verification notes. Its SHA-256 is
recorded in `outputs/SHA256SUMS.txt`. The archive excludes generated `node_modules`,
`dist`, and Rust `target` directories.

### Bounded nonresident NTFS attribute-list support

The first bounded nonresident-list implementation required one complete VCN-zero
mapping in the base record, no unsupported flags or sparse runs, consistent
allocated/initialized lengths, and a maximum size of 16 MiB. Continued nonresident
lists are covered by the later section below.

A synthetic MFT fixture stores the list in a nonresident cluster, reconstructs a
deleted 700-byte file across base and extension records, compares the exact recovered
bytes, and verifies the resulting package. Mutated mappings, oversized lists,
unsupported flags, and a malformed resident/nonresident form do not produce an
exportable candidate. `npm run validate` passed: 71 passed, 0 failed, 2 ignored;
TypeScript/Vite build, Rust formatting, and Clippy with warnings denied passed.
The record parser also has a regression test for its 512-byte update-sequence
stride on 4 KiB-sector geometry, including rejection of a torn 1 KiB record.
Microsoft documents this sequence stride as 512 bytes; the test is not a full 4Kn
volume scan.
This fixture is synthetic and does not independently establish behavior on a
Windows-formatted nonresident attribute list. The first optimized executable
`DaemonCore-Data-Recovery-Windows-0.1.0-nonresident-attribute-list-unsigned.exe`
was built successfully and was later superseded; SHA-256 is
`878de620f60532f6accc1660766fa13784f2fb4bd402af0d8e7a85e01fde9f61`, and
Authenticode reports `NotSigned`. At that stage, this executable had not had a
native UI smoke check; it was later superseded. The earlier documented smoke result
applies to the resident-list executable only.

### Continued nonresident NTFS attribute-list support

The nonresident-list resolver now follows self-references in the bounded list
prefix to read continued `$ATTRIBUTE_LIST` extents from extension MFT records. It
checks each extension record number, sequence, base-record reference, attribute
type/name, and contiguous VCN mapping, then compares the completed list's
self-references against the extents actually read. Limits remain 256 extension
records, 65,536 mapped runs, and 16 MiB of list data; malformed or incomplete
continuations fail closed.

The synthetic fixture places the first list extent in the base record and its next
extent in an extension record that also contains the recovered file's continued
`$DATA`. The test exports the expected bytes, verifies the package, and rejects a
stale list-entry sequence. `npm run validate` passed: 72 passed, 0 failed, 2 ignored;
the TypeScript/Vite build, Rust formatting, and Clippy with warnings denied passed.
The optimized executable `DaemonCore-Data-Recovery-Windows-0.1.0-continued-attribute-list-unsigned.exe`
was built successfully; SHA-256 is
`77b37b239dd7c4b910289cefda1465e5c0cb1240c60fde29bf01014264aeb937`.
Authenticode reports `NotSigned`; a later native startup and audit-screen smoke
check is recorded below. This fixture is synthetic; an independently formatted
continued-list image remains required.

### Native startup and audit screen smoke check

The optimized executable launched in the native Windows UI and rendered the
workspace dashboard. The Evidence Vault opened, and its read-only audit verifier
reported 27 records with an internally consistent chain. No independently
retained head hash was supplied, so the verifier cannot detect a complete
database rewrite or replacement. This smoke check did not exercise evidence
media, scanning, or recovery export. The executable remains unsigned, and the
independently formatted continued-list fixture and other release gates above
remain outstanding.

### Verified staged audit checkpoint publication

Audit checkpoint export now exclusively creates a sibling staging folder,
verifies the serialized on-disk files and full chain against the captured head,
and publishes the folder through a no-replace move. Failed publication removes
the staging folder where possible. A Windows regression test verifies a complete
checkpoint after publication, confirms that a colliding destination keeps its
original contents, and checks that an already occupied staging path is never
removed by a failed acquisition. It also corrupts a staged event stream to
confirm verification rejects the package and cleanup removes the export-owned
staging folder. `npm run validate` passed: 73 passed, 0 failed, 2 ignored;
frontend build, Rust formatting, and Clippy with warnings denied passed. The
optimized Windows executable
`DaemonCore-Data-Recovery-Windows-0.1.0-checkpoint-atomic-r2-unsigned.exe` was
built and staged; SHA-256 is
`72951a38b1dd4c224a575ebb486305d95f71077323ac94aad80ff66065e67e19`.
Authenticode reports `NotSigned`.

On 2026-10-31, that executable launched in the native Windows UI and rendered the
dashboard. Evidence Vault's read-only verifier reported 27 audit records as
internally consistent and displayed head `10669c0ef2dafbf6dd162190df847de7545441c32926f1746820bba4748b06a0`.
No independently retained head hash was supplied, so this does not detect a full
database rewrite or replacement. The smoke check did not open evidence media,
run a scan or recovery export, or validate checkpoint export through the UI.
Signing, packaging, forensic fixtures, and the other release gates remain open.

### Windows installer bundle attempt

On 2026-10-31, `npm run tauri build` completed the production frontend and
optimized Windows executable builds. The first NSIS attempt downloaded and
validated the official NSIS 3.13 archive but could not start `makensis.exe` inside
the restricted process sandbox (Windows error 623, `Illegal System DLL
Relocation`). Re-running the packaging command outside that sandbox with
`bundle.useLocalToolsDir` enabled succeeded. This points to a build-environment
process-mitigation issue rather than a missing or corrupted NSIS download; the
installer has not been tested on a normal user account.

The configured NSIS bundle was then changed to embed WebView2 using Tauri's
`offlineInstaller` mode, so installation does not need to download that runtime.
The generated x64 offline setup is
`DaemonCore-Data-Recovery-Windows-0.1.0-x64-offline-setup-unsigned.exe`,
222,183,617 bytes (211.89 MiB), SHA-256
`bdb39591c6badf0b24c9303f09d92a4d49bc32160f86b5309cb5400258b7ca83`.
The matching rebuilt executable is
`DaemonCore-Data-Recovery-Windows-0.1.0-offline-webview-unsigned.exe`,
12,878,848 bytes, SHA-256
`05f454fd727871f040a3d8c548b293c87e2dbf71f669692abe4a8412bf25abf1`.
Both files are unsigned. The bundle was generated successfully, but the installer
was not launched or installed. A requested native startup smoke was stopped by
the physical Escape key before the app could be inspected. Therefore install,
upgrade, uninstall, packaged runtime behavior, and this build's UI remain
unverified. The audit panel now uses a neutral idle shield, labels the task
"Verify the local audit chain," and explains that internal consistency without
an independently retained head hash cannot detect a complete database rewrite.
The production frontend build passed after this change; the refreshed Windows
installer includes it. A clean `npm run tauri build -- --no-bundle` left the binary's
bundle marker in its expected unbundled state; the following NSIS build patched
it without warning and restored the standalone binary. The app does not currently
include the Tauri updater plugin, so updater installation is not implemented.
The latest release binary and installer also include the no-follow file-opening,
retained file handles, and package rescan described above.
Signing, installer smoke tests, MSIX/Store review, and other release gates remain
open.
