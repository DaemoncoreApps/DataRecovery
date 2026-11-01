# Capability and release matrix

The product brief's 16 release acceptance criteria and their current evidence
are tracked in [PRODUCTION_GATE_AUDIT.md](PRODUCTION_GATE_AUDIT.md).

| Area | Working now | Production work remaining |
|---|---|---|
| Sources | Local raw image selection, stable read-only handles, offset reads, fail-closed size/timestamp checks | Physical discovery, device capabilities, helper, health/error maps |
| Partitions | MBR/GPT/EBR inspection, CRC checks, backup fallback | Lost partition detection and virtual reconstruction |
| Webview | Packaged CSP allows only local app resources and Tauri IPC; inline scripts default-blocked by `default-src`; production inline styles removed; object embedding and framing denied | Native WebView CSP runtime verification, third-party dependency review, privileged-account and hostile-input testing |
| NTFS | Deleted base records; initialized-size-bounded complete MFT records; resident/uncompressed nonresident/sparse streams; signed runlists; allocation checks; extraction; sequence-validated parent chains and restored directory-tree exports; ambiguous same-namespace filename or parent references fall back to flat exports; decoded base-record `$FILE_NAME` references and those explicitly referenced in a validated `$ATTRIBUTE_LIST` are retained with record/sequence, namespace, and attribute ID in scan snapshots, inspector, audit, and export manifest/inventory; bounded resident and nonresident `$ATTRIBUTE_LIST` resolution for unnamed `$DATA` extents, matching attribute instance IDs and following list continuations in referenced extension records | Independently formatted attribute-list and hard-link fixtures, broader malformed-input coverage, and reporting for extension-record names not explicitly referenced by the list; compression, named streams, `$I30` index reconstruction, MFT mirror/USN, content validation, and deep-path fixture coverage |
| FAT32/exFAT | Boot signature observations | Real directory/allocation parsing and recovery |
| Carving | No operational carving engine | Signature registry, validators, scan coverage, checkpoints |
| Acquisition | Image SHA-256 | Raw imaging, independent acquisition verification, resume, splits, error maps |
| RAID | No operational modes | Validated virtual RAID 0/1, then parity modes |
| Hex | Bounded offset reads and ASCII display | Search, annotations, comparisons, export ranges, decoders |
| Recovery | Paged/filterable NTFS candidates, mandatory source SHA-256, post-scan/export source rechecks, per-file destination hashes, checksummed inventory, no-overwrite publication, native recursive export-folder verifier, transactional persistence of completed scan summaries and candidate snapshots, integrity-checked read-only browsing of archived candidates, case/evidence/scan IDs in recovery manifests and audit events, directory-tree exports for sequence-verified paths with explicit flat fallback metadata | Reactivate archived scans for recovery, durable export queues, signed/external evidence package, content validators, broader filesystem fixtures, large-export progress/cancellation |
| Evidence | Chained audit events, fail-closed writes on detected tampering, SQLite quick-check before schema changes, internal verification, on-disk checkpoint verification before no-replace publication, live database and checkpoint comparison to an operator-supplied independently retained head hash, transactional case-owned source records and hash state, persisted scan candidate snapshots, and case-bound recovery export records | Digitally signed anchors, authenticated anchor provenance, tamper-evident evidence database reconciliation and recovery of archived scans |
| Cases | Persistent title/examiner register, creation-event reconciliation for audited cases, legacy rows explicitly marked unverified, active-case pointer reconciliation and audited correction path, evidence-open gate, evidence-source and completed-scan inventory visible in case management, archived candidate review | Full case lifecycle, import/export integrity, notes, timelines, scan reactivation, and external integrity anchors |
| Reports | Recovery manifest and JSONL inventory | Forensic HTML/PDF/CSV/JSON reports |
| Settings | Actual fixed engine defaults displayed | Persisted, validated editable profiles |
| Distribution | Buildable Windows executable; unsigned x64 NSIS and MSI bundles with embedded offline WebView2 runtime both build | NSIS install/update/uninstall verification, trusted code signing, update policy and Store submission, packaged tests, accessibility and release performance validation. The generated MSI is not qualified: WiX ICE40, ICE57, and ICE61 warnings remain, including mixed per-user/per-machine shortcut registry state. Microsoft Store accepts MSIX and signed EXE/MSI routes; Tauri documents its current Store flow through EXE/MSI, while MSIX requires a separate packaging path. |

A feature is supported only to the scope in the Working now column. No product
release should describe this matrix as complete. The original production brief
remains the target.

## Hard release gates

- Independently verified deleted-file fixtures across NTFS, FAT32 and exFAT.
- Sustained coverage-guided campaigns for record parsing and whole-image
  attribute-list resolution, with corpus retention and artifact triage. One
  bounded 1,000,000-input run covers `parse_record`; a separate whole-image
  `scan` target and three validated synthetic seeds now cover the reader paths
  in the test suite, but that target still needs a coverage-guided campaign.
- Real damaged images, overwrite/TRIM cases, Unicode/deep paths, large images.
- Restricted-account tests, representative large-image exports, and failure/crash recovery.
- Source-protection, failure recovery and crash/resume verification.
- Device/helper and Microsoft Store deployment-policy review. Microsoft accepts
  MSIX or signed EXE/MSI submissions. Its EXE/MSI path requires a standalone,
  offline, silent installer, versioned HTTPS package URL, and publisher signing;
  updates remain the publisher's responsibility. Tauri's Store guide currently
  describes the EXE/MSI route. See the linked policy evidence in
  `VERIFICATION.md`.
- Installer/package testing, signing, accessibility and performance benchmarks.
