# Capability and release matrix

The product brief's 16 release acceptance criteria and their current evidence
are tracked in [PRODUCTION_GATE_AUDIT.md](PRODUCTION_GATE_AUDIT.md).

| Area | Working now | Production work remaining |
|---|---|---|
| Sources | Local raw image selection, stable read-only handles, offset reads, fail-closed size/timestamp checks | Physical discovery, device capabilities, helper, health/error maps |
| Partitions | MBR/GPT/EBR inspection; GPT revision, reserved field, disk GUID, on-disk header locations and primary/backup references, in-image usable LBA bounds, UEFI entry-size constraints, role-specific primary/backup entry-array placement, redundant-header identity/range/dimension consistency warnings, unique partition GUID reporting and zero/duplicate checks; CRC checks and backup fallback | Lost partition detection and virtual reconstruction; independent damaged-disk fixture validation |
| Webview | Packaged CSP allows only local app resources and Tauri IPC; inline scripts default-blocked by `default-src`; production inline styles removed; object embedding and framing denied | Native WebView CSP runtime verification, third-party dependency review, privileged-account and hostile-input testing |
| NTFS | Deleted base records; initialized-size-bounded complete MFT records; resident/uncompressed nonresident/sparse streams; signed runlists; allocation checks; extraction; sequence-validated parent chains and restored directory-tree exports; ambiguous same-namespace filename or parent references fall back to flat exports; decoded base-record `$FILE_NAME` references and those explicitly referenced in a validated `$ATTRIBUTE_LIST` are retained with record/sequence, namespace, and attribute ID in scan snapshots, inspector, audit, and export manifest/inventory; bounded resident and nonresident `$ATTRIBUTE_LIST` resolution for unnamed `$DATA` extents, matching attribute instance IDs and following list continuations in referenced extension records | Independently formatted attribute-list and hard-link fixtures, broader malformed-input coverage, and reporting for extension-record names not explicitly referenced by the list; compression, named streams, `$I30` index reconstruction, MFT mirror/USN, content validation, and deep-path fixture coverage |
| FAT32/exFAT | FAT32 BPB/FAT-capacity/cluster-bound checks and declared backup boot-sector comparison; bounded live FAT32 directory-tree enumeration with validated LFN reconstruction, raw short-record provenance, and cycle/cross-link rejection; exFAT main and backup boot-region checksums and volume geometry | FAT32 allocation analysis, deleted-entry recovery, Tauri scan/persistence/export integration, exFAT directory/recovery parsing, and controlled independent test images |
| Carving | No operational carving engine | Signature registry, validators, scan coverage, checkpoints |
| Acquisition | Image SHA-256 | Raw imaging, independent acquisition verification, resume, splits, error maps |
| RAID | No operational modes | Validated virtual RAID 0/1, then parity modes |
| Hex | Bounded offset reads and ASCII display | Search, annotations, comparisons, export ranges, decoders |
| Recovery | Paged/filterable NTFS candidates, mandatory source SHA-256, post-scan/export source rechecks, per-file destination hashes, checksummed inventory, no-overwrite publication, native recursive export-folder verifier, transactional persistence of completed scan summaries and candidate snapshots, integrity-checked read-only browsing of archived candidates, archived evidence reopen only after full SHA-256 verification with audited start/outcome (mismatches mark the evidence record compromised), case/evidence/scan IDs in recovery manifests and audit events, directory-tree exports for sequence-verified paths with explicit flat fallback metadata | Fresh scan still required after archived evidence reopens; scan checkpoints and resume, durable export queues, signed/external evidence package, content validators, broader filesystem fixtures, large-export progress/cancellation |
| Evidence | Chained audit events, fail-closed writes on detected tampering, SQLite quick-check before schema changes, internal verification, on-disk checkpoint verification before no-replace publication, live database and checkpoint comparison to an operator-supplied independently retained head hash, transactional case-owned source records and hash state, persisted scan candidate snapshots, and case-bound recovery export records | Digitally signed anchors, authenticated anchor provenance, tamper-evident evidence database reconciliation, and scan checkpoint/resume |
| Cases | Persistent title/examiner register, creation-event reconciliation for audited cases, legacy rows explicitly marked unverified, active-case pointer reconciliation and audited correction path, evidence-open gate, evidence-source and completed-scan inventory visible in case management, archived candidate review and hash-verified evidence reopening | Full case lifecycle, import/export integrity, notes, timelines, scan checkpoint/resume, and external integrity anchors |
| Reports | Case-linked recovery manifest/JSONL inventory and a native JSON case report with archived NTFS candidate snapshots and verified local audit-chain head; each scan explicitly reports whether its source digest matches the current case evidence digest; report states its unsigned/unanchored scope | Signed or externally anchored reports, PDF/HTML/CSV output, acquisition/device logs, and claims of recovered-content integrity |
| Settings | Actual fixed engine defaults displayed | Persisted, validated editable profiles |
| Distribution | Buildable Windows executable; hosted validation passes; a manual hosted NSIS staging workflow built and uploaded a package with a provenance manifest | Install/update/uninstall testing, trusted signing, update policy, Store submission, packaged tests, accessibility, and release performance validation. Historical MSI output is not qualified due WiX ICE40, ICE57, and ICE61 warnings, including mixed per-user/per-machine shortcut registry state. |

A feature is supported only to the scope in the Working now column. No product
release should describe this matrix as complete. The original production brief
remains the target.

## Hard release gates

- Independently verified deleted-file fixtures across NTFS, FAT32 and exFAT.
- Sustained coverage-guided campaigns for record parsing and whole-image
  attribute-list resolution, with corpus retention and artifact triage. Two
  hosted 1,000,000-input runs cover `parse_record`;
  two hosted 120-second campaigns cover whole-image `scan` from three validated
  synthetic seeds. The workflow retains evolved corpora and artifacts, but
  sustained campaigns and independent real-volume fixtures are still required.
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
