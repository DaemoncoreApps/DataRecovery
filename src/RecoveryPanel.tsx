import { useEffect, useState } from "react";
import {
  ArrowDownToLine,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  HardDrive,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  command,
  native,
  type Source,
  type Job,
  type ScanSummary,
  type RecoveryCandidate,
  type RecoveryExportVerification,
  type RecoveryPage,
  type PartitionReport,
  type Fat32ScanSummary,
  type Fat32Page,
} from "./bridge";
import { bytes } from "./format";

type Props = {
  source: Source | null;
  job: Job;
  busy: boolean;
  run: (f: () => Promise<void>) => void;
  onJob: (job: Job) => void;
};
function filetime(value: string | null): string {
  if (!value || value === "0") return "Not recorded";
  try {
    const milliseconds = (BigInt(value) - 116444736000000000n) / 10000n;
    const date = new Date(Number(milliseconds));
    return Number.isNaN(date.valueOf())
      ? "Invalid timestamp"
      : date.toISOString();
  } catch {
    return "Invalid timestamp";
  }
}
const allocationLabel: Record<string, string> = {
  resident: "Resident bytes",
  unallocated: "Unallocated extents",
  reused: "Extents reused",
  unknown: "Allocation unknown",
};
export function RecoveryPanel({ source, job, busy, run, onJob }: Props) {
  const [offset, setOffset] = useState("0");
  const [partitions, setPartitions] = useState<PartitionReport | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [page, setPage] = useState<RecoveryPage>({ total: 0, rows: [] });
  const [pageIndex, setPageIndex] = useState(0);
  const [query, setQuery] = useState("");
  const [onlyExportable, setOnlyExportable] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [inspected, setInspected] = useState<RecoveryCandidate | null>(null);
  const [loadError, setLoadError] = useState("");
  const [exportVerification, setExportVerification] =
    useState<RecoveryExportVerification | null>(null);
  const [fat32Summary, setFat32Summary] = useState<Fat32ScanSummary | null>(null);
  const [fat32Page, setFat32Page] = useState<Fat32Page>({ total: 0, rows: [] });
  const [fat32Query, setFat32Query] = useState("");
  const [fat32DeletedOnly, setFat32DeletedOnly] = useState(true);
  const [fat32PageIndex, setFat32PageIndex] = useState(0);
  const [fat32Selected, setFat32Selected] = useState<Set<number>>(new Set());
  const working = busy || job.state === "running";
  useEffect(() => {
    setSummary(null);
    setSelected(new Set());
    setPage({ total: 0, rows: [] });
    setPartitions(null);
    setOffset("0");
    setInspected(null);
    setFat32Summary(null);
    setFat32Page({ total: 0, rows: [] });
    setFat32PageIndex(0);
    setFat32Selected(new Set());
    setExportVerification(null);
  }, [source?.id]);
  useEffect(() => {
    if (job.state === "running") setExportVerification(null);
  }, [job.kind, job.state]);
  useEffect(() => {
    if (
      !native ||
      !source ||
      (job.kind === "ntfs_scan" && job.state === "running")
    )
      return;
    let active = true;
    command<ScanSummary | null>("scan_summary")
      .then((result) => {
        if (active && result?.source_id === source.id) setSummary(result);
      })
      .catch((e) => {
        if (active) setLoadError(String(e));
      });
    return () => {
      active = false;
    };
  }, [source?.id, job.kind, job.state]);
  useEffect(() => {
    if (!native || !source || (job.kind === "fat32_scan" && job.state === "running"))
      return;
    let active = true;
    command<Fat32ScanSummary | null>("fat32_scan_summary")
      .then((result) => {
        if (active && result?.source_id === source.id) setFat32Summary(result);
      })
      .catch((e) => {
        if (active) setLoadError(String(e));
      });
    return () => {
      active = false;
    };
  }, [source?.id, job.kind, job.state]);
  useEffect(() => {
    if (!summary || !source || summary.source_id !== source.id) return;
    let active = true;
    setLoadError("");
    command<RecoveryPage>("scan_results", {
      sourceId: source.id,
      offset: pageIndex * 50,
      limit: 50,
      query,
      onlyExportable,
    })
      .then((result) => {
        if (active) setPage(result);
      })
      .catch((e) => {
        if (active) setLoadError(String(e));
      });
    return () => {
      active = false;
    };
  }, [summary, source?.id, pageIndex, query, onlyExportable]);
  useEffect(() => {
    if (!fat32Summary || !source || fat32Summary.source_id !== source.id) return;
    let active = true;
    command<Fat32Page>("fat32_scan_results", {
      sourceId: source.id,
      offset: fat32PageIndex * 50,
      limit: 50,
      query: fat32Query,
      deletedOnly: fat32DeletedOnly,
    })
      .then((result) => {
        if (active) setFat32Page(result);
      })
      .catch((e) => {
        if (active) setLoadError(String(e));
      });
    return () => {
      active = false;
    };
  }, [fat32Summary, source?.id, fat32PageIndex, fat32Query, fat32DeletedOnly]);
  const scan = () =>
    run(async () => {
      const n = Number(offset);
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("Enter a valid byte offset, such as 0 or 0x100000.");
      await command("start_ntfs_scan", { offset: n });
      setSummary(null);
      setPage({ total: 0, rows: [] });
      setSelected(new Set());
      setPageIndex(0);
      setInspected(null);
      onJob(await command<Job>("job_status"));
    });
  const scanFat32 = () =>
    run(async () => {
      const n = Number(offset);
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error("Enter a valid byte offset, such as 0 or 0x100000.");
      await command("start_fat32_scan", { offset: n });
      setFat32Summary(null);
      setFat32Page({ total: 0, rows: [] });
      setFat32PageIndex(0);
      setFat32Selected(new Set());
      onJob(await command<Job>("job_status"));
    });
  const exportFat32Files = () =>
    run(async () => {
      if (!source || !fat32Summary || fat32Selected.size === 0) return;
      const started = await command<boolean>("export_fat32_deleted", {
        sourceId: source.id,
        scanSessionId: fat32Summary.scan_session_id,
        entryOffsets: [...fat32Selected],
      });
      if (started) onJob(await command<Job>("job_status"));
    });
  const exportFiles = () =>
    run(async () => {
      if (!source) return;
      setExportVerification(null);
      const started = await command<boolean>("export_selected", {
        sourceId: source.id,
        ids: [...selected],
      });
      if (started) onJob(await command<Job>("job_status"));
    });
  const verifyExport = () =>
    run(async () => {
      setExportVerification(null);
      const result = await command<RecoveryExportVerification | null>(
        "verify_recovery_export",
      );
      if (result) setExportVerification(result);
    });
  const toggle = (id: number) =>
    setSelected((old) => {
      const next = new Set(old);
      if (next.has(id)) next.delete(id);
      else if (next.size < 1000) next.add(id);
      return next;
    });
  return (
    <>
      <section className="panel">
        <div className="panelTitle">
          <div className="panelHeading">
            <FileSearch size={17} />
            <h2>NTFS metadata recovery</h2>
          </div>
          <span className="tag">NATIVE · READ ONLY</span>
        </div>
        {!source ? (
          <div className="empty">
            <HardDrive />
            <h3>Open an evidence image to find deleted files</h3>
            <p>
              Scan an NTFS volume or enter the start of an NTFS partition inside
              a raw disk image.
            </p>
          </div>
        ) : (
          <>
            <div className="recoverySetup">
              <label>
                NTFS volume byte offset
                <input
                  value={offset}
                  onChange={(e) => setOffset(e.target.value)}
                  placeholder="0"
                  disabled={working}
                />
              </label>
              <button
                disabled={working}
                onClick={() =>
                  run(async () =>
                    setPartitions(
                      await command<PartitionReport>("analyze_partitions"),
                    ),
                  )
                }
              >
                Read partition table
              </button>
              <button
                className="primary"
                onClick={scan}
                disabled={working || !source?.sha256}
              >
                <Search size={15} />
                Scan deleted records
              </button>
            </div>
            {!source?.sha256 && (
              <p className="muted recoveryHashNotice">
                Calculate and record the source SHA-256 in Image Workspace before scanning.
              </p>
            )}
            {partitions && (
              <div className="partitionChoices">
                <span className="muted">PARTITION STARTS</span>
                {partitions.partitions
                  .filter((p) => !p.type_id.includes("container"))
                  .map((p) => (
                    <button
                      key={p.index}
                      disabled={working}
                      onClick={() =>
                        setOffset(String(p.start_lba * partitions.sector_size))
                      }
                    >
                      Partition {p.index} · {bytes(p.size_bytes)}
                      <span>
                        {p.filesystem_hint?.startsWith("NTFS")
                          ? "NTFS hint"
                          : p.type_id}
                      </span>
                    </button>
                  ))}
              </div>
            )}
            <p className="panelFootnote">
              Finds deleted NTFS records and reconstructs resident, fragmented,
              and sparse unnamed streams. Compressed, encrypted, continued
              streams and extents currently allocated to other files are
              blocked. Unallocated extents may still contain overwritten or
              discarded content.
            </p>
          </>
        )}
      </section>
      <section className="panel">
        <div className="panelTitle">
          <div>
            <div className="panelHeading">
              <FileSearch size={17} />
              <h2>FAT32 directory examination</h2>
            </div>
            <p>Records FAT32 directory entries to the active case. A deleted long-name lead may be partial and is identified separately.</p>
          </div>
          <span className="tag">READ ONLY · AUDITED</span>
        </div>
        <button
          className="primary"
          disabled={working || !source?.sha256}
          onClick={scanFat32}
        >
          <Search size={15} />
          Scan FAT32 directory
        </button>
        {!source?.sha256 && (
          <p className="muted recoveryHashNotice">
            Calculate and record the source SHA-256 before scanning.
          </p>
        )}
        {fat32Summary && source?.id === fat32Summary.source_id && (
          <div className="fat32Results">
            <div className="panelTitle">
              <div>
                <h3>FAT32 directory entries</h3>
                <p>
                  {fat32Summary.entries.toLocaleString()} entries ·{" "}
                  {fat32Summary.deleted_entries.toLocaleString()} deleted entries ·{" "}
                  scan SC-{String(fat32Summary.scan_session_id).padStart(6, "0")}
                </p>
              </div>
              <label className="checkLabel">
                <input
                  type="checkbox"
                  checked={fat32DeletedOnly}
                  onChange={(event) => {
                    setFat32DeletedOnly(event.target.checked);
                    setFat32PageIndex(0);
                  }}
                />
                Deleted only
              </label>
            </div>
            <label className="searchField">
              <Search size={14} />
              <input
                aria-label="Search FAT32 directory entries"
                placeholder="Search filename…"
                maxLength={200}
                value={fat32Query}
                onChange={(event) => {
                  setFat32Query(event.target.value);
                  setFat32PageIndex(0);
                }}
              />
            </label>
            <div className="fat32RecoveryBar">
              <p role="note">
                Deleted FAT32 entries do not retain their former cluster chain. Export is attempted only when the declared contiguous cluster range is still free in the active FAT or all mirrored FAT copies. A prior fragmented file may therefore be reconstructed incorrectly; the package records this assumption and does not claim content integrity. Overlap checks apply to the entries selected for this export only.
              </p>
              <button
                className="primary"
                disabled={!native || working || fat32Selected.size === 0}
                onClick={exportFat32Files}
              >
                Export selected · {fat32Selected.size}
              </button>
            </div>
            {fat32Page.rows.map(({ path, entry }) => (
              <div className="case" key={entry.source_offset}>
                {entry.deleted &&
                  (entry.attributes & 0x10) === 0 &&
                  (entry.attributes & 0x08) === 0 &&
                  entry.size > 0 && (
                    <label className="checkLabel fat32Select">
                      <input
                        type="checkbox"
                        checked={fat32Selected.has(entry.source_offset)}
                        onChange={() =>
                          setFat32Selected((current) => {
                            const next = new Set(current);
                            if (next.has(entry.source_offset)) next.delete(entry.source_offset);
                            else if (next.size < 1000) next.add(entry.source_offset);
                            return next;
                          })
                        }
                        aria-label={`Select ${path.join("/")} for contiguous-assumed FAT32 recovery`}
                      />
                      Eligible to attempt
                    </label>
                  )}
                <code>
                  {entry.deleted ? "DELETED" : "LIVE"} · 0x{entry.source_offset.toString(16)}
                </code>
                <h3 title={path.join("/")}>
                  {path.join("/") || entry.long_name || "(unnamed)"}
                </h3>
                {entry.deleted_long_name_lead && (
                  <p className="warning" role="note">
                    Deleted long-name lead; it may be partial. Adjacent LFN slots
                    and the reconstructed short-name checksum do not prove this text
                    was the original name: {entry.deleted_long_name_lead}
                  </p>
                )}
                <span>
                  {entry.size.toLocaleString()} bytes · cluster {entry.first_cluster} · {entry.attributes.toString(16).padStart(2, "0")} attributes
                </span>
                <code className="muted">
                  Raw short record · {entry.raw_record.map((byte) => byte.toString(16).padStart(2, "0")).join("")}
                </code>
              </div>
            ))}
            <div className="actions archivedPagination">
              <button
                disabled={fat32PageIndex === 0}
                onClick={() => setFat32PageIndex((index) => Math.max(0, index - 1))}
              >
                Previous
              </button>
              <span>
                {fat32Page.total.toLocaleString()} entries · page {fat32PageIndex + 1}
              </span>
              <button
                disabled={(fat32PageIndex + 1) * 50 >= fat32Page.total}
                onClick={() => setFat32PageIndex((index) => index + 1)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </section>
      <section className="panel">
        <div className="panelTitle">
          <div>
            <div className="panelHeading">
              <ShieldCheck size={17} />
              <h2>Verify an output package</h2>
            </div>
            <p>Recheck the output files, inventory, and completion record.</p>
          </div>
          <button disabled={!native || working} onClick={verifyExport}>
            <ShieldCheck size={15} />
            Verify package folder
          </button>
        </div>
        {exportVerification && (
          <div
            className={
              exportVerification.state === "complete"
                ? "recoveryVerification success"
                : "recoveryVerification warning"
            }
            role="status"
          >
            <strong>
              {exportVerification.state === "complete"
                ? "Export is internally consistent"
                : "Export is internally consistent but incomplete"}
            </strong>
            <span>
              {exportVerification.records.toLocaleString()} records ·{" "}
              {exportVerification.exported.toLocaleString()} files verified ·{" "}
              {exportVerification.failed.toLocaleString()} failed
              {exportVerification.cancelled ? " · cancelled" : ""}
            </span>
            <code>Checksum list SHA-256 · {exportVerification.checksums_sha256}</code>
            <small>
              This checks package consistency. It does not prove source
              authenticity or original file-content integrity; no external
              signature or anchor is present.
            </small>
          </div>
        )}
        <p className="panelFootnote">
          Choose an existing DaemonCore recovery export folder. Verification
          reads and hashes its contents without changing them.
        </p>
      </section>
      {job.kind === "ntfs_scan" && job.state === "running" && (
        <div className="recoveryActivity">
          <FileSearch size={18} />
          <div>
            <h3>Examining the master file table</h3>
            <p>
              {job.discovered.toLocaleString()} deleted-file candidates found ·{" "}
              {bytes(job.processed)} of{" "}
              {job.total ? bytes(job.total) : "metadata size being established"}
            </p>
          </div>
          <button
            onClick={() =>
              run(async () => {
                await command("cancel_job");
              })
            }
          >
            Cancel scan
          </button>
        </div>
      )}
      {loadError && (
        <div className="warning" role="alert">
          {loadError}
        </div>
      )}
      {summary && (
        <section className="panel recoveryResults">
          <div className="panelTitle">
            <div>
              <h2>Deleted-file candidates</h2>
              <p>
                {summary.records.toLocaleString()} records examined ·{" "}
                {summary.found.toLocaleString()} candidates ·{" "}
                {summary.skipped.toLocaleString()} records skipped
              </p>
            </div>
            <span className="tag">
              NTFS · {bytes(summary.boot.cluster_size)} CLUSTERS
            </span>
          </div>
          {(summary.limited || summary.cancelled) && (
            <div className="warning">
              {summary.cancelled
                ? "This scan was cancelled. Results cover only the metadata examined before cancellation."
                : "A safety limit was reached. These are partial results, not a complete volume inventory."}
            </div>
          )}
          <div className="recoveryToolbar">
            <label className="searchField">
              <Search size={14} />
              <input
                aria-label="Search recovered filenames"
                placeholder="Search filename…"
                maxLength={200}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPageIndex(0);
                }}
              />
            </label>
            <label className="checkLabel">
              <input
                type="checkbox"
                checked={onlyExportable}
                onChange={(e) => {
                  setOnlyExportable(e.target.checked);
                  setPageIndex(0);
                }}
              />
              Extractable only
            </label>
            <button
              className="primary"
              disabled={working || !selected.size}
              onClick={exportFiles}
            >
              <ArrowDownToLine size={14} />
              Recover{" "}
              {selected.size ? `selected (${selected.size})` : "selected"}
            </button>
          </div>
          <div className="tableScroll">
            <table>
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      aria-label="Select extractable files on this page"
                      disabled={working || !page.rows.some((c) => c.exportable)}
                      checked={
                        page.rows.some((c) => c.exportable) &&
                        page.rows
                          .filter((c) => c.exportable)
                          .every((c) => selected.has(c.id))
                      }
                      onChange={(e) =>
                        setSelected((old) => {
                          const next = new Set(old);
                          for (const c of page.rows.filter(
                            (c) => c.exportable,
                          )) {
                            if (e.target.checked && next.size < 1000)
                              next.add(c.id);
                            else if (!e.target.checked) next.delete(c.id);
                          }
                          return next;
                        })
                      }
                    />
                  </th>
                  <th>Filename</th>
                  <th>Logical size</th>
                  <th>Storage</th>
                  <th>Evidence status</th>
                  <th>MFT record</th>
                </tr>
              </thead>
              <tbody>
                {page.rows.map((c) => (
                  <tr
                    key={c.id}
                    className={inspected?.id === c.id ? "inspectedRow" : ""}
                  >
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${c.name}`}
                        checked={selected.has(c.id)}
                        disabled={working || !c.exportable}
                        onChange={() => toggle(c.id)}
                      />
                    </td>
                    <td>
                      <button
                        className="resultName"
                        onClick={() => setInspected(c)}
                      >
                        {c.name}
                      </button>
                    </td>
                    <td>{bytes(c.size)}</td>
                    <td>{c.storage}</td>
                    <td>
                      <span
                        className={
                          c.exportable ? "resultStatus" : "resultStatus blocked"
                        }
                      >
                        {allocationLabel[c.allocation] || c.allocation}
                        {!c.exportable ? " · blocked" : ""}
                      </span>
                    </td>
                    <td>
                      <code>{c.id}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!page.rows.length && (
            <div className="empty">
              <FileSearch />
              <h3>
                {query
                  ? "No matching candidates"
                  : "No deleted-file candidates found"}
              </h3>
              <p>
                This result does not establish that no recoverable data remains
                elsewhere on the source.
              </p>
            </div>
          )}
          <div className="recoveryPagination">
            <span>
              {page.total
                ? `${pageIndex * 50 + 1}–${Math.min((pageIndex + 1) * 50, page.total)} of ${page.total}`
                : "0 candidates"}
            </span>
            <div>
              <button
                aria-label="Previous result page"
                disabled={pageIndex === 0}
                onClick={() => setPageIndex((n) => n - 1)}
              >
                <ChevronLeft size={14} />
              </button>
              <button
                aria-label="Next result page"
                disabled={(pageIndex + 1) * 50 >= page.total}
                onClick={() => setPageIndex((n) => n + 1)}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
          {inspected && (
            <div className="candidateInspector">
              <div className="panelHeading">
                <ShieldCheck size={16} />
                <h3>{inspected.name}</h3>
              </div>
              <div className="detail">
                <span>MFT record / parent</span>
                <b>
                  {inspected.id} / {inspected.parent_record}
                </b>
                <span>Verified parent path</span>
                <b>
                  {inspected.parent_path === null
                    ? "Unavailable · parent chain did not verify"
                    : inspected.parent_path.some((part) => part.record !== 5)
                      ? inspected.parent_path
                          .filter((part) => part.record !== 5)
                          .map((part) => part.name)
                          .join("\\")
                      : "\\ (root)"}
                </b>
                <span>Names recorded in this MFT record</span>
                <div className="filenameReferenceList">
                  {inspected.filename_references.length === 0 ? (
                    <span>No $FILE_NAME attributes decoded</span>
                  ) : (
                    inspected.filename_references.map((reference, index) => (
                      <div key={`${reference.attribute_id}-${index}`}>
                        <b>{reference.name}</b>
                        <span>
                          Attribute record {reference.attribute_record} (sequence{" "}
                          {reference.attribute_record_sequence}) · namespace{" "}
                          {reference.namespace} · parent{" "}
                          {reference.parent_record} (sequence {reference.parent_sequence}) ·
                          attribute {reference.attribute_id}
                        </span>
                      </div>
                    ))
                  )}
                  <span>
                    Includes base-record names and extension-record names
                    explicitly referenced by the validated attribute list.
                  </span>
                </div>
                <span>Created (UTC)</span>
                <b>{filetime(inspected.created_filetime)}</b>
                <span>Modified (UTC)</span>
                <b>{filetime(inspected.modified_filetime)}</b>
                <span>Record SHA-256</span>
                <code>{inspected.fingerprint}</code>
              </div>
              {inspected.notes.map((note, i) => (
                <p key={i}>{note}</p>
              ))}
            </div>
          )}
          <p className="panelFootnote">
            Recovery uses a new folder on a different physical disk, never
            replaces existing files, and independently rehashes destination
            bytes. This verifies the export round trip; it does not prove the
            original file's content is intact. Filenames are prefixed with their
            MFT record number.
            Verified parent paths are restored in the export tree. Unverified
            or unusually long paths stay flat and are identified in the manifest.
          </p>
        </section>
      )}
    </>
  );
}
