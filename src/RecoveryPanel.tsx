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
  const working = busy || job.state === "running";
  useEffect(() => {
    setSummary(null);
    setSelected(new Set());
    setPage({ total: 0, rows: [] });
    setPartitions(null);
    setOffset("0");
    setInspected(null);
  }, [source?.id]);
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
                Calculate and record the source SHA-256 in Device Explorer before scanning.
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
              <ShieldCheck size={17} />
              <h2>Verify a recovery export</h2>
            </div>
            <p>Recheck the output files, inventory, and completion record.</p>
          </div>
          <button disabled={!native || working} onClick={verifyExport}>
            <ShieldCheck size={15} />
            Verify export folder
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
