import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { ChevronRight, FolderOpen, LockKeyhole, Plus } from "lucide-react";
import {
  command,
  native,
  type Case,
  type CaseReportExport,
  type CaseEvidenceRecord,
  type CaseScanSession,
  type ActiveCaseState,
  type RecoveryCandidate,
  type RecoveryPage,
  type Source,
  type Job,
  type Fat32CaseScanSession,
  type Fat32Page,
  type ExfatPage,
  type ExfatCaseScanSession,
  type ExfatScanSummary,
  type CarvePage,
} from "./bridge";
import "./style.css";
import { SourcePanel } from "./SourcePanel";
import { JobPanel } from "./JobPanel";
import { PartitionPanel } from "./PartitionPanel";
import { AuditPanel } from "./AuditPanel";
import { WorkspaceShell } from "./WorkspaceShell";
import { Overview } from "./Overview";
import { RecoveryPanel } from "./RecoveryPanel";
import { DiskImagingPanel } from "./DiskImagingPanel";
import { RaidPanel } from "./RaidPanel";
import { bytes } from "./format";
class AppErrorBoundary extends React.Component<
  React.PropsWithChildren,
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("Unhandled application render error", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <main className="workspace">
          <section className="panel" role="alert">
            <div className="panelTitle">
              <h1>Interface stopped unexpectedly</h1>
              <span className="tag">VERIFY BEFORE CONTINUING</span>
            </div>
            <div className="empty">
              <p>The interface could not render safely. A native operation may have completed, failed, or still be running. Reopen the app, check its recorded status, and verify any output package before using it as evidence.</p>
              <pre className="warning">{this.state.error.message || "Unexpected rendering error"}</pre>
              <button className="primary" onClick={() => window.location.reload()}>
                Reopen interface
              </button>
            </div>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}
const emptyJob: Job = {
  kind: "hash",
  discovered: 0,
  message: null,
  output_directory: null,
  state: "idle",
  processed: 0,
  total: 0,
  sha256: null,
  error: null,
};
function App() {
  const [page, setPage] = useState("Dashboard"),
    [source, setSource] = useState<Source | null>(null),
    [job, setJob] = useState<Job>(emptyJob),
    [error, setError] = useState(""),
    [statusError, setStatusError] = useState(""),
    [backgroundErrors, setBackgroundErrors] = useState<Record<string, string>>({}),
    [cases, setCases] = useState<Case[]>([]),
    [caseEvidence, setCaseEvidence] = useState<CaseEvidenceRecord[]>([]),
    [caseScans, setCaseScans] = useState<CaseScanSession[]>([]),
    [fat32CaseScans, setFat32CaseScans] = useState<Fat32CaseScanSession[]>([]),
    [exfatCaseScans, setExfatCaseScans] = useState<ExfatCaseScanSession[]>([]),
    [archivedScanId, setArchivedScanId] = useState<number | null>(null),
    [archivedPage, setArchivedPage] = useState<RecoveryPage | null>(null),
    [archivedFat32ScanId, setArchivedFat32ScanId] = useState<number | null>(null),
    [archivedFat32Page, setArchivedFat32Page] = useState<Fat32Page | null>(null),
    [archivedExfatScanId, setArchivedExfatScanId] = useState<number | null>(null),
    [archivedExfatPage, setArchivedExfatPage] = useState<ExfatPage | null>(null),
    [archivedExfatPageIndex, setArchivedExfatPageIndex] = useState(0),
    [exfatPage, setExfatPage] = useState<ExfatPage | null>(null),
    [exfatSummary, setExfatSummary] = useState<ExfatScanSummary | null>(null),
    [exfatSelected, setExfatSelected] = useState<Set<number>>(new Set()),
    [filesystemOffset, setFilesystemOffset] = useState("0"),
    [exfatPageIndex, setExfatPageIndex] = useState(0),
    [archivedFat32PageIndex, setArchivedFat32PageIndex] = useState(0),
    [archivedPageIndex, setArchivedPageIndex] = useState(0),
    [activeCaseId, setActiveCaseId] = useState<number | null>(null),
    [activeCaseAuditMatched, setActiveCaseAuditMatched] = useState(true),
    [caseReport, setCaseReport] = useState<CaseReportExport | null>(null),
    [carvePage, setCarvePage] = useState<CarvePage | null>(null),
    [carvePageIndex, setCarvePageIndex] = useState(0),
    [selectedCarves, setSelectedCarves] = useState<number[]>([]),
    [title, setTitle] = useState(""),
    [examiner, setExaminer] = useState(""),
    [offset, setOffset] = useState("0"),
    [searchPattern, setSearchPattern] = useState(""),
    [searchLength, setSearchLength] = useState("1048576"),
    [hexMatches, setHexMatches] = useState<number[] | null>(null),
    [data, setData] = useState<number[]>([]),
    [readOffset, setReadOffset] = useState(0),
    [busy, setBusy] = useState(false);
  const sourceGeneration = useRef(0);
  const actionInProgress = useRef(false);
  const reportBackgroundError = (key: string, error: unknown | null) =>
    setBackgroundErrors((current) => {
      if (error === null) {
        if (!(key in current)) return current;
        const next = { ...current };
        delete next[key];
        return next;
      }
      return { ...current, [key]: String(error) };
    });
  const run = async (action: () => Promise<void>) => {
    if (actionInProgress.current) return;
    actionInProgress.current = true;
    setError("");
    setBusy(true);
    try {
      await action();
    } catch (e) {
      setError(String(e));
    } finally {
      actionInProgress.current = false;
      setBusy(false);
    }
  };
  useEffect(() => {
    if (native) {
      let active = true;
      command<Case[]>("list_cases")
        .then((result) => {
          if (!active) return;
          setCases(result);
          reportBackgroundError("cases", null);
        })
        .catch((e) => {
          if (active) reportBackgroundError("cases", `Case list: ${String(e)}`);
        });
      command<ActiveCaseState>("get_active_case_state")
        .then(({ case_id, audit_matched }) => {
          if (!active) return;
          setActiveCaseId(case_id);
          setActiveCaseAuditMatched(audit_matched);
          reportBackgroundError("active-case", null);
        })
        .catch((e) => {
          if (!active) return;
          setActiveCaseAuditMatched(false);
          reportBackgroundError("active-case", `Active case state: ${String(e)}`);
        });
      return () => {
        active = false;
      };
    }
  }, []);
  useEffect(() => {
    setCaseReport(null);
  }, [activeCaseId, activeCaseAuditMatched]);
  useEffect(() => {
    if (!native || activeCaseId === null) {
      setCaseEvidence([]);
      setCaseScans([]);
      setFat32CaseScans([]);
      setExfatCaseScans([]);
      setArchivedFat32ScanId(null);
      setArchivedFat32Page(null);
      setArchivedFat32PageIndex(0);
      setArchivedExfatScanId(null);
      setArchivedExfatPage(null);
      setArchivedExfatPageIndex(0);
      return;
    }
    let active = true;
    Promise.all([
      command<CaseEvidenceRecord[]>("list_case_evidence", {
        caseId: activeCaseId,
      }),
      command<CaseScanSession[]>("list_case_scan_sessions", {
        caseId: activeCaseId,
      }),
      command<Fat32CaseScanSession[]>("list_case_fat32_scan_sessions", {
        caseId: activeCaseId,
      }),
      command<ExfatCaseScanSession[]>("list_case_exfat_scan_sessions", {
        caseId: activeCaseId,
      }),
    ])
      .then(([evidence, scans, fat32Scans, exfatScans]) => {
        if (active) {
          setCaseEvidence(evidence);
          setCaseScans(scans);
          setFat32CaseScans(fat32Scans);
          setExfatCaseScans(exfatScans);
          reportBackgroundError("case-evidence", null);
        }
      })
      .catch((e) => {
        if (active) reportBackgroundError("case-evidence", `Case evidence and scan history: ${String(e)}`);
      });
    return () => {
      active = false;
    };
  }, [activeCaseId, job.state]);
  useEffect(() => {
    if (!native) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let delay = 700;
    const poll = async () => {
      const generation = sourceGeneration.current;
      const [jobResult, sourceResult] = await Promise.allSettled([
        command<Job>("job_status"),
        command<Source | null>("source_status"),
      ] as const);
      if (!active) return;

      const failures: string[] = [];
      if (jobResult.status === "fulfilled") setJob(jobResult.value);
      else failures.push(`Job status: ${String(jobResult.reason)}`);
      if (sourceResult.status === "fulfilled") {
        if (generation === sourceGeneration.current) setSource(sourceResult.value);
      } else failures.push(`Evidence source status: ${String(sourceResult.reason)}`);

      if (failures.length) {
        setStatusError(`${failures.join("; ")} Retrying automatically.`);
        delay = Math.min(delay * 2, 8_000);
      } else {
        setStatusError("");
        delay = 700;
      }
      timer = setTimeout(poll, delay);
    };
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, []);
  useEffect(() => {
    if (
      !native ||
      page !== "File Carving" ||
      job.kind !== "carving_scan" ||
      job.state !== "completed" ||
      !source
    )
      return;
    let active = true;
    command<CarvePage>("carve_results", {
      sourceId: source.id,
      offset: carvePageIndex * 100,
      limit: 100,
    })
      .then((result) => {
        if (!active) return;
        setCarvePage(result);
        reportBackgroundError("carve-results", null);
      })
      .catch((e) => {
        if (active) reportBackgroundError("carve-results", `Carving results: ${String(e)}`);
      });
    return () => {
      active = false;
    };
  }, [native, page, job.kind, job.state, source?.id, carvePageIndex]);
  useEffect(() => {
    if (!native || page !== "Filesystem Analysis" || job.kind !== "exfat_scan" || job.state !== "completed" || !source) return;
    let active = true;
    Promise.all([
      command<ExfatPage>("exfat_scan_results", { sourceId: source.id, offset: exfatPageIndex * 50, limit: 50 }),
      command<ExfatScanSummary | null>("exfat_scan_summary"),
    ])
      .then(([results, summary]) => {
        if (!active) return;
        if (!summary || summary.source_id !== source.id) {
          setExfatPage(null);
          setExfatSummary(null);
          setExfatSelected(new Set());
          reportBackgroundError("exfat-results", "The scan summary no longer matches the active source. Re-run the analysis.");
          return;
        }
        setExfatPage(results);
        setExfatSummary(summary);
        reportBackgroundError("exfat-results", null);
      })
      .catch((e) => {
        if (active) reportBackgroundError("exfat-results", `exFAT scan results: ${String(e)}`);
      });
    return () => { active = false; };
  }, [native, page, job.kind, job.state, source?.id, exfatPageIndex]);
  const clearActiveEvidenceView = () => {
    sourceGeneration.current += 1;
    setSource(null);
    setJob(emptyJob);
    setData([]);
    setCarvePage(null);
    setCarvePageIndex(0);
    setSelectedCarves([]);
    setOffset("0");
    setReadOffset(0);
    setCaseEvidence([]);
    setCaseScans([]);
    setFat32CaseScans([]);
    setExfatCaseScans([]);
    setExfatPage(null);
    setExfatSummary(null);
    setExfatSelected(new Set());
    setExfatPageIndex(0);
    setArchivedScanId(null);
    setArchivedPage(null);
    setArchivedFat32ScanId(null);
    setArchivedFat32Page(null);
    setArchivedExfatScanId(null);
    setArchivedExfatPage(null);
    setArchivedExfatPageIndex(0);
    setArchivedPageIndex(0);
    setCaseReport(null);
  };
  const open = () =>
    run(async () => {
      if (activeCaseId === null)
        throw new Error("Create or select a case before opening evidence.");
      if (!activeCaseAuditMatched)
        throw new Error("Re-select the intended active case to record a correction before opening evidence.");
      const s = await command<Source | null>("open_image");
      if (s) {
        sourceGeneration.current += 1;
        setSource(s);
        setData([]);
        setHexMatches(null);
        setJob(emptyJob);
        setCarvePage(null);
        setCarvePageIndex(0);
        setSelectedCarves([]);
        setPage("Image Workspace");
      }
    });
  const hash = () =>
    run(async () => {
      await command("start_hash");
      setJob(await command<Job>("job_status"));
    });
  const inspect = () =>
    run(async () => {
      const n = Number(offset);
      if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(
          "Enter a nonnegative decimal or 0x hexadecimal offset.",
        );
      const d = await command<number[]>("read_hex", { offset: n, length: 512 });
      setData(d);
      setReadOffset(n);
    });
  const searchHex = () =>
    run(async () => {
      const startOffset = Number(offset);
      const scanLength = Number(searchLength);
      if (!Number.isSafeInteger(startOffset) || startOffset < 0)
        throw new Error("Enter a nonnegative decimal or 0x hexadecimal start offset.");
      if (!Number.isSafeInteger(scanLength) || scanLength < 1 || scanLength > 1024 * 1024 * 1024)
        throw new Error("Search length must be from 1 byte through 1 GiB.");
      const matches = await command<number[]>("search_hex", {
        patternHex: searchPattern,
        startOffset,
        scanLength,
      });
      setHexMatches(matches);
    });
  const inspectHexOffset = (value: number) =>
    run(async () => {
      setOffset(String(value));
      const d = await command<number[]>("read_hex", { offset: value, length: 512 });
      setData(d);
      setReadOffset(value);
    });
  const startCarving = () =>
    run(async () => {
      setCarvePage(null);
      setCarvePageIndex(0);
      setSelectedCarves([]);
      await command("start_file_carving");
      setJob(await command<Job>("job_status"));
    });
  const inspectCarvedOffset = (value: number) =>
    run(async () => {
      const d = await command<number[]>("read_hex", { offset: value, length: 512 });
      setData(d);
      setOffset(String(value));
      setReadOffset(value);
      setPage("Hex Inspector");
    });
  const exportCarved = () =>
    run(async () => {
      if (!source || selectedCarves.length === 0)
        throw new Error("Select at least one carved candidate.");
      await command("export_carved_selected", {
        sourceId: source.id,
        ids: selectedCarves,
      });
      setJob(await command<Job>("job_status"));
    });
  const showArchivedResults = (scanSessionId: number, pageIndex: number) =>
    run(async () => {
      if (activeCaseId === null) throw new Error("Select the case first.");
      const result = await command<RecoveryPage>("archived_scan_results", {
        caseId: activeCaseId,
        scanSessionId,
        offset: pageIndex * 50,
        limit: 50,
      });
      setArchivedScanId(scanSessionId);
      setArchivedPageIndex(pageIndex);
      setArchivedPage(result);
    });
  const showArchivedFat32Results = (scanSessionId: number, pageIndex: number) =>
    run(async () => {
      if (activeCaseId === null) throw new Error("Select the case first.");
      const result = await command<Fat32Page>("archived_fat32_scan_results", {
        caseId: activeCaseId,
        scanSessionId,
        offset: pageIndex * 50,
        limit: 50,
      });
      setArchivedFat32ScanId(scanSessionId);
      setArchivedFat32Page(result);
      setArchivedFat32PageIndex(pageIndex);
    });
  const showArchivedExfatResults = (scanSessionId: number, pageIndex: number) =>
    run(async () => {
      if (activeCaseId === null) throw new Error("Select the case first.");
      const result = await command<ExfatPage>("archived_exfat_scan_results", {
        caseId: activeCaseId,
        scanSessionId,
        offset: pageIndex * 50,
        limit: 50,
      });
      setArchivedExfatScanId(scanSessionId);
      setArchivedExfatPage(result);
      setArchivedExfatPageIndex(pageIndex);
    });
  const reopenArchivedSource = (scanSessionId: number) =>
    run(async () => {
      if (activeCaseId === null) throw new Error("Select the case first.");
      const reopened = await command<Source>("reopen_archived_source", {
        caseId: activeCaseId,
        scanSessionId,
      });
      sourceGeneration.current += 1;
      setSource(reopened);
      setData([]);
      setHexMatches(null);
      setCarvePage(null);
      setCarvePageIndex(0);
      setSelectedCarves([]);
      setJob(emptyJob);
      setArchivedScanId(null);
      setArchivedPage(null);
      setPage("Image Workspace");
    });
  const exportCaseReport = () =>
    run(async () => {
      setCaseReport(null);
      if (activeCaseId === null) throw new Error("Select a case first.");
      if (!activeCaseAuditMatched)
        throw new Error("Reconfirm the active case before exporting a report.");
      const exported = await command<CaseReportExport | null>(
        "export_case_report",
        { caseId: activeCaseId },
      );
      if (exported) {
        setCaseReport(exported);
        setJob(await command<Job>("job_status"));
      }
    });
  const selectedArchivedScan = caseScans.find(
    (scan) => scan.id === archivedScanId,
  );
  const selectedArchivedEvidence = caseEvidence.find(
    (record) => record.id === selectedArchivedScan?.evidence_id,
  );
  const selectedArchivedFat32Scan = fat32CaseScans.find(
    (scan) => scan.id === archivedFat32ScanId,
  );
  const selectedArchivedFat32Evidence = caseEvidence.find(
    (record) => record.id === selectedArchivedFat32Scan?.evidence_id,
  );
  const selectedArchivedExfatScan = exfatCaseScans.find(
    (scan) => scan.id === archivedExfatScanId,
  );
  const selectedArchivedExfatEvidence = caseEvidence.find(
    (record) => record.id === selectedArchivedExfatScan?.evidence_id,
  );
  const archivedExfatSourceMatchesScan =
    selectedArchivedExfatEvidence?.status === "hashed" &&
    selectedArchivedExfatEvidence.sha256 === selectedArchivedExfatScan?.source_sha256;
  const archivedFat32SourceMatchesScan =
    selectedArchivedFat32Evidence?.status === "hashed" &&
    selectedArchivedFat32Evidence.sha256 === selectedArchivedFat32Scan?.source_sha256;
  const archivedSourceMatchesScan =
    selectedArchivedEvidence?.status === "hashed" &&
    selectedArchivedEvidence.sha256 === selectedArchivedScan?.source_sha256;
  const heading = (
    <div className="heading">
      <div className="headingCopy">
        <div className="eyebrow">
          <span className="eyebrowLine" /> DAEMONCORE /{" "}
          {page === "Dashboard" ? "OVERVIEW" : page.toUpperCase()}
        </div>
        <h1>{page === "Dashboard" ? "Investigation overview" : page}</h1>
        <p>
          {page === "Dashboard"
            ? "Your evidence, your workflow. A clearer view of every examination."
            : "A dedicated workspace for precise, read-only evidence examination."}
        </p>
      </div>
      <div className="headingActions">
        <span className="sessionBadge">
          <LockKeyhole size={12} />
          Read-only session
        </span>
        <button
          className="primary"
          onClick={open}
          disabled={busy || job.state === "running"}
        >
          <Plus size={16} /> Open disk image
        </button>
      </div>
    </div>
  );
  const sourcePanel = (
    <SourcePanel
      source={source}
      busy={busy}
      job={job}
      open={open}
      hash={hash}
      onInspect={() => setPage("Hex Inspector")}
      onScan={() => setPage("Recovery Workspace")}
    />
  );
  const jobPanel = (
    <JobPanel
      job={job}
      cancel={() =>
        run(async () => {
          await command("cancel_job");
        })
      }
    />
  );

  return (
    <WorkspaceShell page={page} setPage={setPage} source={source} job={job}>
      {heading}
      {statusError && (
        <div className="warning" role="status">
          Background status is temporarily unavailable. {statusError}
        </div>
      )}
      {Object.entries(backgroundErrors).map(([key, message]) => (
        <div className="warning" role="status" key={key}>
          Background data could not be loaded. {message}
        </div>
      ))}
      {error && (
        <div className="warning" role="alert">
          {error}
        </div>
      )}
      {page === "Dashboard" ? (
        <Overview
          source={source}
          job={job}
          caseCount={cases.length}
          sourcePanel={sourcePanel}
          jobPanel={jobPanel}
          open={open}
          setPage={setPage}
          busy={busy}
        />
      ) : page === "Image Workspace" ? (
        <>
          {sourcePanel}
          {jobPanel}
        </>
      ) : page === "Disk Imaging" ? (
        <>
          <DiskImagingPanel job={job} busy={busy} canAcquire={activeCaseId !== null && activeCaseAuditMatched} run={run} onSource={setSource} onJob={setJob} />
          {sourcePanel}
          {jobPanel}
        </>
      ) : page === "Partition Analysis" ? (
        <PartitionPanel
          key={source?.id}
          source={source}
          busy={busy || job.state === "running"}
          analyze={(read) => run(read)}
        />
      ) : page === "Recovery Workspace" ? (
        <>
          <RecoveryPanel
            source={source}
            job={job}
            busy={busy}
            run={run}
            onJob={setJob}
          />
          {jobPanel}
        </>
      ) : page === "Deep Scan" || page === "Filesystem Analysis" ? (
        <>
          <section className="capabilityPanel panel">
            <div className="panelTitle">
              <h2>{page === "Deep Scan" ? "Metadata scan" : "Filesystem review"}</h2>
              <span className="tag">SUPPORTED FORMATS ONLY</span>
            </div>
            <p>
              {page === "Deep Scan"
                ? "The available scan reads supported NTFS metadata and rechecks the source digest before accepting results. It is not signature-based file carving."
                : "Review NTFS metadata, inventory FAT32 directories, or validate live exFAT directory entries against the allocation bitmap and source hash."}
            </p>
            <button className="primary" onClick={() => setPage("Recovery Workspace")}>
              Open supported scan tools <ChevronRight size={14} />
            </button>
          </section>
          <RecoveryPanel
            source={source}
            job={job}
            busy={busy}
            run={run}
            onJob={setJob}
          />
          {page === "Filesystem Analysis" && (
            <section className="panel filesystemPanel">
              <div className="panelTitle">
                <h2>exFAT directory analysis</h2>
                <span className="tag">READ ONLY · SOURCE VERIFIED</span>
              </div>
              <p>Validates boot regions, the allocation bitmap, up-case table, live streams, and checksum-valid deleted entry sets. Deleted-file export uses either the entry set’s contiguous layout or a retained FAT chain, and requires every candidate cluster to be free in the current bitmap. Deleted metadata cannot prove the bytes still belong to the original file.</p>
              <div className="actions">
                <label>Volume byte offset <input value={filesystemOffset} onChange={(event) => setFilesystemOffset(event.target.value)} placeholder="0 or 0x..." /></label>
                <button className="primary" disabled={!source?.sha256 || busy || job.state === "running"} onClick={() => void run(async () => {
                  const parsedOffset = filesystemOffset.trim().toLowerCase().startsWith("0x") ? Number.parseInt(filesystemOffset.trim().slice(2), 16) : Number(filesystemOffset);
                  if (!Number.isSafeInteger(parsedOffset) || parsedOffset < 0) throw new Error("Enter a valid nonnegative decimal or 0x hexadecimal volume offset.");
                  setExfatPage(null);
                  setExfatSummary(null);
                  setExfatSelected(new Set());
                  setExfatPageIndex(0);
                  await command("start_exfat_scan", { offset: parsedOffset });
                  setJob(await command<Job>("job_status"));
                })}>Analyze exFAT volume</button>
              </div>
              {!source?.sha256 && <p className="muted">Calculate the source SHA-256 before starting filesystem analysis.</p>}
              {exfatPage && exfatSummary && source?.id === exfatSummary.source_id && (
                <>
                  <div className="panelTitle"><h3>{exfatPage.total.toLocaleString()} verified directory records</h3><span className="muted">PAGE {exfatPageIndex + 1}</span></div>
                  <div className="fat32RecoveryBar">
                    <p role="note">Selected files are revalidated against the source image and allocation bitmap before export. Overlapping selected ranges are rejected. Each output is destination-hash checked; original content integrity cannot be established from deleted metadata alone.</p>
                    <button className="primary" disabled={!native || busy || job.state === "running" || exfatSelected.size === 0} onClick={() => void run(async () => {
                      if (!source || !exfatSummary) throw new Error("The verified exFAT scan is no longer available. Re-run the analysis.");
                      const started = await command<boolean>("export_exfat_deleted", {
                        sourceId: source.id,
                        scanSessionId: exfatSummary.scan_session_id,
                        entryOffsets: [...exfatSelected],
                      });
                      if (started) setJob(await command<Job>("job_status"));
                    })}>Export selected · {exfatSelected.size}</button>
                  </div>
                  {exfatPage.rows.map(({ path, entry }) => (
                    <div className="case" key={entry.source_offset}>
                      {entry.deleted && (entry.attributes & 0x10) === 0 && (entry.attributes & 0x08) === 0 && entry.data_length > 0 && (
                        <label className="checkLabel fat32Select">
                          <input type="checkbox" checked={exfatSelected.has(entry.source_offset)} onChange={() => setExfatSelected((current) => {
                            const next = new Set(current);
                            if (next.has(entry.source_offset)) next.delete(entry.source_offset);
                            else if (next.size < 1000) next.add(entry.source_offset);
                            return next;
                          })} aria-label={`Select ${path.join("/")} for attempted exFAT recovery using ${entry.no_fat_chain ? "declared contiguous layout" : "retained FAT chain"}`} />
                          Eligible to attempt
                        </label>
                      )}
                      <code>0x{entry.source_offset.toString(16).padStart(12, "0")}</code>
                      <h3 title={path.join("/")}>{path.join("/")}</h3>
                      <span>{entry.deleted ? `Deleted metadata lead · ${entry.no_fat_chain ? "contiguous allocation assumed" : "retained FAT chain unverified"}` : "Live entry"} · {entry.data_length.toLocaleString()} bytes · cluster {entry.first_cluster || "—"} · {entry.attributes & 0x10 ? "directory" : "file"}</span>
                    </div>
                  ))}
                  {!exfatPage.total && <p className="muted">The volume is valid and contains no supported file entry sets.</p>}
                  <div className="actions archivedPagination">
                    <button disabled={exfatPageIndex === 0} onClick={() => setExfatPageIndex((index) => Math.max(0, index - 1))}>Previous</button>
                    <span>{exfatPage.total.toLocaleString()} entries</span>
                    <button disabled={(exfatPageIndex + 1) * 50 >= exfatPage.total} onClick={() => setExfatPageIndex((index) => index + 1)}>Next</button>
                  </div>
                </>
              )}
            </section>
          )}
          {jobPanel}
        </>
      ) : page === "Evidence Vault" ? (
        <AuditPanel run={(read) => run(read)} busy={busy} />
      ) : page === "Hex Inspector" ? (
        <section className="panel">
          <div className="panelTitle">
            <h2>Hex inspector</h2>
            <span className="muted">READ ONLY · 512 BYTES / VIEW</span>
          </div>
          <div className="actions hexControls">
            <label>
              Byte offset{" "}
              <input
                value={offset}
                onChange={(e) => setOffset(e.target.value)}
                placeholder="0x0"
              />
            </label>
            <button disabled={!source || busy} onClick={inspect}>
              Read range
            </button>
          </div>
          <div className="actions hexSearchControls">
            <label>
              Hex byte pattern{" "}
              <input value={searchPattern} onChange={(e) => setSearchPattern(e.target.value)} placeholder="4D 5A 90 00" spellCheck={false} />
            </label>
            <label>
              Search bytes{" "}
              <input value={searchLength} onChange={(e) => setSearchLength(e.target.value)} inputMode="numeric" />
            </label>
            <button className="primary" disabled={!source?.sha256 || busy} onClick={searchHex}>Search image range</button>
          </div>
          {hexMatches !== null && hexMatches.length > 0 && (
            <div className="hexMatches">
              <div className="panelTitle"><h3>{hexMatches.length.toLocaleString()} matching offsets</h3><span className="muted">AUDITED SEARCH</span></div>
              <div className="hexMatchList">
                {hexMatches.map((match) => (
                  <button key={match} onClick={() => void inspectHexOffset(match)} disabled={busy}>
                    <code>0x{match.toString(16).padStart(12, "0")}</code><span>Inspect</span>
                  </button>
                ))}
              </div>
            </div>
          )}
          {hexMatches !== null && hexMatches.length === 0 && (
            <p className="muted hexSearchHint">No matches in the selected range.</p>
          )}
          {hexMatches === null && (
            <p className="muted hexSearchHint">{source?.sha256 ? "Search an operator-selected range (up to 1 GiB). Each operation and its result digest are recorded in the case audit log. Patterns accept hexadecimal bytes with optional spaces." : "Calculate the source SHA-256 before searching evidence bytes."}</p>
          )}
          <div className="hex">
            <div className="hexHead">OFFSET HEXADECIMAL ASCII</div>
            {Array.from({ length: Math.ceil(data.length / 16) }, (_, r) => {
              const row = data.slice(r * 16, r * 16 + 16);
              return (
                <div key={r}>
                  <span>
                    {(readOffset + r * 16).toString(16).padStart(12, "0")}{" "}
                  </span>
                  <code>
                    {row
                      .map((b) => b.toString(16).padStart(2, "0"))
                      .join(" ")
                      .padEnd(47, " ")}{" "}
                  </code>
                  <span>
                    {row
                      .map((b) =>
                        b >= 32 && b < 127 ? String.fromCharCode(b) : ".",
                      )
                      .join("")}
                  </span>
                </div>
              );
            })}
            {!data.length && (
              <p>
                Open an image and read a range to inspect its actual contents.
              </p>
            )}
          </div>
        </section>
      ) : page === "Case Management" ? (
        <>
          <section className="panel">
            <div className="panelTitle">
              <h2>Create local case</h2>
              <span className="muted">SQLITE</span>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  await command("create_case", { title, examiner });
                  clearActiveEvidenceView();
                  setCases(await command<Case[]>("list_cases"));
                  const active = await command<ActiveCaseState>("get_active_case_state");
                  setActiveCaseId(active.case_id);
                  setActiveCaseAuditMatched(active.audit_matched);
                  setTitle("");
                });
              }}
            >
              <label>
                Case title
                <input
                  required
                  maxLength={200}
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                />
              </label>
              <label>
                Examiner
                <input
                  required
                  maxLength={200}
                  value={examiner}
                  onChange={(e) => setExaminer(e.target.value)}
                />
              </label>
              <button className="primary" disabled={busy || job.state === "running"}>
                Create case
              </button>
            </form>
          </section>
          <section className="panel">
            <div className="panelTitle">
              <h2>Case register</h2>
              <span className="muted">{cases.length} CASES</span>
            </div>
            {cases.length ? (
              cases.map((c) => (
                <div className="case" key={c.id}>
                  <code>DC-{String(c.id).padStart(5, "0")}</code>
                  <h3>{c.title}</h3>
                  <span className="caseExaminer">{c.examiner}</span>
                  <span className={`caseIntegrity ${c.integrity === "legacy_unverified" ? "legacy" : ""}`}>
                    {c.integrity === "audit_matched" ? "AUDIT MATCHED" : "LEGACY · UNVERIFIED"}
                  </span>
                  <button
                    type="button"
                    className={activeCaseId === c.id ? "secondary" : ""}
                    aria-pressed={activeCaseId === c.id && activeCaseAuditMatched}
                    disabled={busy || job.state === "running" || (activeCaseId === c.id && activeCaseAuditMatched)}
                    onClick={() => void run(async () => {
                      await command("set_active_case", { caseId: c.id });
                      clearActiveEvidenceView();
                      setActiveCaseId(c.id);
                      setActiveCaseAuditMatched(true);
                    })}
                  >
                    {activeCaseId === c.id
                      ? activeCaseAuditMatched
                        ? "Active case"
                        : "Reconfirm active"
                      : "Set active"}
                  </button>
                </div>
              ))
            ) : (
              <div className="empty">
                <FolderOpen />
                <p>No cases created yet.</p>
              </div>
            )}
          </section>
          <section className="panel">
            <div className="panelTitle">
              <h2>Active case records</h2>
              <span className="muted">
                {activeCaseId === null
                  ? "SELECT A CASE"
                  : `DC-${String(activeCaseId).padStart(5, "0")}`}
              </span>
            </div>
            {activeCaseId === null ? (
              <div className="empty">
                <FolderOpen />
                <p>Select a case to review its evidence and scans.</p>
              </div>
            ) : (
              <>
                <div className="panelTitle">
                  <h3>Evidence sources</h3>
                  <span className="muted">{caseEvidence.length} RECORDS</span>
                </div>
                {caseEvidence.length ? (
                  caseEvidence.map((record) => (
                    <div className="case" key={record.id}>
                      <code>EV-{String(record.id).padStart(6, "0")}</code>
                      <h3 title={record.path}>{record.name}</h3>
                      <span title={record.sha256 ?? record.path}>
                        {record.status.toUpperCase()}
                        {record.sha256 ? ` · ${record.sha256.slice(0, 12)}…` : ""}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="muted caseEmpty">
                    No source images recorded in this case.
                  </p>
                )}
                <div className="panelTitle">
                  <h3>Completed NTFS scans</h3>
                  <span className="muted">{caseScans.length} SESSIONS</span>
                </div>
                {caseScans.length ? (
                  caseScans.map((scan) => {
                    const evidence = caseEvidence.find(
                      (record) => record.id === scan.evidence_id,
                    );
                    return (
                      <div className="case" key={scan.id}>
                        <code>SC-{String(scan.id).padStart(6, "0")}</code>
                        <h3
                          title={
                            evidence?.path ?? `Evidence record ${scan.evidence_id}`
                          }
                        >
                          {scan.found} candidates
                        </h3>
                        <span title={`SHA-256 ${scan.source_sha256}`}>
                          {evidence?.name ?? `Evidence ${scan.evidence_id}`} ·{" "}
                          {scan.records} records · {scan.skipped} skipped
                          {scan.limited ? " · partial" : ""}
                        </span>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => showArchivedResults(scan.id, 0)}
                        >
                          Review saved results
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <p className="muted caseEmpty">
                    No completed scans recorded in this case.
                  </p>
                )}
                <div className="panelTitle">
                  <h3>Completed FAT32 directory scans</h3>
                  <span className="muted">{fat32CaseScans.length} SESSIONS</span>
                </div>
                {fat32CaseScans.length ? (
                  fat32CaseScans.map((scan) => {
                    const evidence = caseEvidence.find(
                      (record) => record.id === scan.evidence_id,
                    );
                    return (
                      <div className="case" key={scan.id}>
                        <code>FAT-{String(scan.id).padStart(6, "0")}</code>
                        <h3 title={evidence?.path ?? `Evidence record ${scan.evidence_id}`}>
                          {scan.deleted} deleted entries
                        </h3>
                        <span title={`SHA-256 ${scan.source_sha256}`}>
                          {evidence?.name ?? `Evidence ${scan.evidence_id}`} · {scan.found} total · offset {scan.volume_offset}
                        </span>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => showArchivedFat32Results(scan.id, 0)}
                        >
                          Review saved directory entries
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <p className="muted caseEmpty">
                    No FAT32 directory scans recorded in this case.
                  </p>
                )}
                {archivedFat32ScanId !== null && archivedFat32Page && (
                  <div className="archivedSnapshot">
                    <div className="panelTitle">
                      <h3>Saved FAT32 entries · FAT-{String(archivedFat32ScanId).padStart(6, "0")}</h3>
                      <span className="tag">ARCHIVE · READ ONLY</span>
                    </div>
                    <div className="archivedSourceIdentity">
                      <b>{selectedArchivedFat32Evidence?.name ?? `Evidence ${selectedArchivedFat32Scan?.evidence_id ?? "unknown"}`}</b>
                      <span>{selectedArchivedFat32Evidence?.path ?? "Recorded source path unavailable"}</span>
                      <code>Expected SHA-256 · {selectedArchivedFat32Scan?.source_sha256 ?? "unavailable"}</code>
                      {!archivedFat32SourceMatchesScan && (
                        <span className="archivedSourceWarning">
                          Evidence is unverified or no longer matches this FAT32 scan.
                        </span>
                      )}
                    </div>
                    <p className="warning" role="status">
                      This archived directory inventory is review-only. FAT32 file recovery and export are not yet available.
                    </p>
                    {archivedFat32Page.rows.map(({ path, entry }) => (
                      <div className="case" key={entry.source_offset}>
                        <code>{entry.deleted ? "DELETED" : "LIVE"} · 0x{entry.source_offset.toString(16)}</code>
                        <h3 title={path.join("/")}>{path.join("/") || "(unnamed)"}</h3>
                        <span>{entry.size.toLocaleString()} bytes · cluster {entry.first_cluster}</span>
                      </div>
                    ))}
                    <div className="actions archivedPagination">
                      <button
                        disabled={archivedFat32PageIndex === 0}
                        onClick={() => showArchivedFat32Results(archivedFat32ScanId, Math.max(0, archivedFat32PageIndex - 1))}
                      >
                        Previous
                      </button>
                      <span>{archivedFat32Page.total.toLocaleString()} entries · page {archivedFat32PageIndex + 1}</span>
                      <button
                        disabled={(archivedFat32PageIndex + 1) * 50 >= archivedFat32Page.total}
                        onClick={() => showArchivedFat32Results(archivedFat32ScanId, archivedFat32PageIndex + 1)}
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
                <div className="panelTitle">
                  <h3>Completed exFAT directory scans</h3>
                  <span className="muted">{exfatCaseScans.length} SESSIONS</span>
                </div>
                {exfatCaseScans.length ? (
                  exfatCaseScans.map((scan) => {
                    const evidence = caseEvidence.find((record) => record.id === scan.evidence_id);
                    return (
                      <div className="case" key={scan.id}>
                        <code>EXF-{String(scan.id).padStart(6, "0")}</code>
                        <h3 title={evidence?.path ?? `Evidence record ${scan.evidence_id}`}>{scan.records} live entries</h3>
                        <span title={`SHA-256 ${scan.source_sha256}`}>
                          {evidence?.name ?? `Evidence ${scan.evidence_id}`} · volume offset {scan.volume_offset}
                        </span>
                        <button type="button" disabled={busy} onClick={() => showArchivedExfatResults(scan.id, 0)}>
                          Review saved directory entries
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <p className="muted caseEmpty">No exFAT directory scans recorded in this case.</p>
                )}
                {archivedExfatScanId !== null && archivedExfatPage && (
                  <div className="archivedSnapshot">
                    <div className="panelTitle">
                      <h3>Saved exFAT entries · EXF-{String(archivedExfatScanId).padStart(6, "0")}</h3>
                      <span className="tag">ARCHIVE · READ ONLY</span>
                    </div>
                    <div className="archivedSourceIdentity">
                      <b>{selectedArchivedExfatEvidence?.name ?? `Evidence ${selectedArchivedExfatScan?.evidence_id ?? "unknown"}`}</b>
                      <span>{selectedArchivedExfatEvidence?.path ?? "Recorded source path unavailable"}</span>
                      <code>Expected SHA-256 · {selectedArchivedExfatScan?.source_sha256 ?? "unavailable"}</code>
                      {!archivedExfatSourceMatchesScan && <span className="archivedSourceWarning">Evidence is unverified or no longer matches this exFAT scan.</span>}
                    </div>
                    <p className="warning" role="status">This archived exFAT inventory is read-only. Deleted entry sets are metadata leads only; their file contents are not recovered.</p>
                    {archivedExfatPage.rows.map(({ path, entry }) => (
                      <div className="case" key={entry.source_offset}>
                        <code>0x{entry.source_offset.toString(16).padStart(12, "0")}</code>
                        <h3 title={path.join("/")}>{path.join("/")}</h3>
                        <span>{entry.data_length.toLocaleString()} bytes · cluster {entry.first_cluster || "—"} · {entry.attributes & 0x10 ? "directory" : "file"}</span>
                      </div>
                    ))}
                    <div className="actions archivedPagination">
                      <button disabled={archivedExfatPageIndex === 0} onClick={() => showArchivedExfatResults(archivedExfatScanId, Math.max(0, archivedExfatPageIndex - 1))}>Previous</button>
                      <span>{archivedExfatPage.total.toLocaleString()} entries · page {archivedExfatPageIndex + 1}</span>
                      <button disabled={(archivedExfatPageIndex + 1) * 50 >= archivedExfatPage.total} onClick={() => showArchivedExfatResults(archivedExfatScanId, archivedExfatPageIndex + 1)}>Next</button>
                    </div>
                  </div>
                )}
                {archivedScanId !== null && archivedPage && (
                  <div className="archivedSnapshot">
                    <div className="panelTitle">
                      <h3>
                        Saved candidates · SC-
                        {String(archivedScanId).padStart(6, "0")}
                      </h3>
                      <span className="tag">ARCHIVE · READ ONLY</span>
                    </div>
                    <p className="muted archivedNotice">
                      This stored snapshot is review-only. Reopen its recorded evidence with
                      SHA-256 verification, then run a fresh scan before recovery.
                    </p>
                    <div className="archivedSourceIdentity">
                      <b>
                        {selectedArchivedEvidence?.name ??
                          `Evidence record ${selectedArchivedScan?.evidence_id ?? "unknown"}`}
                      </b>
                      <span>
                        {selectedArchivedEvidence?.path ??
                          "Recorded source path unavailable"}
                      </span>
                      <code
                        title={`SHA-256 ${selectedArchivedScan?.source_sha256 ?? "unavailable"}`}
                      >
                        Expected SHA-256 · {selectedArchivedScan?.source_sha256 ?? "unavailable"}
                      </code>
                      {!archivedSourceMatchesScan && (
                        <span className="archivedSourceWarning">
                          Evidence record is unverified or no longer matches this scan.
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      disabled={
                        busy ||
                        job.state === "running" ||
                        !archivedSourceMatchesScan
                      }
                      onClick={() => reopenArchivedSource(archivedScanId)}
                    >
                      Verify and reopen source
                    </button>
                    {archivedPage.rows.map((candidate: RecoveryCandidate) => (
                      <div className="case" key={candidate.id}>
                        <code>MFT-{candidate.id}</code>
                        <h3 title={candidate.notes.join(" · ")}>{candidate.name}</h3>
                        <span>
                          {bytes(candidate.size)} · {candidate.storage} · {candidate.allocation}
                        </span>
                      </div>
                    ))}
                    <div className="actions archivedPagination">
                      <button
                        disabled={archivedPageIndex === 0 || busy}
                        onClick={() => showArchivedResults(archivedScanId, archivedPageIndex - 1)}
                      >
                        Previous
                      </button>
                      <span className="muted">
                        {archivedPage.total === 0
                          ? "0 candidates"
                          : `${archivedPageIndex * 50 + 1}–${Math.min((archivedPageIndex + 1) * 50, archivedPage.total)} of ${archivedPage.total}`}
                      </span>
                      <button
                        disabled={(archivedPageIndex + 1) * 50 >= archivedPage.total || busy}
                        onClick={() => showArchivedResults(archivedScanId, archivedPageIndex + 1)}
                      >
                        Next
                      </button>
                      <button
                        disabled={busy}
                        onClick={() => {
                          setArchivedScanId(null);
                          setArchivedPage(null);
                        }}
                      >
                        Close
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </section>
        </>
      ) : page === "Settings" ? (
        <section className="panel">
          <div className="panelTitle">
            <h2>Engine configuration</h2>
            <span className="tag">PROTECTED DEFAULTS</span>
          </div>
          <div className="detail">
            <span>Source mode</span>
            <b>Read only</b>
            <span>Hash algorithm</span>
            <b>SHA-256</b>
            <span>Streaming buffer</span>
            <b>1 MiB / one worker</b>
            <span>Hex read limit</span>
            <b>4 KiB per request</b>
            <span>Privileged helper</span>
            <b>Not installed / unavailable</b>
            <span>Network processing</span>
            <b>None</b>
            <span>Case persistence</span>
            <b>Windows local application data</b>
          </div>
        </section>
      ) : page === "Reports" ? (
        <section className="panel">
          <div className="panelTitle">
            <h2>Forensic case report</h2>
            <span className="tag">JSON / HTML · AUDIT LINKED</span>
          </div>
          <div className="reportIntro">
            <p>
              Export the active case register, verified evidence metadata,
              completed NTFS scans, FAT32 directory scans, PNG/BMP/JPEG carving
              snapshots, hash-chained imaging/RAID records, and recovery export
              and package verification records as canonical JSON or a printable
              HTML report with the complete JSON data included.
            </p>
            <p className="muted">
              The report checks the local audit chain and records its head hash.
              It is not signed or externally anchored. Operation entries
              reproduce operator and tool audit records; they do not independently
              prove device identity, write blocking, array geometry, or recovery
              correctness.
            </p>
          </div>
          <div className="reportActions">
            <button
              className="primary"
              type="button"
              disabled={
                !native ||
                busy ||
                job.state === "running" ||
                activeCaseId === null ||
                !activeCaseAuditMatched
              }
              onClick={exportCaseReport}
            >
              Export active case report
            </button>
            {!native && (
              <span className="muted">
                Open the Windows desktop app to export a report.
              </span>
            )}
            {activeCaseId === null && (
              <span className="muted">Select a case before exporting.</span>
            )}
            {activeCaseId !== null && !activeCaseAuditMatched && (
              <span className="archivedSourceWarning">
                Reconfirm the active case before reporting.
              </span>
            )}
          </div>
          {caseReport && caseReport.case_id === activeCaseId && (
            <div className="reportResult">
              <b>Report exported · {caseReport.scans} NTFS scans · {caseReport.candidates} NTFS candidates · {caseReport.fat32_scans} FAT32 scans / {caseReport.directory_entries} entries · {caseReport.exfat_scans} exFAT scans / {caseReport.exfat_entries} entries · {caseReport.carve_scans} carving scans · {caseReport.carved_candidates} carved candidates · {caseReport.imaging_and_raid_operations} imaging/RAID events · {caseReport.recovery_operations} recovery export/verification events</b>
              <span>{caseReport.path}</span>
              <code>SHA-256 · {caseReport.sha256}</code>
            </div>
          )}
        </section>
      ) : page === "File Carving" ? (
        <>
          <section className="panel">
            <div className="panelTitle">
              <h2>Validated file carving</h2>
              <span className="tag">PNG + BMP + JPEG · FULL IMAGE</span>
            </div>
            <p className="muted">
              Searches the complete, SHA-256-verified image. PNG candidates pass chunk CRC checks and image decoding; JPEG candidates pass bounded marker parsing and pixel decoding; BMP candidates pass header, geometry, pixel-array, and bounded pixel-decode checks. Carving does not restore original names, paths, timestamps, or allocation state, or prove a file was deleted.
            </p>
            <div className="actions">
              <button className="primary" disabled={!source?.sha256 || busy || job.state === "running"} onClick={startCarving}>
                Scan image for supported file types
              </button>
              {!source?.sha256 && <span className="muted">Open evidence and calculate its SHA-256 first.</span>}
            </div>
            {carvePage && (
              <div className="carveResults">
                <div className="panelTitle">
                  <h3>{carvePage.total.toLocaleString()} validated candidates</h3>
                  <div className="actions">
                    <span className="muted">SCAN #{carvePage.scan_session_id}</span>
                    <button className="primary" disabled={!selectedCarves.length || selectedCarves.length > 1000 || busy || job.state === "running"} onClick={exportCarved}>
                      Export selected ({selectedCarves.length})
                    </button>
                  </div>
                </div>
                <div className="carveMetadata">
                  <span>Scanned {bytes(carvePage.scanned_bytes)}</span>
                  <code title={carvePage.source_sha256}>Source SHA-256 · {carvePage.source_sha256}</code>
                </div>
                {carvePage.candidates_limited && <div className="warning">Candidate display reached the 10,000-item cap. The scan completed, but its candidate list is incomplete.</div>}
                {carvePage.rows.length > 0 ? (
                  <div className="carveList">
                    {carvePage.rows.map((candidate) => (
                      <div className="carveRow" key={candidate.id}>
                        <div>
                          <input
                            type="checkbox"
                            aria-label={`Select ${candidate.format} at offset 0x${candidate.offset.toString(16)}`}
                            checked={selectedCarves.includes(candidate.id)}
                            disabled={busy || job.state === "running" || (!selectedCarves.includes(candidate.id) && selectedCarves.length >= 1000)}
                            onChange={(event) => setSelectedCarves((current) => event.target.checked ? [...new Set([...current, candidate.id])] : current.filter((id) => id !== candidate.id))}
                          />
                          <b>{candidate.format}</b><span>Offset 0x{candidate.offset.toString(16)}</span><span>{bytes(candidate.length)}</span>
                        </div>
                        <code title={candidate.sha256}>SHA-256 · {candidate.sha256}</code>
                        <button onClick={() => void inspectCarvedOffset(candidate.offset)} disabled={busy}>Inspect bytes</button>
                      </div>
                    ))}
                  </div>
                ) : <div className="empty"><h3>No validated files found</h3><p>No supported file candidates were produced for this image.</p></div>}
                <div className="actions">
                  <button disabled={busy || carvePageIndex === 0} onClick={() => setCarvePageIndex((index) => Math.max(0, index - 1))}>Previous</button>
                  <span className="muted">Page {carvePageIndex + 1} of {Math.max(1, Math.ceil(carvePage.total / 100))}</span>
                  <button disabled={busy || (carvePageIndex + 1) * 100 >= carvePage.total} onClick={() => setCarvePageIndex((index) => index + 1)}>Next</button>
                </div>
              </div>
            )}
          </section>
          {jobPanel}
        </>
      ) : page === "RAID Reconstruction" ? (
        <>
          <RaidPanel
            job={job}
            busy={busy}
            canReconstruct={activeCaseId !== null && activeCaseAuditMatched}
            run={run}
            onJob={setJob}
            onSource={setSource}
          />
          {jobPanel}
        </>
      ) : (
        <section className="panel">
          <div className="panelTitle">
            <h2>{page}</h2>
            <span className="tag">NOT AVAILABLE</span>
          </div>
          <div className="empty">
            <LockKeyhole size={32} />
            <h3>This capability is not implemented yet</h3>
            <p>
              This route is not available in this build. No operation or forensic result is generated here.
              <br />
              Use the available workspaces for supported evidence operations.
            </p>
            <button onClick={() => setPage("Image Workspace")}>
              Open evidence workspace <ChevronRight size={14} />
            </button>
          </div>
        </section>
      )}
      {page === "Disk Imaging" && jobPanel}
    </WorkspaceShell>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
);
