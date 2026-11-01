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
} from "./bridge";
import "./style.css";
import { SourcePanel } from "./SourcePanel";
import { JobPanel } from "./JobPanel";
import { PartitionPanel } from "./PartitionPanel";
import { AuditPanel } from "./AuditPanel";
import { WorkspaceShell } from "./WorkspaceShell";
import { Overview } from "./Overview";
import { RecoveryPanel } from "./RecoveryPanel";
import { bytes } from "./format";
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
    [cases, setCases] = useState<Case[]>([]),
    [caseEvidence, setCaseEvidence] = useState<CaseEvidenceRecord[]>([]),
    [caseScans, setCaseScans] = useState<CaseScanSession[]>([]),
    [archivedScanId, setArchivedScanId] = useState<number | null>(null),
    [archivedPage, setArchivedPage] = useState<RecoveryPage | null>(null),
    [archivedPageIndex, setArchivedPageIndex] = useState(0),
    [activeCaseId, setActiveCaseId] = useState<number | null>(null),
    [activeCaseAuditMatched, setActiveCaseAuditMatched] = useState(true),
    [caseReport, setCaseReport] = useState<CaseReportExport | null>(null),
    [title, setTitle] = useState(""),
    [examiner, setExaminer] = useState(""),
    [offset, setOffset] = useState("0"),
    [data, setData] = useState<number[]>([]),
    [readOffset, setReadOffset] = useState(0),
    [busy, setBusy] = useState(false);
  const sourceGeneration = useRef(0);
  const run = async (action: () => Promise<void>) => {
    setError("");
    setBusy(true);
    try {
      await action();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (native) {
      command<Case[]>("list_cases")
        .then(setCases)
        .catch((e) => setError(String(e)));
      command<ActiveCaseState>("get_active_case_state")
        .then(({ case_id, audit_matched }) => {
          setActiveCaseId(case_id);
          setActiveCaseAuditMatched(audit_matched);
        })
        .catch((e) => {
          setActiveCaseAuditMatched(false);
          setError(String(e));
        });
    }
  }, []);
  useEffect(() => {
    if (!native || activeCaseId === null) {
      setCaseEvidence([]);
      setCaseScans([]);
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
    ])
      .then(([evidence, scans]) => {
        if (active) {
          setCaseEvidence(evidence);
          setCaseScans(scans);
        }
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [activeCaseId, job.state]);
  useEffect(() => {
    if (!native) return;
    const id = setInterval(() => {
      command<Job>("job_status")
        .then(setJob)
        .catch((e) => setError(String(e)));
      const generation = sourceGeneration.current;
      command<Source | null>("source_status")
        .then((currentSource) => {
          if (generation === sourceGeneration.current) setSource(currentSource);
        })
        .catch((e) => setError(String(e)));
    }, 700);
    return () => clearInterval(id);
  }, []);
  const clearActiveEvidenceView = () => {
    sourceGeneration.current += 1;
    setSource(null);
    setJob(emptyJob);
    setData([]);
    setOffset("0");
    setReadOffset(0);
    setCaseEvidence([]);
    setCaseScans([]);
    setArchivedScanId(null);
    setArchivedPage(null);
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
        setJob(emptyJob);
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
      ) : page === "Evidence Vault" ? (
        <AuditPanel run={(read) => run(read)} busy={busy} />
      ) : page === "Hex Inspector" ? (
        <section className="panel">
          <div className="panelTitle">
            <h2>Read-only hex inspector</h2>
            <span className="muted">512 BYTES / PAGE</span>
          </div>
          <div className="actions">
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
            <span className="tag">JSON · AUDIT LINKED</span>
          </div>
          <div className="reportIntro">
            <p>
              Export the active case register, verified evidence metadata,
              completed NTFS scan summaries, and candidate snapshots in one
              portable JSON file.
            </p>
            <p className="muted">
              The report checks the local audit chain and records its head hash.
              It is not signed or externally anchored, and it does not certify
              recovered file contents or acquisition provenance.
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
          {caseReport && (
            <div className="reportResult">
              <b>Report exported · {caseReport.scans} scans · {caseReport.candidates} candidates</b>
              <span>{caseReport.path}</span>
              <code>SHA-256 · {caseReport.sha256}</code>
            </div>
          )}
        </section>
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
              {page === "Disk Imaging"
                ? "Image acquisition and destination verification are planned. Existing image hashing is available below."
                : "This release supports raw image loading, hex reads, image hashing, and a local case register."}
              <br />
              No recovery or validation results are generated for unsupported
              operations.
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
    <App />
  </React.StrictMode>,
);
