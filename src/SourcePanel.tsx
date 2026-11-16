import {
  ArrowUpRight,
  ChevronRight,
  FolderOpen,
  HardDrive,
  LockKeyhole,
  ShieldCheck,
} from "lucide-react";
import type { Source, Job } from "./bridge";
import { bytes } from "./format";

interface Props {
  source: Source | null;
  busy: boolean;
  job: Job;
  open: () => void;
  onSelectCase: () => void;
  canOpenEvidence: boolean;
  openPrompt: string;
  hash: () => void;
  onInspect: () => void;
  onScan: () => void;
}

export function SourcePanel({
  source,
  busy,
  job,
  open,
  onSelectCase,
  canOpenEvidence,
  openPrompt,
  hash,
  onInspect,
  onScan,
}: Props) {
  return (
    <section className="panel sourcePanel">
      <div className="panelTitle">
        <div className="panelHeading">
          <span className="panelIcon">
            <HardDrive size={16} strokeWidth={1.6} />
          </span>
          <h2>Evidence source</h2>
        </div>
        <span className="quietStatus">
          <span className={source ? "dot positive" : "dot"} />
          {source ? "Connected" : "Awaiting source"}
        </span>
      </div>
      {source ? (
        <>
          <div className="source">
            <span className="sourceDeviceIcon">
              <HardDrive size={28} strokeWidth={1.4} />
            </span>
            <div>
              <h3>{source.name}</h3>
              <p>{source.filesystem}</p>
            </div>
            <strong>{bytes(source.size)}</strong>
          </div>
          <div className="detail">
            <span>Case ID</span>
            <b>DC-{String(source.case_id).padStart(5, "0")}</b>
            <span>Access mode</span>
            <b>Read only; write handles denied while open</b>
            <span>Physical write protection</span>
            <b>Requires a hardware write blocker</b>
            <span>Filesystem recovery</span>
            <b>NTFS metadata recovery available for supported streams</b>
            <span>Source SHA-256</span>
            <b className="sourceDigest">
              {source.sha256 ?? "Required before metadata scanning"}
            </b>
          </div>
          <div className="actions">
            <button
              className="primary"
              onClick={onScan}
              disabled={busy || job.state === "running" || !source.sha256}
            >
              Find deleted NTFS files <ArrowUpRight size={14} />
            </button>
            <button onClick={onInspect}>
              Inspect bytes <ArrowUpRight size={14} />
            </button>
            <button onClick={hash} disabled={busy || job.state === "running"}>
              Calculate SHA-256
            </button>
          </div>
        </>
      ) : (
        <>
          <div className="evidenceEmpty">
            <div className="evidenceGlyph" aria-hidden="true">
              <div className="glyphRing" />
              <HardDrive size={35} strokeWidth={1.15} />
              <span className="glyphLock">
                <LockKeyhole size={12} />
              </span>
            </div>
            <h3>Bring your evidence into focus.</h3>
            <p>
              Open a disk image to inspect its structure,
              <br />
              examine raw data, and establish an image digest.
            </p>
            {!canOpenEvidence && (
              <p className="muted casePrerequisite" role="status">
                {openPrompt}
              </p>
            )}
            <button
              className="sourceBrowse"
              onClick={canOpenEvidence ? open : onSelectCase}
              disabled={busy || job.state === "running"}
            >
              <FolderOpen size={15} />
              {canOpenEvidence ? "Select evidence image" : openPrompt}
              <ChevronRight size={13} />
            </button>
            <div className="formatChips" aria-label="Supported image formats">
              {["IMG", "DD", "RAW", "BIN"].map((format) => (
                <span key={format}>{format}</span>
              ))}
            </div>
          </div>
          <div className="sourceReassurance">
            <ShieldCheck size={13} />
            <span>Read-only access</span>
            <span className="miniDivider" />
            <span>Processed on this device</span>
          </div>
        </>
      )}
    </section>
  );
}
