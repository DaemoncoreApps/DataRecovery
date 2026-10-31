import { Activity, Check, Fingerprint, Square } from "lucide-react";
import type { Job } from "./bridge";
import { bytes } from "./format";

interface Props {
  job: Job;
  cancel: () => void;
}
export function JobPanel({ job, cancel }: Props) {
  const operation =
    job.kind === "ntfs_scan"
      ? "NTFS metadata scan"
      : job.kind === "recovery_export"
        ? "Recovery export & verification"
        : "SHA-256 image digest";
  const percent = job.total ? (100 * job.processed) / job.total : 0;
  const status =
    job.state === "idle"
      ? "Idle"
      : job.state.charAt(0).toUpperCase() + job.state.slice(1);
  return (
    <section className="panel jobPanel">
      <div className="panelTitle">
        <div className="panelHeading">
          <span className="panelIcon">
            <Activity size={16} strokeWidth={1.6} />
          </span>
          <h2>Operation monitor</h2>
        </div>
        <span
          className={
            job.state === "running" ? "statusPill running" : "statusPill"
          }
        >
          <span className={job.state === "running" ? "dot active" : "dot"} />
          {status}
        </span>
      </div>
      <div className="job">
        <span className="jobIcon">
          <Fingerprint size={23} strokeWidth={1.3} />
        </span>
        <div>
          <h3>
            {job.state === "idle"
              ? "Ready for your next operation"
              : `${operation} · ${status.toLowerCase()}`}
          </h3>
          <p>
            {job.state === "idle"
              ? "Open an image to hash, inspect, or scan supported NTFS metadata."
              : job.message ||
                "Processing locally through the native evidence engine."}
          </p>
        </div>
        {job.state === "running" && (
          <button onClick={cancel}>
            <Square size={12} /> Cancel
          </button>
        )}
      </div>
      <div className="jobMetrics">
        <div>
          <span>PROCESSED</span>
          <strong>{bytes(job.processed)}</strong>
        </div>
        <div>
          <span>
            {job.kind === "recovery_export" ? "READ + VERIFY" : "TOTAL SIZE"}
          </span>
          <strong>{job.total ? bytes(job.total) : "—"}</strong>
        </div>
        <div>
          <span>PROGRESS</span>
          <strong>{job.total ? `${percent.toFixed(1)}%` : "—"}</strong>
        </div>
      </div>
      <div
        className="progress"
        role="progressbar"
        aria-label={`${operation} progress`}
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div style={{ width: `${percent}%` }} />
      </div>
      <div className="jobFoot">
        <span>
          {job.kind === "ntfs_scan"
            ? `${job.discovered} candidates`
            : job.kind === "recovery_export"
              ? "Destination verification"
              : "SHA-256"}
        </span>
        <span className="miniDivider" />
        <span>Read only</span>
        <span className="jobFootState">
          {job.state === "running" ? "Processing" : "No active operation"}
        </span>
      </div>
      {job.output_directory && (
        <div className="hash">
          <span>
            <Check size={14} />
            Recovery output folder
          </span>
          <code>{job.output_directory}</code>
          <p>
            See inventory.jsonl for each file's status and hash, and
            summary.json for the operation outcome.
          </p>
        </div>
      )}
      {job.sha256 && (
        <div className="hash">
          <span>
            <Check size={14} /> Image digest calculated
          </span>
          <code>{job.sha256}</code>
          <p>
            A digest alone does not establish acquisition verification or source
            immutability.
          </p>
        </div>
      )}
      {job.error && (
        <div role="alert" className="warning">
          {job.error}
        </div>
      )}
    </section>
  );
}
