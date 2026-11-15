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
      : job.kind === "fat32_scan"
        ? "FAT32 directory scan"
        : job.kind === "carving_scan"
          ? "PNG, BMP, and JPEG file carving scan"
          : job.kind === "carving_export"
            ? "Carved file export & verification"
        : job.kind === "fat32_recovery_export"
          ? "FAT32 recovery export"
      : job.kind === "recovery_export"
        ? "Recovery export & verification"
        : job.kind === "evidence_reopen"
          ? "Archived evidence verification"
          : job.kind === "case_report_export"
            ? "Forensic case report"
            : job.kind === "disk_acquisition"
              ? "Physical device acquisition"
              : job.kind === "raid_reconstruction"
                ? "RAID reconstruction"
            : "SHA-256 image digest";
  const percent = job.total ? (100 * job.processed) / job.total : 0;
  const canCancel =
    job.state === "running" &&
    job.kind !== "case_report_export" &&
    (job.kind !== "fat32_scan" || job.message?.startsWith("Rechecking the complete source SHA-256"));
  const status =
    job.state === "idle"
      ? "Idle"
      : job.state.charAt(0).toUpperCase() + job.state.slice(1);
  const ioDisclosure =
    job.kind === "disk_acquisition"
      ? "Physical source opened read-only · hardware write blocker required"
      : job.kind === "raid_reconstruction"
        ? "Member images read-only · output written to destination"
        : job.kind === "case_report_export"
          ? "Evidence database read · report written to destination"
          : job.kind === "recovery_export" ||
              job.kind === "fat32_recovery_export" ||
              job.kind === "carving_export"
            ? "Source image read-only · recovered files written to destination"
            : "Source image read-only";
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
        {canCancel && (
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
            {job.kind === "recovery_export" ||
            job.kind === "fat32_recovery_export" ||
            job.kind === "carving_export"
              ? "READ + VERIFY"
              : job.kind === "disk_acquisition"
                ? "ACQUIRE + VERIFY"
                : job.kind === "raid_reconstruction"
                  ? "READ + RECONSTRUCT + VERIFY"
              : job.kind === "case_report_export"
                ? "REPORT SIZE"
                : "TOTAL SIZE"}
          </span>
          <strong>{job.total ? bytes(job.total) : "—"}</strong>
        </div>
        <div>
          <span>PROGRESS</span>
          <strong>{job.total ? `${percent.toFixed(1)}%` : "—"}</strong>
        </div>
      </div>
      <progress
        className="progress"
        aria-label={`${operation} progress`}
        max={100}
        value={Math.min(percent, 100)}
      />
      <div className="jobFoot">
        <span>
          {job.kind === "ntfs_scan"
            ? `${job.discovered} candidates`
            : job.kind === "fat32_scan"
              ? `${job.discovered} deleted entries`
              : job.kind === "carving_scan"
                ? `${job.discovered} validated file candidates`
                : job.kind === "carving_export"
                  ? "Destination verification"
            : job.kind === "recovery_export" ||
              job.kind === "fat32_recovery_export"
              ? "Destination verification"
                : job.kind === "disk_acquisition"
                  ? `${job.discovered} read-error ranges`
                  : job.kind === "raid_reconstruction"
                    ? "Member and output image verification"
                : job.kind === "case_report_export"
                ? "Audit-linked JSON"
                : "SHA-256"}
        </span>
        <span className="miniDivider" />
        <span>{ioDisclosure}</span>
        <span className="jobFootState">
          {job.state === "running" ? "Processing" : "No active operation"}
        </span>
      </div>
      {job.output_directory && (
        <div className="hash">
          <span>
            <Check size={14} />
            {job.kind === "disk_acquisition" ? "Acquisition package" : job.kind === "raid_reconstruction" ? "RAID reconstruction package" : "Recovery output folder"}
          </span>
          <code>{job.output_directory}</code>
          <p>
            {job.kind === "raid_reconstruction"
              ? "Review manifest.json for array level, member order, offsets, member hashes, and reconstruction limits."
              : job.kind === "disk_acquisition"
              ? "See manifest.json, checksums.sha256, completion.json, and read-errors.jsonl. Partial images include zero-filled unreadable ranges and must not be treated as complete evidence."
              : "See inventory.jsonl for each file's status and hash, and summary.json for the operation outcome."}
          </p>
        </div>
      )}
      {job.sha256 && (
        <div className="hash">
          <span>
            <Check size={14} /> {job.kind === "disk_acquisition" ? "Acquired image digest verified" : job.kind === "raid_reconstruction" ? "Reconstructed image digest verified" : "Image digest calculated"}
          </span>
          <code>{job.sha256}</code>
          <p>
            {job.kind === "raid_reconstruction"
              ? "Digest verified against a second read of the reconstructed image; each member image was rehashed after reconstruction."
              : job.kind === "disk_acquisition"
              ? "Digest verified against a second read of the staged image. Source immutability still depends on offline handling and a validated hardware write blocker."
              : "A digest alone does not establish acquisition verification or source immutability."}
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
