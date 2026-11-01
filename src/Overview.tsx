import type { ReactNode } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  Activity,
  FolderOpen,
  HardDrive,
  Hexagon,
  Layers,
  LockKeyhole,
  ShieldCheck,
  FileSearch,
} from "lucide-react";
import type { Job, Source } from "./bridge";

export function Overview({
  source,
  job,
  caseCount,
  sourcePanel,
  jobPanel,
  open,
  setPage,
  busy,
}: {
  source: Source | null;
  job: Job;
  caseCount: number;
  sourcePanel: ReactNode;
  jobPanel: ReactNode;
  open: () => void;
  setPage: (page: string) => void;
  busy: boolean;
}) {
  return (
    <>
      <div className="stats">
        <div>
          <div className="statLabel">
            <HardDrive size={15} />
            Evidence sources
          </div>
          <div className="statValue">
            {source ? "01" : "00"}
            <span className="statBadge">
              {source ? "Image connected" : "None connected"}
            </span>
          </div>
          <small>
            {source ? source.name : "Connect a disk image to begin"}
          </small>
        </div>
        <div>
          <div className="statLabel">
            <FolderOpen size={15} />
            Case register
          </div>
          <div className="statValue">
            {String(caseCount).padStart(2, "0")}
            <button
              className="statLink"
              onClick={() => setPage("Case Management")}
              aria-label="Open case register"
            >
              <ArrowUpRight size={16} />
            </button>
          </div>
          <small>Stored on this workstation</small>
        </div>
        <div>
          <div className="statLabel">
            <Activity size={15} />
            Engine activity
          </div>
          <div className="statValue statText">
            {job.state === "running" ? "Working" : "Standby"}
            <span
              className={
                job.state === "running" ? "dot active" : "dot positive"
              }
            />
          </div>
          <small>
            {job.state === "running"
              ? "Processing evidence locally"
              : "Ready for your next operation"}
          </small>
        </div>
        <div>
          <div className="statLabel">
            <LockKeyhole size={15} />
            Evidence access
          </div>
          <div className="statValue statText">
            Read only
            <ShieldCheck size={18} className="positiveText" />
          </div>
          <small>Source writes are disabled</small>
        </div>
      </div>
      <div className="overviewGrid">
        <div className="overviewMain">
          {sourcePanel}
          {jobPanel}
        </div>
        <div className="overviewRail">
          <section className="panel workflowPanel">
            <div className="panelTitle">
              <div>
                <span className="sectionKicker">GUIDED WORKFLOW</span>
                <h2>Start with the source.</h2>
              </div>
              <span className="tinyIcon">
                <ArrowUpRight size={15} />
              </span>
            </div>
            <div className="workflowSteps">
              <button
                className="workflowStep"
                onClick={open}
                disabled={busy || job.state === "running"}
              >
                <span className="stepNumber">01</span>
                <div>
                  <h3>Open an evidence image</h3>
                  <p>Load a working copy for examination.</p>
                </div>
                <ArrowRight size={14} />
              </button>
              <button
                className="workflowStep"
                onClick={() => setPage("Partition Analysis")}
              >
                <span className="stepNumber">02</span>
                <div>
                  <h3>Understand the structure</h3>
                  <p>Inspect partition tables and boundaries.</p>
                </div>
                <ArrowRight size={14} />
              </button>
              <button
                className="workflowStep"
                onClick={() => setPage("Image Workspace")}
              >
                <span className="stepNumber">03</span>
                <div>
                  <h3>Establish an image digest</h3>
                  <p>Calculate SHA-256 before analysis.</p>
                </div>
                <ArrowRight size={14} />
              </button>
            </div>
            <div className="workflowNote">
              <ShieldCheck size={14} />
              <p>Work from an image. Preserve the original.</p>
            </div>
          </section>
          <section className="panel toolsPanel">
            <div className="panelTitle">
              <h2>Examination tools</h2>
              <span className="muted">AVAILABLE</span>
            </div>
            {[
              {
                page: "Recovery Workspace",
                icon: FileSearch,
                title: "NTFS recovery",
                description: "Find and extract deleted records",
              },
              {
                page: "Hex Inspector",
                icon: Hexagon,
                title: "Hex inspector",
                description: "Examine raw bytes",
              },
              {
                page: "Partition Analysis",
                icon: Layers,
                title: "Partition analysis",
                description: "Inspect MBR & GPT metadata",
              },
              {
                page: "Evidence Vault",
                icon: ShieldCheck,
                title: "Audit verification",
                description: "Check the activity chain",
              },
            ].map(({ page, icon: Icon, title, description }) => (
              <button
                className="toolRow"
                onClick={() => setPage(page)}
                key={page}
              >
                <span className="toolIcon">
                  <Icon size={17} strokeWidth={1.6} />
                </span>
                <div>
                  <h3>{title}</h3>
                  <p>{description}</p>
                </div>
                <ArrowUpRight size={14} />
              </button>
            ))}
          </section>
        </div>
      </div>
      <section className="capabilityNote">
        <span className="capabilityIcon">
          <ShieldCheck size={18} />
        </span>
        <div>
          <h3>Built around evidence integrity.</h3>
          <p>
            NTFS metadata recovery, image inspection, partition analysis,
            hashing, and audit verification are available for supported image
            layouts. Carving and physical acquisition remain in development.
          </p>
        </div>
        <span className="subtleBadge">LOCAL PROCESSING</span>
      </section>
    </>
  );
}
