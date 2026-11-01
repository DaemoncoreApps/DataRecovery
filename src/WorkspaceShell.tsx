import type { ReactNode } from "react";
import {
  Activity,
  Boxes,
  ChevronRight,
  Database,
  FileSearch,
  Files,
  FolderOpen,
  HardDrive,
  Hexagon,
  Layers,
  LockKeyhole,
  Network,
  PanelLeft,
  Search,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { native, type Job, type Source } from "./bridge";
import { bytes } from "./format";

const groups = [
  {
    label: "Workspace",
    items: [
      ["Dashboard", Activity],
      ["Device Explorer", HardDrive],
      ["Case Management", FolderOpen],
    ],
  },
  {
    label: "Analysis",
    items: [
      ["Deep Scan", Search],
      ["Partition Analysis", Layers],
      ["Filesystem Analysis", Database],
      ["File Carving", FileSearch],
      ["Hex Inspector", Hexagon],
    ],
  },
  {
    label: "Evidence",
    items: [
      ["Disk Imaging", Boxes],
      ["RAID Reconstruction", Network],
      ["Recovery Workspace", Files],
      ["Evidence Vault", ShieldCheck],
      ["Reports", FileSearch],
    ],
  },
] as const;

export function WorkspaceShell({
  page,
  setPage,
  source,
  job,
  children,
}: {
  page: string;
  setPage: (page: string) => void;
  source: Source | null;
  job: Job;
  children: ReactNode;
}) {
  return (
    <div className="shell">
      <a href="#workspace-content" className="skipLink">
        Skip to workspace
      </a>
      <aside className="sidebar">
        <div className="brand">
          <img src="/logo.png" alt="DaemonCore: Data Recovery" />
          <span className="brandEdition">
            FORENSIC WORKSTATION <span>01</span>
          </span>
        </div>
        <nav className="workspaceNav" aria-label="Main navigation">
          {groups.map((group) => (
            <div className="navGroup" key={group.label}>
              <div className="navLabel">{group.label}</div>
              {group.items.map(([name, Icon]) => (
                <button
                  key={name}
                  className={page === name ? "selected" : ""}
                  aria-label={name}
                  aria-current={page === name ? "page" : undefined}
                  onClick={() => setPage(name)}
                >
                  <Icon size={16} strokeWidth={1.7} />
                  <span>{name}</span>
                  {page === name && <span className="navActiveMark" />}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebarBottom">
          <button
            className={
              page === "Settings"
                ? "sidebarSettings selected"
                : "sidebarSettings"
            }
            onClick={() => setPage("Settings")}
            aria-current={page === "Settings" ? "page" : undefined}
          >
            <Settings size={16} strokeWidth={1.7} /> <span>Settings</span>
          </button>
          <div className="sidebarFoot">
            <span className="sidebarShield">
              <ShieldCheck size={17} />
            </span>
            <div>
              Local by design<span>Private. Offline. In your control.</span>
            </div>
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="appBar">
          <div className="breadcrumbs">
            <PanelLeft size={15} />
            <span>Workspace</span>
            <ChevronRight size={12} />
            <strong>{page === "Dashboard" ? "Overview" : page}</strong>
          </div>
          <div className="appBarActions">
            <span className="environmentPill">
              <span className={native ? "dot positive" : "dot"} />
              {native ? "Local workspace" : "Browser preview"}
            </span>
            <span className="buildLabel">v0.1.0</span>
            <button
              className="iconButton"
              onClick={() => setPage("Settings")}
              aria-label="Open settings"
            >
              <Settings size={16} />
            </button>
          </div>
        </header>
        <main id="workspace-content">{children}</main>
        <footer className="statusBar">
          <span className="statusMode">
            <LockKeyhole size={11} /> Read-only mode
          </span>
          <span className="statusSource">
            <HardDrive size={11} />
            {source?.name || "No evidence source"}
          </span>
          <span className="statusRight">
            <span className={job.state === "running" ? "dot active" : "dot"} />
            {job.state === "running"
              ? "Operation in progress"
              : native
                ? "Engine ready"
                : "Preview mode"}
            <span className="statusDivider" />
            {bytes(job.processed)} processed
            <span className="statusDivider" />
            {native ? "Native engine" : "Browser preview"}
          </span>
        </footer>
      </div>
    </div>
  );
}
