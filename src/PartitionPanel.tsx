import { useState } from "react";
import { AlertTriangle, HardDrive, RefreshCw } from "lucide-react";
import { command, type PartitionReport, type Source } from "./bridge";
import { bytes } from "./format";

interface Props {
  source: Source | null;
  busy: boolean;
  analyze: (read: () => Promise<void>) => void;
}

export function PartitionPanel({ source, busy, analyze }: Props) {
  const [report, setReport] = useState<PartitionReport | null>(null);
  return (
    <section className="panel">
      <div className="panelTitle">
        <h2>Read only partition analysis</h2>
        <span className="tag">MBR / GPT</span>
      </div>
      {!source ? (
        <div className="empty">
          <HardDrive size={34} />
          <h3>Open a disk image to inspect its partition table</h3>
          <p>Only partition metadata is read. No changes are made.</p>
        </div>
      ) : (
        <>
          <div className="actions">
            <span className="muted">
              Source: {source.name} · {bytes(source.size)}
            </span>
            <button
              disabled={busy}
              onClick={() =>
                analyze(async () =>
                  setReport(
                    await command<PartitionReport>("analyze_partitions"),
                  ),
                )
              }
            >
              <RefreshCw size={14} /> Analyze table
            </button>
          </div>
          {report && (
            <>
              <div className="detail">
                <span>Table scheme</span>
                <b>{report.scheme}</b>
                <span>Logical sector size</span>
                <b>{report.sector_size} bytes</b>
                {report.scheme === "GPT" && (
                  <>
                    <span>Primary header and CRC</span>
                    <b>{report.primary_gpt_valid ? "Valid" : "Invalid"}</b>
                    <span>Backup header and CRC</span>
                    <b>{report.backup_gpt_valid ? "Valid" : "Invalid"}</b>
                  </>
                )}
              </div>
              {report.warnings.map((warning, i) => (
                <div className="warning" key={i}>
                  <AlertTriangle size={14} /> {warning}
                </div>
              ))}
              {report.partitions.length ? (
                <div className="tableScroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Index</th>
                        <th>Type identifier</th>
                        {report.scheme === "GPT" && <th>Unique partition GUID</th>}
                        <th>Start LBA</th>
                        <th>End LBA</th>
                        <th>Length</th>
                        <th>Filesystem signature</th>
                        <th>Boot flag</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.partitions.map((p) => (
                        <tr key={p.index}>
                          <td>{p.index}</td>
                          <td>
                            <code>{p.type_id}</code>
                          </td>
                          {report.scheme === "GPT" && (
                            <td>
                              <code>{p.unique_guid ?? "—"}</code>
                            </td>
                          )}
                          <td>{p.start_lba.toLocaleString()}</td>
                          <td>{p.end_lba.toLocaleString()}</td>
                          <td>{bytes(p.size_bytes)}</td>
                          <td>{p.filesystem_hint ?? "Not identified"}</td>
                          <td>{p.bootable ? "Active" : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">
                  <p>No valid partition entries were found.</p>
                </div>
              )}
              <p className="panelFootnote">
                exFAT boot-region checksums and geometry are validated.
                FAT32 identification checks BPB geometry, FAT capacity, cluster
                bounds, and the declared backup boot sector. NTFS checks only
                its boot signature and basic geometry. These checks do not
                validate directories or file contents. File recovery and
                partition-table repair are not provided here.
              </p>
            </>
          )}
        </>
      )}
    </section>
  );
}
