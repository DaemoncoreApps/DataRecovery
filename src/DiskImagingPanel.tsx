import { useEffect, useState } from "react";
import { Boxes, CircleAlert, RefreshCw, ShieldCheck } from "lucide-react";
import { command, native, type Job, type PhysicalDevice, type PhysicalDeviceInventory, type RecoveryExportVerification, type Source } from "./bridge";
import { bytes } from "./format";

const busNames: Record<number, string> = {
  0: "Unknown",
  1: "SCSI",
  2: "ATAPI",
  3: "ATA",
  4: "IEEE 1394",
  5: "SSA",
  6: "Fibre Channel",
  7: "USB",
  8: "RAID",
  9: "iSCSI",
  10: "SAS",
  11: "SATA",
  12: "SD",
  13: "MMC",
  14: "Virtual",
  15: "File backed virtual",
  16: "Storage Spaces",
  17: "NVMe",
  18: "SCM",
  19: "UFS",
  20: "NVMe over Fabrics",
};

function attestationKey(device: PhysicalDevice): string {
  return JSON.stringify([
    device.number,
    device.size_bytes,
    device.bytes_per_sector,
    device.vendor,
    device.product,
    device.revision,
    device.serial_number,
    device.bus_type,
    device.identity_error,
  ]);
}

interface Props {
  job: Job;
  busy: boolean;
  canAcquire: boolean;
  run: (action: () => Promise<void>) => void;
  onSource: (source: Source | null) => void;
  onJob: (job: Job) => void;
}

export function DiskImagingPanel({ job, busy, canAcquire, run, onSource, onJob }: Props) {
  const [devices, setDevices] = useState<PhysicalDevice[]>([]);
  const [probeFailures, setProbeFailures] = useState<PhysicalDeviceInventory["failures"]>([]);
  const [attestedDevices, setAttestedDevices] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [verification, setVerification] = useState<RecoveryExportVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const operationRunning = busy || job.state === "running";

  const refresh = async () => {
    if (!native) return;
    setAttestedDevices(new Set());
    setLoading(true);
    setMessage("");
    setDevices([]);
    setProbeFailures([]);
    try {
      const inventory = await command<PhysicalDeviceInventory>("list_physical_devices");
      setDevices(inventory.devices);
      setProbeFailures(inventory.failures);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const acquire = (device: PhysicalDevice) => {
    if (!attestedDevices.has(attestationKey(device))) {
      setMessage("Attest to this exact device after confirming it is offline and protected by a validated hardware write blocker.");
      return;
    }
    return run(async () => {
      setMessage("");
      setVerification(null);
      await command<boolean>("acquire_physical_device", {
        expectedDevice: device,
        hardwareWriteBlockerAttested: true,
      });
      onJob(await command<Job>("job_status"));
      onSource(await command<Source | null>("source_status"));
    });
  };

  const resume = (device: PhysicalDevice) => {
    if (!attestedDevices.has(attestationKey(device))) {
      setMessage("Attest to this exact device after confirming it is offline and protected by a validated hardware write blocker.");
      return;
    }
    return run(async () => {
      setMessage("");
      setVerification(null);
      await command<boolean>("resume_physical_device_acquisition", {
        expectedDevice: device,
        hardwareWriteBlockerAttested: true,
      });
      onJob(await command<Job>("job_status"));
      onSource(await command<Source | null>("source_status"));
    });
  };

  return (
    <>
      <section className="panel acquisitionPanel">
        <div className="panelTitle">
          <div className="panelHeading">
            <span className="panelIcon"><Boxes size={16} /></span>
            <h2>Physical device acquisition</h2>
          </div>
          <span className="tag">READ ONLY · HASH VERIFIED</span>
        </div>
        <div className="warning acquisitionWarning" role="note">
          <CircleAlert size={16} />
          <p>
            Software read-only access does not stop other processes or the device firmware from changing source data.
            Acquire an offline source through a validated hardware write blocker. Output must be saved to a different
            physical disk. Failed reads are retried at smaller ranges down to the reported sector size; only sectors
            that remain unreadable are zero-filled in the image and recorded in its error map.
          </p>
        </div>
        {!native ? (
          <p className="muted">Physical device acquisition is available only in the native Windows application.</p>
        ) : (
          <>
            <div className="panelTitle acquisitionDevicesTitle">
              <h3>Readable physical disks</h3>
              <button onClick={() => void refresh()} disabled={loading || operationRunning}>
                <RefreshCw size={14} /> {loading ? "Checking devices…" : "Refresh list"}
              </button>
            </div>
            {devices.length ? (
              <div className="acquisitionDeviceList">
                {devices.map((device) => (
                  <div className="acquisitionDevice" key={attestationKey(device)}>
                    <div>
                      <strong>{[device.vendor, device.product].filter(Boolean).join(" ") || "Unknown device"} · PhysicalDrive {device.number}</strong>
                      <span>{bytes(device.size_bytes)} · {device.bytes_per_sector.toLocaleString()} bytes/sector</span>
                      <span>Serial: {device.serial_number || "not reported by device"}{device.revision ? ` · Rev ${device.revision}` : ""}{device.bus_type !== null ? ` · ${busNames[device.bus_type] || `Bus ${device.bus_type}`}` : ""}</span>
                      {device.identity_error && <span className="muted">Stable device identity unavailable: {device.identity_error}</span>}
                      <label className="checkLabel acquisitionAttestation">
                        <input
                          type="checkbox"
                          checked={attestedDevices.has(attestationKey(device))}
                          onChange={(event) => setAttestedDevices((current) => {
                            const next = new Set(current);
                            if (event.target.checked) next.add(attestationKey(device));
                            else next.delete(attestationKey(device));
                            return next;
                          })}
                          disabled={operationRunning || !canAcquire}
                        />
                        <ShieldCheck size={15} />
                        I verified PhysicalDrive {device.number} is offline and protected by a validated hardware write blocker.
                      </label>
                    </div>
                    <div className="actions">
                      <button
                        className="primary"
                        disabled={operationRunning || !canAcquire || !attestedDevices.has(attestationKey(device))}
                        onClick={() => acquire(device)}
                      >
                        Acquire image
                      </button>
                      <button
                        disabled={operationRunning || !canAcquire || !attestedDevices.has(attestationKey(device))}
                        onClick={() => resume(device)}
                        title="Select a matching incomplete acquisition folder and revalidate its saved bytes before continuing"
                      >
                        Resume interrupted image
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty">
                <h3>{loading ? "Checking connected disks" : probeFailures.length ? "Physical disks need attention" : "No readable physical disks found"}</h3>
                {!probeFailures.length && <p>Connect the source through its write blocker, then refresh the device list.</p>}
              </div>
            )}
            {probeFailures.length > 0 && (
              <div className="warning" role="status">
                <strong>Some physical devices could not be inspected</strong>
                <ul>
                  {probeFailures.map((failure) => (
                    <li key={failure.number}>PhysicalDrive {failure.number}: {failure.message}</li>
                  ))}
                </ul>
                <p>Resolve the listed access or device issue, then refresh before starting acquisition.</p>
              </div>
            )}
            {!canAcquire && <p className="muted">Select or reconfirm an audit-matched case before acquisition.</p>}
          </>
        )}
        {message && <div className="warning" role="alert">{message}</div>}
      </section>
      {job.kind === "disk_acquisition" && job.output_directory && (
        <section className="panel acquisitionResult">
          <div className="panelTitle">
            <h2>{job.discovered ? "Partial acquisition package" : "Acquisition package"}</h2>
            <span className="tag">{job.discovered ? "READ ERRORS MAPPED" : "DESTINATION HASH VERIFIED"}</span>
          </div>
          <p>{job.message}</p>
          <code>{job.output_directory}</code>
          {job.sha256 && <code>Acquired image SHA-256 · {job.sha256}</code>}
          {job.discovered > 0 && <p className="muted">This partial image was not activated for filesystem analysis. Review read-errors.jsonl before any further use.</p>}
          <div className="actions">
            <button
              disabled={operationRunning || verifying}
              onClick={() => run(async () => {
                setVerification(null);
                setVerifying(true);
                try {
                  const result = await command<RecoveryExportVerification | null>("verify_recovery_export");
                  if (result) setVerification(result);
                } finally {
                  setVerifying(false);
                }
              })}
            >
              {verifying ? "Verifying image and package records…" : "Verify acquisition package"}
            </button>
          </div>
          {verification && (
            <div className={`recoveryVerification ${verification.state === "complete" ? "success" : "warning"}`} role="status">
              <strong>{verification.state === "complete" ? "Package verified" : "Partial package verified"}</strong>
              <span>{verification.failed} unreadable source ranges · image SHA-256 and package checksums match</span>
              <code>Checksum list SHA-256 · {verification.checksums_sha256}</code>
            </div>
          )}
        </section>
      )}
    </>
  );
}
