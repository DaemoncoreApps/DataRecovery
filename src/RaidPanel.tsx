import { useState } from "react";
import { ArrowDown, ArrowUp, Database, HardDrive, Plus, ShieldCheck } from "lucide-react";
import { command, native, type Job, type RecoveryExportVerification, type Source } from "./bridge";

interface Props {
  job: Job;
  busy: boolean;
  canReconstruct: boolean;
  run: (action: () => Promise<void>) => void;
  onJob: (job: Job) => void;
  onSource: (source: Source | null) => void;
}

export function RaidPanel({ job, busy, canReconstruct, run, onJob, onSource }: Props) {
  const [members, setMembers] = useState<string[]>([]);
  const [level, setLevel] = useState<"raid0" | "raid1" | "raid5" | "raid6">("raid0");
  const [raid5Layout, setRaid5Layout] = useState("left_symmetric");
  const [dataOffset, setDataOffset] = useState("0");
  const [stripeSize, setStripeSize] = useState("65536");
  const [sectorSize, setSectorSize] = useState("512");
  const [verification, setVerification] = useState<RecoveryExportVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const operationRunning = busy || job.state === "running";
  const minimumMembers = level === "raid6" ? 4 : level === "raid5" ? 3 : 2;
  const memberCountReady = members.length >= minimumMembers;

  const chooseMembers = () => run(async () => {
    const selected = await command<string[]>("pick_raid_members");
    if (selected.length) setMembers([...new Set(selected)]);
  });

  const move = (index: number, direction: -1 | 1) => {
    setMembers((current) => {
      const target = index + direction;
      if (target < 0 || target >= current.length) return current;
      const updated = [...current];
      [updated[index], updated[target]] = [updated[target], updated[index]];
      return updated;
    });
  };

  const reconstruct = () => run(async () => {
    const offset = Number(dataOffset);
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new Error("Enter a valid member data offset in bytes.");
    }
    setVerification(null);
    const started = await command<boolean>("reconstruct_raid", {
      memberPaths: members,
      level,
      dataOffsetBytes: offset,
      layout: {
        stripeSizeBytes: level === "raid1" ? 0 : Number(stripeSize),
        raid5Layout,
      },
      bytesPerSector: Number(sectorSize),
    });
    if (started) {
      onJob(await command<Job>("job_status"));
      onSource(await command<Source | null>("source_status"));
    }
  });

  return (
    <>
      <section className="panel raidPanel">
        <div className="panelTitle">
          <div className="panelHeading"><span className="panelIcon"><Database size={16} /></span><h2>Operator-configured array</h2></div>
          <span className="tag">RAID 0 + RAID 1 + RAID 5/6</span>
        </div>
        <div className="warning" role="note">
          <ShieldCheck size={16} />
          <p>
            This does not identify RAID metadata automatically. Supply the correct member order, member data offset,
            sector size, stripe size, and parity layout from validated array metadata. RAID 5 requires every
            member and checks XOR parity. RAID 6 supports full-member Linux MD left-symmetric P/Q only and checks
            both parity syndromes. Parity agreement does not prove the selected layout or logical data
            order is correct. Confirm layout and member order from metadata and compare recovered files with
            independent references before forensic use. Missing-member reconstruction is not supported. The
            output is a derived image; keep every original member unchanged. RAID 1 reconstructs only when all
            selected member data regions match byte for byte.
          </p>
        </div>
        {!native ? (
          <div className="empty"><HardDrive /><h3>Native Windows application required</h3><p>Member selection and output disk checks are available in the installed desktop application.</p></div>
        ) : (
          <>
            <div className="raidControls">
              <label>Array level
                <select value={level} disabled={operationRunning} onChange={(event) => setLevel(event.target.value as "raid0" | "raid1" | "raid5" | "raid6")}>
                  <option value="raid0">RAID 0 · striped</option>
                  <option value="raid1">RAID 1 · mirrored</option>
                  <option value="raid5">RAID 5 · rotating parity</option>
                  <option value="raid6">RAID 6 · dual rotating parity (Linux MD left-symmetric)</option>
                </select>
              </label>
              {level === "raid5" && (
                <label>RAID 5 parity layout
                  <select value={raid5Layout} disabled={operationRunning} onChange={(event) => setRaid5Layout(event.target.value)}>
                    <option value="left_symmetric">Left-symmetric</option>
                    <option value="right_symmetric">Right-symmetric</option>
                    <option value="left_asymmetric">Left-asymmetric</option>
                    <option value="right_asymmetric">Right-asymmetric</option>
                  </select>
                </label>
              )}
              <label>Member data offset (bytes)
                <input value={dataOffset} disabled={operationRunning} onChange={(event) => setDataOffset(event.target.value)} inputMode="numeric" />
              </label>
              <label>Logical sector size
                <select value={sectorSize} disabled={operationRunning} onChange={(event) => setSectorSize(event.target.value)}>
                  <option value="512">512 bytes</option><option value="4096">4096 bytes</option>
                </select>
              </label>
              {level !== "raid1" && (
                <label>Stripe size per member
                  <select value={stripeSize} disabled={operationRunning} onChange={(event) => setStripeSize(event.target.value)}>
                    <option value="65536">64 KiB</option><option value="131072">128 KiB</option>
                    <option value="262144">256 KiB</option><option value="524288">512 KiB</option>
                    <option value="1048576">1 MiB</option><option value="2097152">2 MiB</option>
                  </select>
                </label>
              )}
            </div>
            <div className="panelTitle raidMembersHeading">
              <div><h3>Members in logical order</h3><p className="muted">Use the controller’s member order and the layout reported by validated array metadata.</p></div>
              <button disabled={operationRunning} onClick={chooseMembers}><Plus size={14} /> Choose member images</button>
            </div>
            {members.length ? (
              <div className="raidMemberList">
                {members.map((path, index) => (
                  <div className="raidMember" key={path}>
                    <b>{String(index + 1).padStart(2, "0")}</b><span title={path}>{path}</span>
                    <button aria-label={`Move member ${index + 1} up`} disabled={operationRunning || index === 0} onClick={() => move(index, -1)}><ArrowUp size={14} /></button>
                    <button aria-label={`Move member ${index + 1} down`} disabled={operationRunning || index === members.length - 1} onClick={() => move(index, 1)}><ArrowDown size={14} /></button>
                    <button aria-label={`Remove member ${index + 1}`} disabled={operationRunning} onClick={() => setMembers((current) => current.filter((_, item) => item !== index))}>Remove</button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty"><HardDrive /><h3>No member images selected</h3><p>Select at least {minimumMembers} raw member images for {level.toUpperCase()}. Original members are opened read only.</p></div>
            )}
            <div className="actions">
              <button className="primary" disabled={operationRunning || !canReconstruct || !memberCountReady} onClick={reconstruct}>
                Reconstruct {level === "raid0" ? "RAID 0" : level === "raid1" ? "RAID 1" : level === "raid5" ? "RAID 5" : "RAID 6"}
              </button>
              {!memberCountReady && members.length > 0 && <span className="muted">{level.toUpperCase()} requires at least {minimumMembers} member images; {members.length} selected.</span>}
              {!canReconstruct && <span className="muted">Select or reconfirm an audit-matched case first.</span>}
            </div>
          </>
        )}
      </section>
      {job.kind === "raid_reconstruction" && job.output_directory && (
        <section className="panel acquisitionResult">
          <div className="panelTitle"><h2>Reconstructed array image</h2><span className="tag">READ BACK HASH VERIFIED</span></div>
          <p>{job.message}</p><code>{job.output_directory}</code>
          <p className="muted">The image is registered as hashed evidence and is now the active source. Review manifest.json for member order, offsets, hashes, and reconstruction limitations.</p>
          {job.sha256 && <code>Reconstructed image SHA-256 · {job.sha256}</code>}
          <div className="actions">
            <button disabled={operationRunning || verifying} onClick={() => run(async () => {
              setVerification(null);
              setVerifying(true);
              try {
                const result = await command<RecoveryExportVerification | null>("verify_recovery_export");
                if (result) setVerification(result);
              } finally {
                setVerifying(false);
              }
            })}>{verifying ? "Verifying reconstructed image…" : "Verify reconstruction package"}</button>
          </div>
          {verification && <div className="recoveryVerification success" role="status"><strong>Reconstruction package verified</strong><span>{verification.records} member records · output image SHA-256 and package checksums match</span><code>Checksum list SHA-256 · {verification.checksums_sha256}</code></div>}
        </section>
      )}
    </>
  );
}
