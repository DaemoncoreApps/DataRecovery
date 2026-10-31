import { useState } from "react";
import { Shield, ShieldCheck, ShieldAlert } from "lucide-react";
import {
  command,
  type AuditVerification,
  type AuditCheckpoint,
  type AuditCheckpointVerification,
} from "./bridge";

export function AuditPanel({
  run,
  busy,
}: {
  run: (f: () => Promise<void>) => void;
  busy: boolean;
}) {
  const [result, setResult] = useState<AuditVerification | null>(null);
  const [checkpoint, setCheckpoint] = useState<AuditCheckpoint | null>(null);
  const [checkpointVerification, setCheckpointVerification] =
    useState<AuditCheckpointVerification | null>(null);
  const [expectedHeadSha256, setExpectedHeadSha256] = useState("");
  const expectedHead = expectedHeadSha256.trim();
  const anchorIsValid =
    expectedHead === "" || /^[0-9a-fA-F]{64}$/.test(expectedHead);
  return (
    <section className="panel">
      <div className="panelTitle">
        <h2>Activity audit verification</h2>
        <span className="tag">LOCAL SQLITE</span>
      </div>
      <div className="empty">
        {result?.valid && result.anchor_match !== false ? (
          <ShieldCheck size={34} />
        ) : result ? (
          <ShieldAlert size={34} />
        ) : (
          <Shield size={34} />
        )}
        {result ? (
          <>
            <h3>
              {result.valid
                ? result.anchor_match === true
                  ? "Audit chain matches the independent head hash"
                  : result.anchor_match === false
                    ? "Audit chain does not match the independent head hash"
                  : "Audit chain is internally consistent"
                : `Audit chain failed at record ${result.first_invalid_record}`}
            </h3>
            <p>
              {result.records_checked} records checked.{" "}
              {result.anchor_match === true
                ? "The independently retained head hash matches."
                : result.anchor_match === false
                  ? "The stored chain does not match the supplied independent head hash."
                  : "No independent head hash was compared, so a complete rewritten database cannot be detected."}
            </p>
            <code>Stored chain head · {result.head_sha256 || "empty log"}</code>
          </>
        ) : (
          <>
            <h3>Verify the local audit chain</h3>
            <p>
              Checks each event digest and its link to the previous record.
              Without a separately retained head hash, a complete database
              rewrite cannot be detected.
            </p>
          </>
        )}
        <div className="anchorComparison">
          <label htmlFor="expected-checkpoint-head">
            Expected chain-head SHA-256 from an independent record
          </label>
          <input
            id="expected-checkpoint-head"
            type="text"
            value={expectedHeadSha256}
            maxLength={64}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            placeholder="Optional · 64 hexadecimal characters"
            aria-describedby="checkpoint-anchor-guidance"
            aria-invalid={!anchorIsValid}
            onChange={(event) => {
              setExpectedHeadSha256(event.target.value);
              setResult(null);
              setCheckpointVerification(null);
            }}
          />
          <p id="checkpoint-anchor-guidance">
            Enter the head hash you retained separately. It can be compared
            with the live audit database or a checkpoint bundle.
          </p>
        </div>
        <button
          disabled={busy || !anchorIsValid}
          onClick={() =>
            run(async () => {
              setResult(null);
              setCheckpointVerification(null);
              setResult(
                await command<AuditVerification>("verify_audit", {
                  expectedHeadSha256: expectedHead || null,
                }),
              );
            })
          }
        >
          Verify audit log
        </button>
        <button
          disabled={busy}
          onClick={() =>
            run(async () => {
              setCheckpoint(null);
              setCheckpointVerification(null);
              const exported = await command<AuditCheckpoint | null>(
                "export_audit_checkpoint",
              );
              if (exported) setCheckpoint(exported);
            })
          }
        >
          Export verified checkpoint
        </button>
        <button
          disabled={busy || !anchorIsValid}
          onClick={() =>
            run(async () => {
              setCheckpointVerification(null);
              const verified = await command<AuditCheckpointVerification | null>(
                "verify_audit_checkpoint",
                { expectedHeadSha256: expectedHead || null },
              );
              if (verified) setCheckpointVerification(verified);
            })
          }
        >
          Verify checkpoint folder
        </button>
        {checkpointVerification && (
          <div className="auditCheckpoint">
            <b>
              Checkpoint package is internally consistent ·{" "}
              {checkpointVerification.records} events
            </b>
            <code>
              Chain head · {checkpointVerification.head_sha256 || "empty log"}
            </code>
            <p>
              {checkpointVerification.anchor_match
                ? "The supplied independent head hash matches."
                : "No independent head hash was compared."} A match only
              confirms consistency with the value supplied; preserve its source
              separately. This package is not digitally signed.
            </p>
          </div>
        )}
        {checkpoint && (
          <div className="auditCheckpoint">
            <b>Checkpoint exported · {checkpoint.records} events</b>
            <span>{checkpoint.directory}</span>
            <code>Chain head · {checkpoint.head_sha256 || "empty log"}</code>
            <code>Bundle checksums · {checkpoint.checksums_sha256}</code>
            <p>
              This checkpoint is unanchored. Preserve a copy and its head hash
              in independently controlled immutable storage.
            </p>
          </div>
        )}
      </div>
      <p className="panelFootnote">
        This detects changes within the stored chain. It cannot prove that the
        database itself was not replaced or rewritten.
      </p>
    </section>
  );
}
