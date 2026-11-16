import { useEffect, useRef, useState } from "react";
import type { Job } from "./bridge";

export interface ProgressMetrics {
  elapsedSeconds: number | null;
  throughputBytesPerSecond: number | null;
  etaSeconds: number | null;
}

interface ProgressSample {
  kind: string;
  state: string;
  startedAt: number;
  lastAt: number;
  lastProcessed: number;
  lastProgressAt: number;
  throughputBytesPerSecond: number | null;
}

const emptyMetrics: ProgressMetrics = {
  elapsedSeconds: null,
  throughputBytesPerSecond: null,
  etaSeconds: null,
};

export function formatDuration(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return "—";
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const remainder = total % 60;
  return hours > 0
    ? `${hours}h ${String(minutes).padStart(2, "0")}m`
    : `${minutes}m ${String(remainder).padStart(2, "0")}s`;
}

function metricsFor(job: Job, sample: ProgressSample, now: number): ProgressMetrics {
  const rate = sample.throughputBytesPerSecond;
  return {
    elapsedSeconds: Math.max(0, (now - sample.startedAt) / 1000),
    throughputBytesPerSecond: rate,
    etaSeconds:
      job.state === "running" &&
      job.total > job.processed &&
      rate !== null &&
      rate > 0
        ? (job.total - job.processed) / rate
        : null,
  };
}

export function useProgressMetrics(job: Job): ProgressMetrics {
  const jobRef = useRef(job);
  jobRef.current = job;
  const sampleRef = useRef<ProgressSample | null>(null);
  const [metrics, setMetrics] = useState(emptyMetrics);

  useEffect(() => {
    const initial = jobRef.current;
    if (initial.state === "idle") {
      sampleRef.current = null;
      setMetrics(emptyMetrics);
      return;
    }

    if (initial.state !== "running") {
      const sample = sampleRef.current;
      if (sample?.kind === initial.kind && sample.state === "running") {
        if (performance.now() - sample.lastProgressAt >= 3000) {
          sample.throughputBytesPerSecond = null;
        }
        sample.state = initial.state;
        setMetrics(metricsFor(initial, sample, performance.now()));
      }
      return;
    }

    const now = performance.now();
    let sample = sampleRef.current;
    if (!sample || sample.kind !== initial.kind || sample.state !== "running") {
      sample = {
        kind: initial.kind,
        state: "running",
        startedAt: now,
        lastAt: now,
        lastProcessed: initial.processed,
        lastProgressAt: now,
        throughputBytesPerSecond: null,
      };
      sampleRef.current = sample;
    }

    const update = () => {
      const current = jobRef.current;
      if (current.state !== "running" || current.kind !== sample?.kind || !sample) return;
      const at = performance.now();
      if (current.processed < sample.lastProcessed) {
        // A reset counter means a new operation was started before a terminal
        // status was observed. Do not carry its timing or rate into this job.
        sample.startedAt = at;
        sample.lastProgressAt = at;
        sample.throughputBytesPerSecond = null;
        sample.lastAt = at;
        sample.lastProcessed = current.processed;
      } else {
        const seconds = (at - sample.lastAt) / 1000;
        if (seconds >= 0.5) {
          const delta = current.processed - sample.lastProcessed;
          if (delta > 0) {
            const observedRate = delta / seconds;
            sample.throughputBytesPerSecond =
              sample.throughputBytesPerSecond === null
                ? observedRate
                : sample.throughputBytesPerSecond * 0.65 + observedRate * 0.35;
            sample.lastProgressAt = at;
          } else if (at - sample.lastProgressAt >= 3000) {
            sample.throughputBytesPerSecond = null;
          }
          sample.lastAt = at;
          sample.lastProcessed = current.processed;
        }
      }
      setMetrics(metricsFor(current, sample, at));
    };

    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [job.kind, job.state]);

  return metrics;
}
