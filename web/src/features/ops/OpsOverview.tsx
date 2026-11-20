import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type OpsMetrics, fetchOpsMetrics } from "./api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat-tile">
      <div className="stat-value">{value}</div>
      <div className="muted stat-label">{label}</div>
    </div>
  );
}

function nonzero(map: Record<string, number>): [string, number][] {
  return Object.entries(map)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
}

export function OpsOverview() {
  const [metrics, setMetrics] = useState<OpsMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback((signal?: AbortSignal) => {
    fetchOpsMetrics(signal)
      .then(setMetrics)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(messageOf(err));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);

  return (
    <section className="status-card" aria-labelledby="ops-overview-title">
      <h2 id="ops-overview-title">Operations overview</h2>
      <p className="muted">Live counts from the database (not decorative charts).</p>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {metrics === null && !error && <p className="muted">Loading metrics…</p>}
      {metrics && (
        <>
          <div className="stat-grid">
            <Stat label="Devices" value={metrics.devicesTotal} />
            <Stat label="Stale (&gt;15m)" value={metrics.devicesStale15m} />
            <Stat label="Awaiting approval" value={metrics.approvalsAwaiting} />
            <Stat label="Job queue" value={metrics.jobQueueDepth} />
            <Stat label="Installs succeeded" value={metrics.installOutcomes.succeeded ?? 0} />
            <Stat
              label="Failed verification"
              value={metrics.installOutcomes.failed_verification ?? 0}
            />
            <Stat label="Notification issues" value={metrics.notificationDeliveryIssues} />
          </div>
          <h3 className="subhead">Requests with activity</h3>
          {nonzero(metrics.requestsByStatus).length === 0 ? (
            <p className="muted">No requests recorded yet.</p>
          ) : (
            <ul className="device-list">
              {nonzero(metrics.requestsByStatus).map(([status, n]) => (
                <li key={status}>
                  <strong>{status}</strong> <span className="muted">{n}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="muted">Updated {new Date(metrics.generatedAt).toLocaleString()}</p>
        </>
      )}
      <button
        type="button"
        onClick={() => {
          setError(null);
          reload();
        }}
      >
        Refresh
      </button>
    </section>
  );
}
