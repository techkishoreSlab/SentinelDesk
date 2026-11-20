import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type BannedRule, type ThreatStatus, fetchThreatStatus, listBanned } from "./api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

export function SecurityAdmin() {
  const [rules, setRules] = useState<BannedRule[] | null>(null);
  const [threat, setThreat] = useState<ThreatStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback((signal?: AbortSignal) => {
    Promise.all([listBanned(signal), fetchThreatStatus(signal)])
      .then(([banned, status]) => {
        setRules(banned);
        setThreat(status);
      })
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
    <section className="status-card" aria-labelledby="security-admin-title">
      <h2 id="security-admin-title">Security policy</h2>
      {threat && (
        <p className="muted">
          Threat check: {threat.mandatory ? "mandatory" : "optional"} · external provider{" "}
          {threat.externalConfigured ? threat.provider : "not configured"} (fail closed when
          indeterminate)
        </p>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {rules === null && !error && <p className="muted">Loading banned rules…</p>}
      {rules && rules.length === 0 && <p className="muted">No active banned rules.</p>}
      {rules && rules.length > 0 && (
        <ul className="device-list">
          {rules.map((r) => (
            <li key={r.id}>
              <strong>{r.reasonCode}</strong> <span className="badge badge-bad">{r.severity}</span>
              <span className="muted">
                {" "}
                {r.matchType}={r.matchValue}
              </span>
              <div className="muted">{r.publicMessage}</div>
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        onClick={() => {
          reload();
        }}
      >
        Refresh
      </button>
    </section>
  );
}
