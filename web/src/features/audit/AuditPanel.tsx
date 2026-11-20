import { type SyntheticEvent, useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { type AuditEvent, searchAudit, verifyAuditChain } from "./api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

export function AuditPanel() {
  const [items, setItems] = useState<AuditEvent[] | null>(null);
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [chain, setChain] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(
    (signal?: AbortSignal) => {
      const params: { action?: string; result?: string } = {};
      const actionFilter = action.trim();
      const resultFilter = result.trim();
      if (actionFilter) params.action = actionFilter;
      if (resultFilter) params.result = resultFilter;
      searchAudit(params, signal)
        .then((page) => {
          setItems(page.items);
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(messageOf(err));
        });
    },
    [action, result],
  );

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);

  const onSearch = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    reload();
  };

  const onVerify = () => {
    setBusy(true);
    setChain(null);
    verifyAuditChain()
      .then((v) => {
        setChain(
          v.valid
            ? `Chain valid (${String(v.eventsChecked)} events checked).`
            : `Chain INVALID at seq ${v.firstInvalidSeq == null ? "?" : String(v.firstInvalidSeq)}.`,
        );
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="audit-title">
      <h2 id="audit-title">Audit history</h2>
      <p className="muted">Read-only search. Hashes are tamper-evidence, not secrets.</p>
      <form className="filter-row" onSubmit={onSearch}>
        <label>
          Action
          <input
            type="text"
            value={action}
            placeholder="e.g. installation_job.completed"
            maxLength={60}
            onChange={(e) => {
              setAction(e.target.value);
            }}
          />
        </label>
        <label>
          Result
          <input
            type="text"
            value={result}
            placeholder="SUCCESS / FAILURE / DENIED"
            maxLength={16}
            onChange={(e) => {
              setResult(e.target.value);
            }}
          />
        </label>
        <button type="submit">Search</button>
        <button type="button" disabled={busy} onClick={onVerify}>
          Verify chain
        </button>
      </form>
      {chain && <p className="notice">{chain}</p>}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {items === null && !error && <p className="muted">Loading audit events…</p>}
      {items && items.length === 0 && <p className="muted">No matching audit events.</p>}
      {items && items.length > 0 && (
        <ul className="device-list audit-list">
          {items.map((e) => (
            <li key={e.id}>
              <strong>
                #{e.seq} {e.action}
              </strong>{" "}
              <span className={e.result === "SUCCESS" ? "badge badge-ok" : "badge badge-bad"}>
                {e.result}
              </span>
              <div className="muted">
                {new Date(e.occurredAt).toLocaleString()} · {e.actorType}
                {e.resourceType ? ` · ${e.resourceType}` : ""}
                {e.resourceId ? ` ${e.resourceId.slice(0, 8)}…` : ""}
                {e.reasonCode ? ` · ${e.reasonCode}` : ""}
              </div>
              {e.correlationId && (
                <div className="muted">
                  Correlation: <code>{e.correlationId}</code>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
