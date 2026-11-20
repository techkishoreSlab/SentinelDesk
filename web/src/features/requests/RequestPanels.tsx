import { type SyntheticEvent, useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "../../lib/api";
import { listMyDevices } from "../catalogue/api";
import {
  type ApprovalItem,
  type SoftwareRequest,
  cancelRequest,
  decideApproval,
  listMyRequests,
  listPendingApprovals,
  submitRequest,
} from "./api";
import { requestTimeline } from "./timeline";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return "req-" + String(Date.now()) + "-" + Math.random().toString(16).slice(2);
}

export function SubmitRequestPanel() {
  const [raw, setRaw] = useState("Install git");
  const [devices, setDevices] = useState<{ id: string; deviceName: string; status: string }[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [result, setResult] = useState<SoftwareRequest | null>(null);
  const [items, setItems] = useState<SoftwareRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback((signal?: AbortSignal) => {
    listMyRequests(signal)
      .then(setItems)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(messageOf(err));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    listMyDevices(controller.signal)
      .then((rows) => {
        setDevices(rows);
        const preferred = rows.find((d) => d.status === "ACTIVE") ?? rows[0];
        if (preferred) setDeviceId(preferred.id);
      })
      .catch(() => undefined);
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!deviceId) {
      setError("Enroll a device before submitting a request.");
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    submitRequest(deviceId, raw.trim(), newIdempotencyKey())
      .then((row) => {
        setResult(row);
        reload();
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const onCancel = (id: string) => {
    setBusy(true);
    setError(null);
    cancelRequest(id)
      .then(() => {
        reload();
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="request-submit-title">
      <h2 id="request-submit-title">Software request</h2>
      <p className="muted">
        Creates a tracked request (approval / auto-approve / block). Not an install yet.
      </p>
      <form className="login-form" onSubmit={submit}>
        <label>
          What do you want to install?
          <input
            type="text"
            value={raw}
            maxLength={500}
            onChange={(e) => {
              setRaw(e.target.value);
            }}
          />
        </label>
        {devices.length > 0 && (
          <label>
            Device
            <select
              value={deviceId}
              onChange={(e) => {
                setDeviceId(e.target.value);
              }}
            >
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.deviceName} ({d.status})
                </option>
              ))}
            </select>
          </label>
        )}
        <button type="submit" disabled={busy || !raw.trim() || !deviceId}>
          {busy ? "Submitting…" : "Submit request"}
        </button>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div className="notice" role="status">
          <p>
            {result.status}
            {result.softwareName ? ` · ${result.softwareName}` : ""}
            {result.version ? ` ${result.version}` : ""}
            {result.replayed ? " · replayed" : ""} — {result.explanation ?? result.decisionReason}
          </p>
          <p className="muted">
            Request ID: <code>{result.id}</code>
          </p>
          <ol className="timeline" aria-label="Request progress">
            {requestTimeline(result.status).map((step) => (
              <li key={step.id} className={`timeline-step timeline-${step.state}`}>
                {step.label}
              </li>
            ))}
          </ol>
        </div>
      )}
      {items && items.length === 0 && <p className="muted">No recent requests yet.</p>}
      {items && items.length > 0 && (
        <ul className="device-list">
          {items.map((row) => (
            <li key={row.id}>
              <strong>{row.status}</strong>{" "}
              <span className="muted">
                {row.softwareName ?? row.rawRequest}
                {row.version ? ` ${row.version}` : ""}
              </span>
              <ol className="timeline timeline-compact" aria-label={`Progress for ${row.status}`}>
                {requestTimeline(row.status).map((step) => (
                  <li key={step.id} className={`timeline-step timeline-${step.state}`}>
                    {step.label}
                  </li>
                ))}
              </ol>
              {(row.status === "AWAITING_APPROVAL" ||
                row.status === "QUEUED" ||
                row.status === "READY_TO_INSTALL") && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    onCancel(row.id);
                  }}
                >
                  Cancel
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function relativeTime(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${String(Math.floor(seconds / 60))}m ago`;
  if (seconds < 86_400) return `${String(Math.floor(seconds / 3600))}h ago`;
  return `${String(Math.floor(seconds / 86_400))}d ago`;
}

export function ApprovalQueue({
  onPendingChange,
}: {
  onPendingChange?: (count: number) => void;
} = {}) {
  const [items, setItems] = useState<ApprovalItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const onPendingChangeRef = useRef(onPendingChange);
  useEffect(() => {
    onPendingChangeRef.current = onPendingChange;
  }, [onPendingChange]);

  const reload = useCallback((signal?: AbortSignal) => {
    listPendingApprovals(signal)
      .then((rows) => {
        setItems(rows);
        onPendingChangeRef.current?.(rows.length);
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(messageOf(err));
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") reload();
    }, 4000);
    const onVis = () => {
      if (document.visibilityState === "visible") reload();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [reload]);

  const decide = (item: ApprovalItem, decision: "APPROVED" | "REJECTED") => {
    setDecidingId(item.requestId);
    setError(null);
    decideApproval(item.requestId, decision, item.requestVersion)
      .then(() => {
        reload();
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setDecidingId(null);
      });
  };

  return (
    <section className="status-card approval-queue" aria-labelledby="approval-queue-title">
      <div className="approval-queue-head">
        <div>
          <h2 id="approval-queue-title">Approval queue</h2>
          <p className="muted">
            Review installs that require an approver. Counts stay live while this page is open.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => {
            reload();
          }}
        >
          Refresh
        </button>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {items === null && !error && <p className="muted">Loading…</p>}
      {items && items.length === 0 && (
        <div className="approval-empty" role="status">
          <p className="approval-empty-title">You are clear</p>
          <p className="muted">
            No pending approvals. New requests will appear here automatically.
          </p>
        </div>
      )}
      {items && items.length > 0 && (
        <ul className="approval-list">
          {items.map((item) => {
            const busy = decidingId === item.requestId;
            return (
              <li key={item.requestId} className="approval-card">
                <div className="approval-card-top">
                  <div>
                    <p className="approval-title">{item.softwareName ?? item.rawRequest}</p>
                    <p className="muted approval-meta">
                      {item.version ? `${item.version} · ` : ""}
                      {item.requesterEmail ?? "requester"} · {item.deviceName ?? "device"}
                      {item.createdAt ? ` · ${relativeTime(item.createdAt)}` : ""}
                    </p>
                  </div>
                  <span className="badge">Needs approval</span>
                </div>
                <div className="approval-chips">
                  {item.threatVerdict && <span className="chip">Threat {item.threatVerdict}</span>}
                  {item.sha256Prefix && <span className="chip">sha {item.sha256Prefix}…</span>}
                  {item.decisionReason && <span className="chip">{item.decisionReason}</span>}
                </div>
                <div className="approval-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={busy || decidingId !== null}
                    onClick={() => {
                      decide(item, "APPROVED");
                    }}
                  >
                    {busy ? "Working…" : "Approve"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={busy || decidingId !== null}
                    onClick={() => {
                      decide(item, "REJECTED");
                    }}
                  >
                    Reject
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
