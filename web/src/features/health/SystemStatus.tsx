import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { fetchLive, fetchReady } from "./api";

type State =
  | { kind: "loading" }
  | { kind: "ready"; version: string; checks: string[] }
  | { kind: "degraded"; version: string | null; message: string; correlationId: string | null };

function describe(error: unknown): { message: string; correlationId: string | null } {
  if (error instanceof ApiError)
    return { message: error.message, correlationId: error.correlationId };
  return { message: "The service returned an unexpected response.", correlationId: null };
}

async function loadStatus(signal?: AbortSignal): Promise<State | null> {
  let version: string | null = null;
  try {
    version = (await fetchLive(signal)).version;
    const ready = await fetchReady(signal);
    return { kind: "ready", version, checks: Object.keys(ready.checks) };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return null;
    return { kind: "degraded", version, ...describe(error) };
  }
}

export function SystemStatus() {
  const [state, setState] = useState<State>({ kind: "loading" });

  const refresh = useCallback((signal?: AbortSignal) => {
    void loadStatus(signal).then((next) => {
      if (next) setState(next);
    });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal);
    return () => {
      controller.abort();
    };
  }, [refresh]);

  const retry = () => {
    setState({ kind: "loading" });
    refresh();
  };

  return (
    <section className="status-rail" aria-labelledby="system-status-title" aria-live="polite">
      <h2 id="system-status-title" className="status-rail-title">
        Control plane status
      </h2>
      {state.kind === "loading" && <p className="muted">Checking backend…</p>}
      {state.kind === "ready" && (
        <>
          <p className="status-rail-line">
            <span className="badge badge-ok">Ready</span>
            <span>Backend v{state.version}</span>
          </p>
          <ul className="checks">
            {state.checks.map((check) => (
              <li key={check}>{check}: ok</li>
            ))}
          </ul>
        </>
      )}
      {state.kind === "degraded" && (
        <>
          <p className="status-rail-line">
            <span className="badge badge-bad">Unavailable</span>
            <span>{state.message}</span>
          </p>
          {state.version && <p className="muted">Backend v{state.version} is running.</p>}
          {state.correlationId && (
            <p className="muted">
              Correlation ID: <code>{state.correlationId}</code>
            </p>
          )}
          <button type="button" className="btn btn-ghost" onClick={retry}>
            Retry
          </button>
        </>
      )}
    </section>
  );
}
