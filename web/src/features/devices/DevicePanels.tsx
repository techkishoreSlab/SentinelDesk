import { type SyntheticEvent, useCallback, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import {
  type Device,
  type EligibleOwner,
  type FleetDevice,
  type IssuedToken,
  QUARANTINE_REASONS,
  type QuarantineReason,
  createEnrollmentToken,
  fetchEligibleOwners,
  fetchFleet,
  fetchMyDevices,
  quarantineDevice,
} from "./api";

type Load<T> =
  { kind: "loading" } | { kind: "ready"; data: T } | { kind: "error"; message: string };

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

function useLoad<T>(fetcher: (signal?: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<Load<T>>({ kind: "loading" });
  const reload = useCallback(
    (signal?: AbortSignal) => {
      fetcher(signal)
        .then((data) => {
          setState({ kind: "ready", data });
        })
        .catch((error: unknown) => {
          if (error instanceof DOMException && error.name === "AbortError") return;
          setState({ kind: "error", message: messageOf(error) });
        });
    },
    [fetcher],
  );
  useEffect(() => {
    const controller = new AbortController();
    reload(controller.signal);
    return () => {
      controller.abort();
    };
  }, [reload]);
  return [state, reload] as const;
}

function formatTime(iso: string | null): string {
  if (!iso) return "never";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "unknown" : date.toLocaleString();
}

function StatusBadge({ status }: { status: string }) {
  const tone = status === "ACTIVE" ? "badge-ok" : "badge-bad";
  return <span className={`badge ${tone}`}>{status}</span>;
}

function DeviceRow({ device, owner }: { device: Device; owner?: string }) {
  return (
    <>
      <strong>{device.deviceName}</strong> <StatusBadge status={device.status} />
      <span className="muted">
        {" "}
        {owner ? `${owner} · ` : ""}
        {device.osFamily} {device.osVersion} · {device.architecture} · agent {device.agentVersion} ·
        last seen {formatTime(device.lastSeenAt)}
      </span>
    </>
  );
}

export function MyDevices() {
  const [state] = useLoad(fetchMyDevices);
  return (
    <section className="status-card" aria-labelledby="my-devices-title">
      <h2 id="my-devices-title">My devices</h2>
      {state.kind === "loading" && <p className="muted">Loading devices…</p>}
      {state.kind === "error" && (
        <p className="form-error" role="alert">
          {state.message}
        </p>
      )}
      {state.kind === "ready" &&
        (state.data.length === 0 ? (
          <p className="muted">No enrolled devices.</p>
        ) : (
          <ul className="device-list">
            {state.data.map((d) => (
              <li key={d.id}>
                <DeviceRow device={d} />
              </li>
            ))}
          </ul>
        ))}
    </section>
  );
}

export function EnrollDevice() {
  const [owners] = useLoad(fetchEligibleOwners);
  const [ownerId, setOwnerId] = useState("");
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    createEnrollmentToken(ownerId)
      .then(setIssued)
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="enroll-title">
      <h2 id="enroll-title">Enroll a device</h2>
      {issued ? (
        <div className="token-box">
          <p>
            One-time enrollment token for <strong>{issued.ownerEmail}</strong>, valid until{" "}
            {formatTime(issued.expiresAt)}. It is shown only once.
          </p>
          <code aria-label="Enrollment token">{issued.token}</code>
          <p className="muted">
            On the device, run <code>sentinel-agent enroll</code> and paste the token at the prompt.
            Do not put it on the command line or in chat.
          </p>
          <button
            type="button"
            onClick={() => {
              setIssued(null);
            }}
          >
            Done — hide token
          </button>
        </div>
      ) : (
        <form className="login-form" onSubmit={submit}>
          {owners.kind === "error" && (
            <p className="form-error" role="alert">
              {owners.message}
            </p>
          )}
          <label>
            Device owner
            <select
              value={ownerId}
              disabled={owners.kind !== "ready"}
              onChange={(e) => {
                setOwnerId(e.target.value);
              }}
            >
              <option value="">Select an employee…</option>
              {owners.kind === "ready" &&
                owners.data.map((o: EligibleOwner) => (
                  <option key={o.id} value={o.id}>
                    {o.displayName} ({o.email})
                  </option>
                ))}
            </select>
          </label>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button type="submit" disabled={busy || !ownerId}>
            {busy ? "Creating…" : "Create enrollment token"}
          </button>
        </form>
      )}
    </section>
  );
}

function QuarantineControl({ device, onDone }: { device: FleetDevice; onDone: () => void }) {
  const [reason, setReason] = useState<QuarantineReason | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (device.status !== "ACTIVE") return null;

  const quarantine = () => {
    if (!reason) return;
    setBusy(true);
    setError(null);
    quarantineDevice(device.id, reason)
      .then(onDone)
      .catch((err: unknown) => {
        setError(messageOf(err));
        setBusy(false);
      });
  };

  return (
    <span className="inline-control">
      <select
        aria-label={`Quarantine reason for ${device.deviceName}`}
        value={reason}
        onChange={(e) => {
          setReason(e.target.value as QuarantineReason | "");
        }}
      >
        <option value="">Reason…</option>
        {QUARANTINE_REASONS.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <button type="button" disabled={busy || !reason} onClick={quarantine}>
        {busy ? "Quarantining…" : "Quarantine"}
      </button>
      {error && (
        <span className="form-error" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}

export function FleetDevices() {
  const [state, reload] = useLoad(fetchFleet);
  return (
    <section className="status-card" aria-labelledby="fleet-title">
      <h2 id="fleet-title">Fleet devices</h2>
      {state.kind === "loading" && <p className="muted">Loading devices…</p>}
      {state.kind === "error" && (
        <p className="form-error" role="alert">
          {state.message}
        </p>
      )}
      {state.kind === "ready" &&
        (state.data.length === 0 ? (
          <p className="muted">No enrolled devices.</p>
        ) : (
          <ul className="device-list">
            {state.data.map((d) => (
              <li key={d.id}>
                <DeviceRow device={d} owner={d.ownerEmail} />{" "}
                <QuarantineControl
                  device={d}
                  onDone={() => {
                    reload();
                  }}
                />
              </li>
            ))}
          </ul>
        ))}
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
