import { type SyntheticEvent, useEffect, useState } from "react";

import { ApiError } from "../../lib/api";
import { listMyDevices } from "../catalogue/api";
import { type PreviewResult, previewSoftware } from "./api";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

function statusClass(status: string): string {
  if (status === "AUTO_APPROVE" || status === "ALLOW" || status === "READY") return "notice";
  if (status === "NEEDS_CLARIFICATION" || status === "UNKNOWN_INTENT") return "muted";
  return "form-error";
}

export function PreviewPanel() {
  const [raw, setRaw] = useState("Install Visual Studio Code");
  const [devices, setDevices] = useState<{ id: string; deviceName: string; status: string }[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [result, setResult] = useState<PreviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    listMyDevices(controller.signal)
      .then((rows) => {
        setDevices(rows);
        const preferred = rows.find((d) => d.status === "ACTIVE") ?? rows[0];
        if (preferred) setDeviceId(preferred.id);
      })
      .catch(() => {
        /* panel still renders; submit will explain missing device */
      });
    return () => {
      controller.abort();
    };
  }, []);

  const submit = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!deviceId) {
      setError("Enroll a device before previewing a software request.");
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    previewSoftware(deviceId, raw.trim())
      .then(setResult)
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="status-card" aria-labelledby="preview-title">
      <h2 id="preview-title">Request preview</h2>
      <p className="muted">
        Natural-language install intent → catalogue match → policy evaluation. Does not create a
        request yet.
      </p>
      <form className="login-form" onSubmit={submit}>
        <label>
          What do you want to install?
          <input
            type="text"
            value={raw}
            maxLength={500}
            placeholder="e.g. Install VS Code"
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
          {busy ? "Previewing…" : "Preview"}
        </button>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <div role="status">
          <p className={statusClass(result.status)}>
            <strong>{result.status}</strong>
            {result.policy?.threatVerdict ? ` · threat ${result.policy.threatVerdict}` : ""}
          </p>
          <p>{result.explanation}</p>
          <p className="muted">
            Intent: {result.intent.softwareQuery} via {result.intent.source}
            {result.match?.displayName
              ? ` · matched ${result.match.displayName}${result.match.version ? ` ${result.match.version}` : ""}`
              : ""}
          </p>
          <p className="muted">
            Gemini: {result.geminiConfigured ? "configured" : "not configured"}
            {result.model ? ` (${result.model})` : ""} · tools: {result.toolTrace.join(" → ")}
          </p>
        </div>
      )}
    </section>
  );
}
