import { type SyntheticEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiError } from "../../lib/api";
import { listMyDevices } from "../catalogue/api";
import { previewSoftware, type PreviewResult } from "../preview/api";
import {
  type SoftwareRequest,
  cancelRequest,
  listMyRequests,
  submitRequest,
} from "../requests/api";
import {
  installHeadline,
  installPhases,
  isActiveInstallStatus,
  isTerminalRequestStatus,
} from "../requests/installPhase";
import { requestTimeline } from "../requests/timeline";
import {
  type ThreadContext,
  agentWelcome,
  friendlyPreviewCopy,
  planAgentTurn,
  updateThreadContext,
} from "./agentPersona";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "The service returned an unexpected response.";
}

function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return "req-" + String(Date.now()) + "-" + Math.random().toString(16).slice(2);
}

type DeviceOpt = { id: string; deviceName: string; status: string };

type Msg =
  | { id: string; role: "user"; text: string }
  | {
      id: string;
      role: "assistant";
      text: string;
      request?: SoftwareRequest;
      preview?: PreviewResult;
      error?: boolean;
      local?: boolean;
    };

const EMPTY_CTX: ThreadContext = {
  lastInstallPrompt: null,
  lastStatus: null,
  lastReason: null,
};

function contextFromRequest(row: SoftwareRequest): ThreadContext {
  return {
    lastInstallPrompt: row.rawRequest,
    lastStatus: row.status,
    lastReason: row.decisionReason,
  };
}

function requestToThread(row: SoftwareRequest): Msg[] {
  return [
    { id: `${row.id}-u`, role: "user", text: row.rawRequest },
    {
      id: `${row.id}-a`,
      role: "assistant",
      text: friendlyPreviewCopy(
        row.status,
        row.explanation ?? row.decisionReason ?? "Request recorded.",
        row.decisionReason,
      ),
      request: row,
    },
  ];
}

function statusBadgeClass(status: string): string {
  if (
    status === "SUCCEEDED" ||
    status === "QUEUED" ||
    status === "DISPATCHED" ||
    status === "RUNNING" ||
    status === "VERIFYING" ||
    status === "APPROVED" ||
    status === "AWAITING_APPROVAL"
  ) {
    return "badge badge-ok";
  }
  if (
    status.includes("FAIL") ||
    status === "BLOCKED" ||
    status === "REJECTED" ||
    status === "NOT_FOUND" ||
    status === "INCOMPATIBLE" ||
    status === "CANCELLED"
  ) {
    return "badge badge-bad";
  }
  return "badge";
}

function InstallActivity({
  req,
  busy,
  onCancel,
}: {
  req: SoftwareRequest;
  busy: boolean;
  onCancel: (id: string) => void;
}) {
  const active = isActiveInstallStatus(req.status);
  const awaiting = req.status === "AWAITING_APPROVAL";
  const phases = installPhases(req.status);
  const cancellable =
    req.status === "AWAITING_APPROVAL" ||
    req.status === "QUEUED" ||
    req.status === "READY_TO_INSTALL";

  return (
    <div
      className={
        active
          ? "agent-card install-activity install-activity-live"
          : awaiting
            ? "agent-card install-activity install-activity-paused"
            : "agent-card install-activity"
      }
      role="status"
      aria-live="polite"
    >
      <div className="install-activity-head">
        <span className={statusBadgeClass(req.status)}>{req.status}</span>
        <p className="install-headline">{installHeadline(req.status)}</p>
      </div>
      {(active || req.status === "SUCCEEDED" || req.status.includes("FAIL")) && (
        <>
          {active && (
            <div className="install-bar" aria-hidden="true">
              <span className="install-bar-fill" />
            </div>
          )}
          <ol className="install-phases" aria-label="Install phases">
            {phases.map((phase) => (
              <li
                key={phase.id}
                className={
                  phase.failed
                    ? "install-phase install-phase-failed"
                    : phase.active
                      ? "install-phase install-phase-active"
                      : phase.done
                        ? "install-phase install-phase-done"
                        : "install-phase"
                }
              >
                {phase.label}
              </li>
            ))}
          </ol>
        </>
      )}
      <p className="muted">
        Request ID: <code>{req.id}</code>
        {req.softwareName ? ` · ${req.softwareName}` : ""}
        {req.version ? ` ${req.version}` : ""}
      </p>
      <ol className="timeline timeline-compact" aria-label="Request progress">
        {requestTimeline(req.status).map((step) => (
          <li key={step.id} className={`timeline-step timeline-${step.state}`}>
            {step.label}
          </li>
        ))}
      </ol>
      {cancellable && (
        <button
          type="button"
          className="btn btn-secondary"
          disabled={busy}
          onClick={() => {
            onCancel(req.id);
          }}
        >
          Cancel request
        </button>
      )}
    </div>
  );
}

function AssistantBody({
  msg,
  busy,
  onCancel,
}: {
  msg: Extract<Msg, { role: "assistant" }>;
  busy: boolean;
  onCancel: (id: string) => void;
}) {
  const req = msg.request;
  const preview = msg.preview;
  return (
    <article className="msg msg-assistant">
      <div className="msg-avatar" aria-hidden="true">
        S
      </div>
      <div className="msg-body">
        <div className="msg-meta">
          <span className="agent-mark">Sentinel</span>
          <span className="muted">Agent</span>
        </div>
        <p className={msg.error ? "form-error msg-text" : "msg-text"}>{msg.text}</p>
        {preview && !msg.local && preview.status !== "UNKNOWN_INTENT" && (
          <div className="agent-card">
            <p>
              <span
                className={
                  preview.status === "AUTO_APPROVE" || preview.status === "ALLOW"
                    ? "badge badge-ok"
                    : preview.status === "NEEDS_CLARIFICATION"
                      ? "badge"
                      : "badge badge-bad"
                }
              >
                {preview.status}
              </span>
              {preview.policy?.threatVerdict ? (
                <span className="muted"> · threat {preview.policy.threatVerdict}</span>
              ) : null}
            </p>
            {preview.match?.displayName && (
              <p className="muted">
                Matched {preview.match.displayName}
                {preview.match.version ? ` ${preview.match.version}` : ""}
              </p>
            )}
          </div>
        )}
        {req && <InstallActivity req={req} busy={busy} onCancel={onCancel} />}
      </div>
    </article>
  );
}

export function AgentChat({
  displayName,
  history,
  selectedId,
  onHistoryChange,
  onSelect,
}: {
  displayName: string;
  history: SoftwareRequest[];
  selectedId: string | null;
  onHistoryChange: (rows: SoftwareRequest[]) => void;
  onSelect: (id: string | null) => void;
}) {
  const [devices, setDevices] = useState<DeviceOpt[]>([]);
  const [deviceId, setDeviceId] = useState("");
  const [draft, setDraft] = useState("");
  const [ctx, setCtx] = useState<ThreadContext>(() => {
    if (!selectedId) return EMPTY_CTX;
    const row = history.find((r) => r.id === selectedId);
    return row ? contextFromRequest(row) : EMPTY_CTX;
  });
  const [messages, setMessages] = useState<Msg[]>(() => {
    if (selectedId) {
      const row = history.find((r) => r.id === selectedId);
      return row ? requestToThread(row) : [];
    }
    return [
      {
        id: "welcome",
        role: "assistant",
        text: agentWelcome(displayName),
        local: true,
      },
    ];
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"ask" | "submit">("submit");
  const scroller = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const ctxRef = useRef(ctx);

  useEffect(() => {
    ctxRef.current = ctx;
  }, [ctx]);

  useEffect(() => {
    const controller = new AbortController();
    listMyDevices(controller.signal)
      .then((rows) => {
        setDevices(rows);
        const preferred = rows.find((d) => d.status === "ACTIVE") ?? rows[0];
        if (preferred) setDeviceId(preferred.id);
      })
      .catch(() => undefined);
    return () => {
      controller.abort();
    };
  }, []);

  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, busy]);

  const reloadHistory = useCallback(() => {
    return listMyRequests().then((rows) => {
      onHistoryChange(rows);
      return rows;
    });
  }, [onHistoryChange]);

  const trackedRequestId = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i -= 1) {
      const msg = messages[i];
      if (msg && msg.role === "assistant" && msg.request) return msg.request.id;
    }
    return selectedId;
  }, [messages, selectedId]);

  const trackedStatus = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i -= 1) {
      const msg = messages[i];
      if (msg && msg.role === "assistant" && msg.request) return msg.request.status;
    }
    if (selectedId) {
      return history.find((r) => r.id === selectedId)?.status ?? null;
    }
    return null;
  }, [messages, selectedId, history]);

  useEffect(() => {
    if (!trackedRequestId || !trackedStatus || isTerminalRequestStatus(trackedStatus)) return;

    const applyRow = (row: SoftwareRequest) => {
      setMessages((prev) =>
        prev.map((msg) => {
          if (msg.role !== "assistant" || !msg.request || msg.request.id !== row.id) return msg;
          if (msg.request.status === row.status) return msg;
          return {
            ...msg,
            text: friendlyPreviewCopy(
              row.status,
              row.explanation ?? row.decisionReason ?? msg.text,
              row.decisionReason,
            ),
            request: row,
          };
        }),
      );
      setCtx(contextFromRequest(row));
    };

    const tick = () => {
      if (document.visibilityState !== "visible") return;
      listMyRequests()
        .then((rows) => {
          onHistoryChange(rows);
          const row = rows.find((r) => r.id === trackedRequestId);
          if (row) applyRow(row);
        })
        .catch(() => undefined);
    };

    tick();
    const timer = window.setInterval(tick, 4000);
    const onVis = () => {
      if (document.visibilityState === "visible") tick();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [trackedRequestId, trackedStatus, onHistoryChange]);

  const onCancel = (id: string) => {
    setBusy(true);
    cancelRequest(id)
      .then(() => reloadHistory())
      .then((rows) => {
        const row = rows.find((r) => r.id === id);
        if (row) {
          setMessages(requestToThread(row));
          setCtx(contextFromRequest(row));
          onSelect(row.id);
        }
      })
      .catch((err: unknown) => {
        setError(messageOf(err));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const appendAssistant = (msg: Omit<Extract<Msg, { role: "assistant" }>, "role">) => {
    setMessages((prev) => [...prev, { role: "assistant", ...msg }]);
  };

  const runInstall = (prompt: string, resumeNote?: string) => {
    if (resumeNote) {
      appendAssistant({
        id: `a-resume-${String(Date.now())}`,
        text: resumeNote,
        local: true,
      });
    }
    if (!deviceId) {
      appendAssistant({
        id: `a-nodevice-${String(Date.now())}`,
        text:
          "I'd love to help install that — first enroll an active device (Tools → My devices / Enroll), " +
          "then say “try again”.",
        local: true,
      });
      return;
    }

    setBusy(true);
    const run =
      mode === "ask"
        ? previewSoftware(deviceId, prompt)
        : submitRequest(deviceId, prompt, newIdempotencyKey());

    void run
      .then(async (result) => {
        if (mode === "ask") {
          const preview = result as PreviewResult;
          const reason = preview.policy?.reasonCode ?? preview.status;
          setCtx(updateThreadContext(ctxRef.current, prompt, preview.status, reason));
          appendAssistant({
            id: `a-${String(Date.now())}`,
            text: friendlyPreviewCopy(preview.status, preview.explanation, reason),
            preview,
            local: preview.status === "UNKNOWN_INTENT",
          });
        } else {
          const row = result as SoftwareRequest;
          const rows = await reloadHistory();
          const latest = rows.find((r) => r.id === row.id) ?? row;
          setCtx(updateThreadContext(ctxRef.current, prompt, latest.status, latest.decisionReason));
          appendAssistant({
            id: `a-${latest.id}`,
            text: friendlyPreviewCopy(
              latest.status,
              latest.explanation ??
                latest.decisionReason ??
                "Your request was accepted by the control plane.",
              latest.decisionReason,
            ),
            request: latest,
          });
          onSelect(latest.id);
        }
      })
      .catch((err: unknown) => {
        appendAssistant({
          id: `a-err-${String(Date.now())}`,
          text: messageOf(err),
          error: true,
        });
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const send = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const text = draft.trim();
    if (!text || busy) return;

    const plan = planAgentTurn(text, ctxRef.current);
    const userMsg: Msg = { id: `u-${String(Date.now())}`, role: "user", text };
    setMessages((prev) => (selectedId ? [userMsg] : [...prev, userMsg]));
    if (selectedId) onSelect(null);
    setDraft("");
    setError(null);

    if (plan.kind === "reply") {
      window.setTimeout(() => {
        appendAssistant({
          id: `a-local-${String(Date.now())}`,
          text: plan.text,
          local: true,
        });
      }, 220);
      return;
    }

    runInstall(plan.prompt, plan.resumeNote);
  };

  const onlyWelcome = messages.length === 1 && messages[0]?.id === "welcome";

  return (
    <div className="chat-shell">
      <div className="chat-scroll" ref={scroller} role="log" aria-relevant="additions">
        <div className="chat-thread">
          {onlyWelcome && (
            <header className="chat-hero">
              <p className="brand-mark brand-mark-chat">Sentinel</p>
              <h1 className="chat-empty-title">Your provisioning agent</h1>
            </header>
          )}
          {messages.map((msg) =>
            msg.role === "user" ? (
              <article key={msg.id} className="msg msg-user">
                <p className="msg-text">{msg.text}</p>
              </article>
            ) : (
              <AssistantBody key={msg.id} msg={msg} busy={busy} onCancel={onCancel} />
            ),
          )}
          {busy && (
            <article className="msg msg-assistant msg-thinking" aria-label="Sentinel is thinking">
              <div className="msg-avatar" aria-hidden="true">
                S
              </div>
              <div className="msg-body">
                <div className="msg-meta">
                  <span className="agent-mark">Sentinel</span>
                  <span className="muted">Thinking</span>
                </div>
                <p className="thinking-dots" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </p>
                <div className="agent-thinking-shimmer" aria-hidden="true" />
              </div>
            </article>
          )}
        </div>
        {onlyWelcome && (
          <div className="suggestion-row">
            {["Install git", "Install Visual Studio Code", "What is your name?", "Help"].map(
              (s) => (
                <button
                  key={s}
                  type="button"
                  className="suggestion-chip"
                  onClick={() => {
                    setDraft(s);
                    inputRef.current?.focus();
                  }}
                >
                  {s}
                </button>
              ),
            )}
          </div>
        )}
      </div>

      <form className="composer" onSubmit={send}>
        {error && (
          <p className="form-error composer-error" role="alert">
            {error}
          </p>
        )}
        <div className="composer-toolbar">
          <label className="composer-device">
            <span className="muted">Device</span>
            <select
              value={deviceId}
              onChange={(e) => {
                setDeviceId(e.target.value);
              }}
              disabled={devices.length === 0}
            >
              {devices.length === 0 && <option value="">No enrolled device</option>}
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.deviceName} ({d.status})
                </option>
              ))}
            </select>
          </label>
          <div className="mode-toggle" role="group" aria-label="Message mode">
            <button
              type="button"
              className={mode === "ask" ? "mode-btn mode-btn-active" : "mode-btn"}
              aria-pressed={mode === "ask"}
              onClick={() => {
                setMode("ask");
              }}
            >
              Ask
            </button>
            <button
              type="button"
              className={mode === "submit" ? "mode-btn mode-btn-active" : "mode-btn"}
              aria-pressed={mode === "submit"}
              onClick={() => {
                setMode("submit");
              }}
            >
              Submit
            </button>
          </div>
        </div>
        <div className="composer-box">
          <label className="sr-only" htmlFor="agent-composer">
            Message the provisioning agent
          </label>
          <textarea
            id="agent-composer"
            ref={inputRef}
            rows={1}
            maxLength={500}
            placeholder="Message Sentinel…"
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                e.currentTarget.form?.requestSubmit();
              }
            }}
          />
          <button
            type="submit"
            className="btn btn-primary composer-send"
            disabled={busy || !draft.trim()}
            aria-label="Send"
          >
            {busy ? "…" : "Send"}
          </button>
        </div>
        <p className="muted composer-hint">
          Continuous chat remembers your last install. “continue” / “try again” reuse it.
          {mode === "ask" ? " Ask = preview only." : " Submit = tracked request."}
        </p>
      </form>
    </div>
  );
}
