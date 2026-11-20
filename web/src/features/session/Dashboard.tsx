import { type ReactNode, useCallback, useMemo, useState } from "react";

import { ApiError } from "../../lib/api";
import { useVisiblePoll } from "../../lib/useVisiblePoll";
import { AuditPanel } from "../audit/AuditPanel";
import { AdminCatalogue, CatalogueSearch } from "../catalogue/CataloguePanels";
import { AgentChat } from "../chat/AgentChat";
import { useRequestHistory } from "../chat/useRequestHistory";
import { EnrollDevice, FleetDevices, MyDevices } from "../devices/DevicePanels";
import { OpsOverview } from "../ops/OpsOverview";
import { listPendingApprovals } from "../requests/api";
import { ApprovalQueue } from "../requests/RequestPanels";
import { SecurityAdmin } from "../security/SecurityPanels";
import { type Me, logout } from "./api";

type ToolId =
  | "chat"
  | "approvals"
  | "catalogue"
  | "security"
  | "fleet"
  | "ops"
  | "audit"
  | "enroll"
  | "devices";

type ToolItem = { id: ToolId; label: string };

const POLL_MS = 4000;

function buildTools(permissions: string[]): ToolItem[] {
  const can = (p: string) => permissions.includes(p);
  const items: ToolItem[] = [];
  if (can("device:read_own")) items.push({ id: "devices", label: "My devices" });
  if (can("approval:read")) items.push({ id: "approvals", label: "Approvals" });
  if (can("catalogue:read") || can("catalogue:manage")) {
    items.push({ id: "catalogue", label: "Catalogue" });
  }
  if (can("security:read")) items.push({ id: "security", label: "Security" });
  if (can("device:manage") || can("security:manage")) {
    items.push({ id: "fleet", label: "Fleet" });
  }
  if (can("integration:read") || can("audit:read")) {
    items.push({ id: "ops", label: "Overview" });
  }
  if (can("audit:read")) items.push({ id: "audit", label: "Audit" });
  if (can("enrollment:manage") && can("user:read")) {
    items.push({ id: "enroll", label: "Enroll" });
  }
  return items;
}

function threadTitle(raw: string): string {
  const t = raw.trim();
  if (t.length <= 42) return t;
  return `${t.slice(0, 40)}…`;
}

function formatPendingBadge(count: number): string {
  if (count > 99) return "99+";
  return String(count);
}

export function Dashboard({
  me,
  onSignedOut,
  statusSlot,
}: {
  me: Me;
  onSignedOut: () => void;
  statusSlot?: ReactNode;
}) {
  const canChat = me.permissions.includes("request:create");
  const canApprovals = me.permissions.includes("approval:read");
  const tools = useMemo(() => buildTools(me.permissions), [me.permissions]);
  const [active, setActive] = useState<ToolId>(canChat ? "chat" : (tools[0]?.id ?? "chat"));
  const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);
  const [chatEpoch, setChatEpoch] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingApprovals, setPendingApprovals] = useState(0);
  const { history, setHistory } = useRequestHistory(canChat);

  const can = (p: string) => me.permissions.includes(p);
  const current = active === "chat" && !canChat ? (tools[0]?.id ?? "chat") : active;

  const refreshPending = useCallback(() => {
    if (!canApprovals) return;
    listPendingApprovals()
      .then((rows) => {
        setPendingApprovals(rows.length);
      })
      .catch(() => undefined);
  }, [canApprovals]);

  useVisiblePoll(refreshPending, POLL_MS, canApprovals);

  const onPendingChange = useCallback((count: number) => {
    setPendingApprovals(count);
  }, []);

  const signOut = () => {
    setBusy(true);
    setError(null);
    logout()
      .then(onSignedOut)
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Sign-out failed.");
        setBusy(false);
      });
  };

  const openChat = (requestId: string | null = null) => {
    setSelectedRequestId(requestId);
    if (requestId === null) setChatEpoch((n) => n + 1);
    setActive("chat");
  };

  return (
    <div className="app-frame chat-frame">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <p className="brand-mark brand-mark-sm">SentinelDesk</p>
        </div>

        {canChat && (
          <button
            type="button"
            className="btn btn-primary new-chat-btn"
            aria-label="Home"
            onClick={() => {
              openChat(null);
            }}
          >
            New chat
          </button>
        )}

        {canChat && (
          <div className="sidebar-section">
            <p className="sidebar-section-label">Chats</p>
            <nav className="chat-history" aria-label="Chat history">
              {history.length === 0 && <p className="muted sidebar-empty">No requests yet</p>}
              {history.map((row) => (
                <button
                  key={row.id}
                  type="button"
                  className={
                    current === "chat" && selectedRequestId === row.id
                      ? "history-item history-item-active"
                      : "history-item"
                  }
                  onClick={() => {
                    openChat(row.id);
                  }}
                >
                  <span className="history-title">{threadTitle(row.rawRequest)}</span>
                  <span className="history-status">{row.status}</span>
                </button>
              ))}
            </nav>
          </div>
        )}

        {tools.length > 0 && (
          <div className="sidebar-section">
            <p className="sidebar-section-label">Tools</p>
            <nav className="app-nav" aria-label="Primary">
              {tools.map((item) => {
                const showBadge = item.id === "approvals" && pendingApprovals > 0;
                const ariaLabel =
                  item.id === "ops"
                    ? "Overview"
                    : item.id === "fleet"
                      ? "Devices"
                      : item.id === "approvals" && pendingApprovals > 0
                        ? `Approvals, ${String(pendingApprovals)} pending`
                        : item.label;
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={item.id === current ? "nav-item nav-item-active" : "nav-item"}
                    aria-label={ariaLabel}
                    aria-current={item.id === current ? "page" : undefined}
                    onClick={() => {
                      setActive(item.id);
                    }}
                  >
                    <span className="nav-item-row">
                      <span className="nav-label" aria-hidden="true">
                        {item.label}
                      </span>
                      {showBadge && (
                        <span className="nav-badge" aria-hidden="true">
                          {formatPendingBadge(pendingApprovals)}
                        </span>
                      )}
                    </span>
                  </button>
                );
              })}
            </nav>
          </div>
        )}

        <div className="sidebar-user">
          <p className="sidebar-user-name" id="me-title">
            <strong>{me.displayName}</strong>
          </p>
          <p className="muted sidebar-user-email">{me.email}</p>
          <p className="muted sidebar-provider">
            {me.identityProvider === "entra" ? "Microsoft Entra ID" : "Local development"}
          </p>
          <ul className="roles" aria-label="Roles">
            {me.roles.map((role) => (
              <li key={role} className="badge badge-ok">
                {role}
              </li>
            ))}
          </ul>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button type="button" className="btn btn-ghost" onClick={signOut} disabled={busy}>
            {busy ? "Signing out…" : "Sign out"}
          </button>
          {statusSlot && <div className="sidebar-status">{statusSlot}</div>}
        </div>
      </aside>

      <div className="workspace workspace-chat">
        {current === "chat" && canChat && (
          <AgentChat
            key={selectedRequestId ?? `new-${String(chatEpoch)}`}
            displayName={me.displayName}
            history={history}
            selectedId={selectedRequestId}
            onHistoryChange={setHistory}
            onSelect={setSelectedRequestId}
          />
        )}
        {current === "chat" && !canChat && (
          <section className="status-card chat-admin-home">
            <p className="eyebrow">Control plane</p>
            <h1 className="workspace-title">Welcome, {me.displayName.split(/\s+/)[0]}</h1>
            <p className="muted">
              Your roles focus on administration. Use Tools in the sidebar — Approvals, Catalogue,
              Security, Fleet, Overview, or Audit.
            </p>
          </section>
        )}
        {current === "devices" && can("device:read_own") && (
          <div className="tool-pane">
            <MyDevices />
          </div>
        )}
        {current === "approvals" && can("approval:read") && (
          <div className="tool-pane">
            <ApprovalQueue onPendingChange={onPendingChange} />
          </div>
        )}
        {current === "catalogue" && (
          <div className="tool-pane">
            {can("catalogue:read") && <CatalogueSearch />}
            {can("catalogue:manage") && <AdminCatalogue />}
          </div>
        )}
        {current === "security" && can("security:read") && (
          <div className="tool-pane">
            <SecurityAdmin />
          </div>
        )}
        {current === "fleet" && (can("device:manage") || can("security:manage")) && (
          <div className="tool-pane">
            <FleetDevices />
          </div>
        )}
        {current === "ops" && (can("integration:read") || can("audit:read")) && (
          <div className="tool-pane">
            <OpsOverview />
          </div>
        )}
        {current === "audit" && can("audit:read") && (
          <div className="tool-pane">
            <AuditPanel />
          </div>
        )}
        {current === "enroll" && can("enrollment:manage") && can("user:read") && (
          <div className="tool-pane">
            <EnrollDevice />
          </div>
        )}
      </div>
    </div>
  );
}
