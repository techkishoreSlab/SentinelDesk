import { apiGet, isRecord } from "../../lib/api";

export interface AuditEvent {
  id: string;
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  correlationId: string | null;
  result: string;
  reasonCode: string | null;
  eventHash: string;
}

export interface AuditPage {
  items: AuditEvent[];
  nextBeforeSeq: number | null;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function optStr(value: unknown, field: string): string | null {
  if (value === null || value === undefined) return null;
  return str(value, field);
}

function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError(`invalid ${field}`);
  return value;
}

export function parseAuditEvent(value: unknown): AuditEvent {
  if (!isRecord(value)) throw new TypeError("invalid audit event");
  return {
    id: str(value["id"], "id"),
    seq: num(value["seq"], "seq"),
    occurredAt: str(value["occurred_at"], "occurred_at"),
    actorType: str(value["actor_type"], "actor_type"),
    actorId: optStr(value["actor_id"], "actor_id"),
    action: str(value["action"], "action"),
    resourceType: str(value["resource_type"], "resource_type"),
    resourceId: optStr(value["resource_id"], "resource_id"),
    correlationId: optStr(value["correlation_id"], "correlation_id"),
    result: str(value["result"], "result"),
    reasonCode: optStr(value["reason_code"], "reason_code"),
    eventHash: str(value["event_hash"], "event_hash"),
  };
}

export function parseAuditPage(value: unknown): AuditPage {
  if (!isRecord(value)) throw new TypeError("invalid audit page");
  const items = value["items"];
  if (!Array.isArray(items)) throw new TypeError("invalid items");
  const next = value["next_before_seq"];
  return {
    items: items.map(parseAuditEvent),
    nextBeforeSeq: typeof next === "number" ? next : null,
  };
}

export function searchAudit(
  params: { action?: string; result?: string; beforeSeq?: number; limit?: number },
  signal?: AbortSignal,
): Promise<AuditPage> {
  const q = new URLSearchParams();
  if (params.action) q.set("action", params.action);
  if (params.result) q.set("result", params.result);
  if (params.beforeSeq) q.set("before_seq", String(params.beforeSeq));
  q.set("limit", String(params.limit ?? 30));
  return apiGet(`/api/v1/admin/audit?${q}`, parseAuditPage, signal);
}

export function verifyAuditChain(
  signal?: AbortSignal,
): Promise<{ valid: boolean; eventsChecked: number; firstInvalidSeq: number | null }> {
  return apiGet(
    "/api/v1/admin/audit/verify",
    (value) => {
      if (!isRecord(value)) throw new TypeError("invalid verify");
      const first = value["first_invalid_seq"];
      return {
        valid: value["valid"] === true,
        eventsChecked: num(value["events_checked"], "events_checked"),
        firstInvalidSeq: typeof first === "number" ? first : null,
      };
    },
    signal,
  );
}
