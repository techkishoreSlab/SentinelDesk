import { apiGet, isRecord } from "../../lib/api";

export interface LiveStatus {
  status: "ok";
  version: string;
}

export interface ReadyStatus {
  status: "ready";
  checks: Record<string, "ok">;
}

export function parseLive(value: unknown): LiveStatus {
  if (!isRecord(value) || value["status"] !== "ok" || typeof value["version"] !== "string") {
    throw new TypeError("invalid live status");
  }
  return { status: "ok", version: value["version"] };
}

export function parseReady(value: unknown): ReadyStatus {
  if (!isRecord(value) || value["status"] !== "ready" || !isRecord(value["checks"])) {
    throw new TypeError("invalid ready status");
  }
  const checks: Record<string, "ok"> = {};
  for (const [name, state] of Object.entries(value["checks"])) {
    if (state !== "ok") throw new TypeError("invalid check state");
    checks[name] = "ok";
  }
  return { status: "ready", checks };
}

export const fetchLive = (signal?: AbortSignal) => apiGet("/health/live", parseLive, signal);
export const fetchReady = (signal?: AbortSignal) => apiGet("/health/ready", parseReady, signal);
