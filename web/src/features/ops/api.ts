import { apiGet, isRecord } from "../../lib/api";

export interface OpsMetrics {
  generatedAt: string;
  requestsByStatus: Record<string, number>;
  jobsByStatus: Record<string, number>;
  approvalsAwaiting: number;
  jobQueueDepth: number;
  jobQueueOldestAgeSeconds: number | null;
  devicesTotal: number;
  devicesStale15m: number;
  notificationDeliveryIssues: number;
  installOutcomes: Record<string, number>;
}

function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError(`invalid ${field}`);
  return value;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function recordNums(value: unknown, field: string): Record<string, number> {
  if (!isRecord(value)) throw new TypeError(`invalid ${field}`);
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
  }
  return out;
}

export function parseOpsMetrics(value: unknown): OpsMetrics {
  if (!isRecord(value)) throw new TypeError("invalid metrics");
  const age = value["job_queue_oldest_age_seconds"];
  return {
    generatedAt: str(value["generated_at"], "generated_at"),
    requestsByStatus: recordNums(value["requests_by_status"], "requests_by_status"),
    jobsByStatus: recordNums(value["jobs_by_status"], "jobs_by_status"),
    approvalsAwaiting: num(value["approvals_awaiting"], "approvals_awaiting"),
    jobQueueDepth: num(value["job_queue_depth"], "job_queue_depth"),
    jobQueueOldestAgeSeconds: typeof age === "number" ? age : null,
    devicesTotal: num(value["devices_total"], "devices_total"),
    devicesStale15m: num(value["devices_stale_15m"], "devices_stale_15m"),
    notificationDeliveryIssues: num(
      value["notification_delivery_issues"],
      "notification_delivery_issues",
    ),
    installOutcomes: recordNums(value["install_outcomes"], "install_outcomes"),
  };
}

export function fetchOpsMetrics(signal?: AbortSignal): Promise<OpsMetrics> {
  return apiGet("/api/v1/admin/ops/metrics", parseOpsMetrics, signal);
}
