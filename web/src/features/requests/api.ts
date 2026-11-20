import { apiGet, apiPost, isRecord } from "../../lib/api";

export interface SoftwareRequest {
  id: string;
  status: string;
  decisionReason: string | null;
  rawRequest: string;
  softwareSlug: string | null;
  softwareName: string | null;
  version: string | null;
  explanation: string | null;
  requestVersion: number;
  replayed: boolean;
  createdAt: string;
}

export interface ApprovalItem {
  requestId: string;
  status: string;
  decisionReason: string | null;
  rawRequest: string;
  requesterEmail: string | null;
  deviceName: string | null;
  softwareName: string | null;
  version: string | null;
  sha256Prefix: string | null;
  threatVerdict: string | null;
  requestVersion: number;
  createdAt: string;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function optStr(value: unknown, field: string): string | null {
  if (value === null || value === undefined) return null;
  return str(value, field);
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new TypeError("expected array");
  return value;
}

export function parseRequest(value: unknown): SoftwareRequest {
  if (!isRecord(value)) throw new TypeError("invalid request");
  return {
    id: str(value["id"], "id"),
    status: str(value["status"], "status"),
    decisionReason: optStr(value["decision_reason"], "decision_reason"),
    rawRequest: str(value["raw_request"], "raw_request"),
    softwareSlug: optStr(value["software_slug"], "software_slug"),
    softwareName: optStr(value["software_name"], "software_name"),
    version: optStr(value["version"], "version"),
    explanation: optStr(value["explanation"], "explanation"),
    requestVersion: typeof value["request_version"] === "number" ? value["request_version"] : 1,
    replayed: value["replayed"] === true,
    createdAt: str(value["created_at"], "created_at"),
  };
}

export function parseApproval(value: unknown): ApprovalItem {
  if (!isRecord(value)) throw new TypeError("invalid approval");
  return {
    requestId: str(value["request_id"], "request_id"),
    status: str(value["status"], "status"),
    decisionReason: optStr(value["decision_reason"], "decision_reason"),
    rawRequest: str(value["raw_request"], "raw_request"),
    requesterEmail: optStr(value["requester_email"], "requester_email"),
    deviceName: optStr(value["device_name"], "device_name"),
    softwareName: optStr(value["software_name"], "software_name"),
    version: optStr(value["version"], "version"),
    sha256Prefix: optStr(value["sha256_prefix"], "sha256_prefix"),
    threatVerdict: optStr(value["threat_verdict"], "threat_verdict"),
    requestVersion: typeof value["request_version"] === "number" ? value["request_version"] : 1,
    createdAt: str(value["created_at"], "created_at"),
  };
}

export const submitRequest = (deviceId: string, userPrompt: string, idempotencyKey: string) =>
  apiPost("/api/v1/software/requests", parseRequest, {
    device_id: deviceId,
    user_prompt: userPrompt,
    idempotency_key: idempotencyKey,
  });

export const listMyRequests = (signal?: AbortSignal) =>
  apiGet(
    "/api/v1/software/requests",
    (v) => {
      if (!isRecord(v)) throw new TypeError("invalid list");
      return list(v["items"]).map(parseRequest);
    },
    signal,
  );

export const cancelRequest = (requestId: string) =>
  apiPost(
    `/api/v1/software/requests/${requestId}/cancel`,
    (v) => {
      if (!isRecord(v)) throw new TypeError("invalid cancel");
      return { id: str(v["id"], "id"), status: str(v["status"], "status") };
    },
    {},
  );

export const listPendingApprovals = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/approvals", (v) => list(v).map(parseApproval), signal);

export const decideApproval = (
  requestId: string,
  decision: "APPROVED" | "REJECTED",
  expectedVersion: number,
  comment?: string,
) =>
  apiPost(
    `/api/v1/admin/approvals/${requestId}/decision`,
    (v) => {
      if (!isRecord(v)) throw new TypeError("invalid decision");
      return {
        requestId: str(v["request_id"], "request_id"),
        status: str(v["status"], "status"),
        decision: str(v["decision"], "decision"),
      };
    },
    {
      decision,
      comment: comment ?? null,
      expected_version: expectedVersion,
    },
  );
