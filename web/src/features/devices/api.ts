import { apiGet, apiPost, isRecord, parseEmpty } from "../../lib/api";

export interface Device {
  id: string;
  deviceName: string;
  osFamily: string;
  osVersion: string;
  architecture: string;
  agentVersion: string;
  status: string;
  lastSeenAt: string | null;
  enrolledAt: string | null;
}

export interface FleetDevice extends Device {
  ownerEmail: string;
}

export interface EligibleOwner {
  id: string;
  email: string;
  displayName: string;
}

export interface IssuedToken {
  token: string;
  ownerEmail: string;
  expiresAt: string;
}

export const QUARANTINE_REASONS = [
  "SUSPECTED_COMPROMISE",
  "CREDENTIAL_THEFT",
  "SIGNATURE_MISMATCH",
  "LOST_DEVICE",
  "OTHER",
] as const;
export type QuarantineReason = (typeof QUARANTINE_REASONS)[number];

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function optStr(value: unknown, field: string): string | null {
  return value === null ? null : str(value, field);
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new TypeError("expected array");
  return value;
}

export function parseDevice(value: unknown): Device {
  if (!isRecord(value)) throw new TypeError("invalid device");
  return {
    id: str(value["id"], "id"),
    deviceName: str(value["device_name"], "device_name"),
    osFamily: str(value["os_family"], "os_family"),
    osVersion: str(value["os_version"], "os_version"),
    architecture: str(value["architecture"], "architecture"),
    agentVersion: str(value["agent_version"], "agent_version"),
    status: str(value["device_status"], "device_status"),
    lastSeenAt: optStr(value["last_seen_at"], "last_seen_at"),
    enrolledAt: optStr(value["enrolled_at"], "enrolled_at"),
  };
}

export function parseFleetDevice(value: unknown): FleetDevice {
  if (!isRecord(value)) throw new TypeError("invalid device");
  return { ...parseDevice(value), ownerEmail: str(value["owner_email"], "owner_email") };
}

export function parseEligibleOwners(value: unknown): EligibleOwner[] {
  if (!isRecord(value)) throw new TypeError("invalid user page");
  return list(value["items"]).flatMap((item) => {
    if (!isRecord(item)) throw new TypeError("invalid user");
    const roles = list(item["roles"]);
    if (item["is_active"] !== true || !roles.includes("EMPLOYEE")) return [];
    return [
      {
        id: str(item["id"], "id"),
        email: str(item["email"], "email"),
        displayName: str(item["display_name"], "display_name"),
      },
    ];
  });
}

export function parseIssuedToken(value: unknown): IssuedToken {
  if (!isRecord(value)) throw new TypeError("invalid token");
  const token = str(value["token"], "token");
  if (!/^sde_[A-Za-z0-9_-]{43}$/.test(token)) throw new TypeError("invalid token format");
  return {
    token,
    ownerEmail: str(value["owner_email"], "owner_email"),
    expiresAt: str(value["expires_at"], "expires_at"),
  };
}

export const fetchMyDevices = (signal?: AbortSignal) =>
  apiGet("/api/v1/devices", (v) => list(v).map(parseDevice), signal);

export const fetchFleet = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/devices", (v) => list(v).map(parseFleetDevice), signal);

export const fetchEligibleOwners = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/users?limit=100", parseEligibleOwners, signal);

export const createEnrollmentToken = (ownerUserId: string) =>
  apiPost("/api/v1/admin/enrollment-tokens", parseIssuedToken, { owner_user_id: ownerUserId });

export const quarantineDevice = (deviceId: string, reason: QuarantineReason) =>
  apiPost(`/api/v1/admin/devices/${encodeURIComponent(deviceId)}/quarantine`, parseEmpty, {
    reason,
  });
