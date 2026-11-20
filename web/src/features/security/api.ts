import { apiGet, apiPost, isRecord } from "../../lib/api";

export interface PolicyEvaluation {
  outcome: string;
  reasonCode: string;
  publicMessage: string;
  threatVerdict: string | null;
  softwareSlug: string;
  autoApproveEligible: boolean;
}

export interface BannedRule {
  id: string;
  matchType: string;
  matchValue: string;
  reasonCode: string;
  publicMessage: string;
  severity: string;
  active: boolean;
}

export interface ThreatStatus {
  mandatory: boolean;
  externalConfigured: boolean;
  provider: string | null;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new TypeError("expected array");
  return value;
}

export function parseEvaluation(value: unknown): PolicyEvaluation {
  if (!isRecord(value)) throw new TypeError("invalid evaluation");
  return {
    outcome: str(value["outcome"], "outcome"),
    reasonCode: str(value["reason_code"], "reason_code"),
    publicMessage: str(value["public_message"], "public_message"),
    threatVerdict:
      value["threat_verdict"] === null ? null : str(value["threat_verdict"], "threat_verdict"),
    softwareSlug: str(value["software_slug"], "software_slug"),
    autoApproveEligible: value["auto_approve_eligible"] === true,
  };
}

export function parseBanned(value: unknown): BannedRule {
  if (!isRecord(value)) throw new TypeError("invalid ban");
  return {
    id: str(value["id"], "id"),
    matchType: str(value["match_type"], "match_type"),
    matchValue: str(value["match_value"], "match_value"),
    reasonCode: str(value["reason_code"], "reason_code"),
    publicMessage: str(value["public_message"], "public_message"),
    severity: str(value["severity"], "severity"),
    active: value["active"] === true,
  };
}

export function parseThreatStatus(value: unknown): ThreatStatus {
  if (!isRecord(value)) throw new TypeError("invalid threat status");
  return {
    mandatory: value["mandatory"] === true,
    externalConfigured: value["external_configured"] === true,
    provider: value["provider"] === null ? null : str(value["provider"], "provider"),
  };
}

export const evaluatePolicy = (deviceId: string, catalogueVersionId: string) =>
  apiPost("/api/v1/security/evaluate", parseEvaluation, {
    device_id: deviceId,
    catalogue_version_id: catalogueVersionId,
  });

export const listBanned = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/security/banned", (v) => list(v).map(parseBanned), signal);

export const fetchThreatStatus = (signal?: AbortSignal) =>
  apiGet("/api/v1/admin/security/threat-status", parseThreatStatus, signal);
