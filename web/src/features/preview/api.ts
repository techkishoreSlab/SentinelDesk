import { apiPost, isRecord } from "../../lib/api";

export interface PreviewResult {
  status: string;
  explanation: string;
  geminiConfigured: boolean;
  model: string | null;
  toolTrace: string[];
  intent: {
    intent: string;
    softwareQuery: string;
    source: string;
    clarificationRequired: boolean;
    clarificationQuestion: string | null;
    confidence: number;
  };
  match: {
    displayName: string | null;
    softwareSlug: string | null;
    version: string | null;
    matchedAlias: string | null;
  } | null;
  policy: {
    outcome: string;
    reasonCode: string;
    publicMessage: string;
    threatVerdict: string | null;
    autoApproveEligible: boolean;
  } | null;
}

function str(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`invalid ${field}`);
  return value;
}

function optStr(value: unknown, field: string): string | null {
  if (value === null || value === undefined) return null;
  return str(value, field);
}

function listStr(value: unknown): string[] {
  if (!Array.isArray(value)) throw new TypeError("invalid tool_trace");
  return value.map((item, i) => str(item, "tool_trace[" + String(i) + "]"));
}

export function parsePreview(value: unknown): PreviewResult {
  if (!isRecord(value)) throw new TypeError("invalid preview");
  if (!isRecord(value["intent"])) throw new TypeError("invalid intent");
  const intent = value["intent"];
  const matchRaw = value["match"];
  const policyRaw = value["policy"];
  let match: PreviewResult["match"] = null;
  if (matchRaw !== null && matchRaw !== undefined) {
    if (!isRecord(matchRaw)) throw new TypeError("invalid match");
    match = {
      displayName: optStr(matchRaw["display_name"], "display_name"),
      softwareSlug: optStr(matchRaw["software_slug"], "software_slug"),
      version: optStr(matchRaw["version"], "version"),
      matchedAlias: optStr(matchRaw["matched_alias"], "matched_alias"),
    };
  }
  let policy: PreviewResult["policy"] = null;
  if (policyRaw !== null && policyRaw !== undefined) {
    if (!isRecord(policyRaw)) throw new TypeError("invalid policy");
    policy = {
      outcome: str(policyRaw["outcome"], "outcome"),
      reasonCode: str(policyRaw["reason_code"], "reason_code"),
      publicMessage: str(policyRaw["public_message"], "public_message"),
      threatVerdict: optStr(policyRaw["threat_verdict"], "threat_verdict"),
      autoApproveEligible: policyRaw["auto_approve_eligible"] === true,
    };
  }
  return {
    status: str(value["status"], "status"),
    explanation: str(value["explanation"], "explanation"),
    geminiConfigured: value["gemini_configured"] === true,
    model: optStr(value["model"], "model"),
    toolTrace: listStr(value["tool_trace"]),
    intent: {
      intent: str(intent["intent"], "intent"),
      softwareQuery: str(intent["software_query"], "software_query"),
      source: str(intent["source"], "source"),
      clarificationRequired: intent["clarification_required"] === true,
      clarificationQuestion: optStr(intent["clarification_question"], "clarification_question"),
      confidence: typeof intent["confidence"] === "number" ? intent["confidence"] : 0,
    },
    match,
    policy,
  };
}

export const previewSoftware = (deviceId: string, rawRequest: string) =>
  apiPost("/api/v1/software/preview", parsePreview, {
    device_id: deviceId,
    raw_request: rawRequest,
  });
