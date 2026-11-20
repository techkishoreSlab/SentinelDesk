import { apiGet, apiPost, isRecord, parseEmpty } from "../../lib/api";

export interface Me {
  id: string;
  email: string;
  displayName: string;
  identityProvider: "local" | "entra";
  roles: string[];
  permissions: string[];
}

export interface Providers {
  local: boolean;
  entra: boolean;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new TypeError("expected string array");
  }
  return value;
}

export function parseMe(value: unknown): Me {
  if (
    !isRecord(value) ||
    typeof value["id"] !== "string" ||
    typeof value["email"] !== "string" ||
    typeof value["display_name"] !== "string" ||
    (value["identity_provider"] !== "local" && value["identity_provider"] !== "entra")
  ) {
    throw new TypeError("invalid user");
  }
  return {
    id: value["id"],
    email: value["email"],
    displayName: value["display_name"],
    identityProvider: value["identity_provider"],
    roles: stringArray(value["roles"]),
    permissions: stringArray(value["permissions"]),
  };
}

export function parseProviders(value: unknown): Providers {
  if (
    !isRecord(value) ||
    typeof value["local"] !== "boolean" ||
    typeof value["entra"] !== "boolean"
  ) {
    throw new TypeError("invalid providers");
  }
  return { local: value["local"], entra: value["entra"] };
}

export const ENTRA_LOGIN_PATH = "/api/v1/auth/entra/login";

export const fetchMe = (signal?: AbortSignal) => apiGet("/api/v1/me", parseMe, signal);
export const fetchProviders = (signal?: AbortSignal) =>
  apiGet("/api/v1/auth/providers", parseProviders, signal);
export const login = (email: string, password: string) =>
  apiPost("/api/v1/auth/login", parseMe, { email, password });
export const logout = () => apiPost("/api/v1/auth/logout", parseEmpty);

// Only known codes are shown; the raw query value is never rendered.
const LOGIN_ERROR_MESSAGES: Record<string, string> = {
  LOGIN_FAILED: "Microsoft sign-in did not complete. Please try again.",
  ACCOUNT_LINK_REQUIRED:
    "An account with this email already exists. Ask a platform administrator to link it.",
  ACCOUNT_DISABLED: "This account is disabled. Contact your administrator.",
};

export function loginErrorMessage(code: string | null): string | null {
  if (!code) return null;
  return LOGIN_ERROR_MESSAGES[code] ?? LOGIN_ERROR_MESSAGES["LOGIN_FAILED"] ?? null;
}
