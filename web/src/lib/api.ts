/**
 * Typed API client. Responses are untrusted: every payload passes a runtime
 * parser before it reaches components. The session lives only in an HttpOnly
 * cookie set by the backend; nothing is persisted in browser storage. Unsafe
 * methods echo the readable CSRF cookie in the X-CSRF-Token header.
 */

export type Parser<T> = (value: unknown) => T;

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly correlationId: string | null;

  constructor(code: string, message: string, status: number, correlationId: string | null) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.correlationId = correlationId;
  }
}

const NETWORK_ERROR_MESSAGE = "The SentinelDesk service could not be reached.";
const UNEXPECTED_RESPONSE_MESSAGE = "The service returned an unexpected response.";
const CSRF_COOKIE_NAMES = ["__Host-sd_csrf", "sd_csrf"];

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function readCsrfToken(cookieHeader: string = document.cookie): string | null {
  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    if (rawName && CSRF_COOKIE_NAMES.includes(rawName)) return rest.join("=");
  }
  return null;
}

function parseErrorBody(body: unknown, status: number, headerCorrelation: string | null): ApiError {
  if (isRecord(body) && isRecord(body["error"])) {
    const err = body["error"];
    const code = typeof err["code"] === "string" ? err["code"] : "UNKNOWN_ERROR";
    const message =
      typeof err["message"] === "string" ? err["message"] : UNEXPECTED_RESPONSE_MESSAGE;
    const correlation =
      typeof err["correlation_id"] === "string" ? err["correlation_id"] : headerCorrelation;
    return new ApiError(code, message, status, correlation);
  }
  return new ApiError(
    "UNEXPECTED_RESPONSE",
    UNEXPECTED_RESPONSE_MESSAGE,
    status,
    headerCorrelation,
  );
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";

async function request<T>(
  method: Method,
  path: string,
  parse: Parser<T>,
  options: { body?: unknown; signal?: AbortSignal | undefined } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const csrf = readCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers,
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError("NETWORK_ERROR", NETWORK_ERROR_MESSAGE, 0, null);
  }

  const correlationId = response.headers.get("x-correlation-id");
  let body: unknown = undefined;
  if (response.status !== 204) {
    try {
      body = await response.json();
    } catch {
      throw new ApiError(
        "UNEXPECTED_RESPONSE",
        UNEXPECTED_RESPONSE_MESSAGE,
        response.status,
        correlationId,
      );
    }
  }

  if (!response.ok) throw parseErrorBody(body, response.status, correlationId);

  try {
    return parse(body);
  } catch {
    throw new ApiError(
      "UNEXPECTED_RESPONSE",
      UNEXPECTED_RESPONSE_MESSAGE,
      response.status,
      correlationId,
    );
  }
}

export function apiGet<T>(path: string, parse: Parser<T>, signal?: AbortSignal): Promise<T> {
  return request("GET", path, parse, { signal });
}

export function apiPost<T>(path: string, parse: Parser<T>, body?: unknown): Promise<T> {
  return request("POST", path, parse, { body });
}

/** Multipart POST (do not set Content-Type — browser supplies the boundary). */
export async function apiFormPost<T>(path: string, parse: Parser<T>, form: FormData): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const csrf = readCsrfToken();
  if (csrf) headers["X-CSRF-Token"] = csrf;

  let response: Response;
  try {
    response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: form,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError("NETWORK_ERROR", NETWORK_ERROR_MESSAGE, 0, null);
  }

  const correlationId = response.headers.get("x-correlation-id");
  let body: unknown = undefined;
  if (response.status !== 204) {
    try {
      body = await response.json();
    } catch {
      throw new ApiError(
        "UNEXPECTED_RESPONSE",
        UNEXPECTED_RESPONSE_MESSAGE,
        response.status,
        correlationId,
      );
    }
  }

  if (!response.ok) throw parseErrorBody(body, response.status, correlationId);

  try {
    return parse(body);
  } catch {
    throw new ApiError(
      "UNEXPECTED_RESPONSE",
      UNEXPECTED_RESPONSE_MESSAGE,
      response.status,
      correlationId,
    );
  }
}

export const parseEmpty: Parser<null> = () => null;
