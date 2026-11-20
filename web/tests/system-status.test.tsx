import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SystemStatus } from "../src/features/health/SystemStatus";
import { ApiError, apiGet } from "../src/lib/api";
import { parseLive, parseReady } from "../src/features/health/api";

// Unit tests stub `fetch`; real backend connectivity is checked by the Phase 1 integration run.
function jsonResponse(body: unknown, status = 200, correlationId = "cid-1"): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-correlation-id": correlationId },
  });
}

function stubFetch(responses: Record<string, () => Response | Promise<Response>>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const handler = responses[url];
    if (!handler) throw new Error(`unexpected fetch ${url}`);
    return Promise.resolve(handler());
  });
}

describe("parsers", () => {
  it("accept valid payloads and reject malformed ones", () => {
    expect(parseLive({ status: "ok", version: "1" })).toEqual({ status: "ok", version: "1" });
    expect(() => parseLive({ status: "ok" })).toThrow();
    expect(() => parseReady({ status: "ready", checks: { database: "down" } })).toThrow();
  });
});

describe("apiGet", () => {
  it("maps the standard error format to ApiError", async () => {
    stubFetch({
      "/x": () =>
        jsonResponse(
          { error: { code: "SERVICE_UNAVAILABLE", message: "down", correlation_id: "c9" } },
          503,
        ),
    });
    const err = await apiGet("/x", parseLive).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: "SERVICE_UNAVAILABLE", status: 503, correlationId: "c9" });
  });

  it("reports network failures without leaking internals", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("connect ECONNREFUSED 10.0.0.5"));
    const err = await apiGet("/x", parseLive).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "NETWORK_ERROR" });
    expect((err as Error).message).not.toContain("10.0.0.5");
  });

  it("rejects responses that fail schema parsing", async () => {
    stubFetch({ "/x": () => jsonResponse({ status: "ok", version: 7 }) });
    await expect(apiGet("/x", parseLive)).rejects.toMatchObject({ code: "UNEXPECTED_RESPONSE" });
  });
});

describe("SystemStatus", () => {
  it("shows ready state from backend responses", async () => {
    stubFetch({
      "/health/live": () => jsonResponse({ status: "ok", version: "0.1.0" }),
      "/health/ready": () => jsonResponse({ status: "ready", checks: { database: "ok" } }),
    });
    render(<SystemStatus />);
    expect(await screen.findByText("Ready")).toBeInTheDocument();
    expect(screen.getByText("database: ok")).toBeInTheDocument();
  });

  it("shows degraded state with correlation ID and retries", async () => {
    const fetchSpy = stubFetch({
      "/health/live": () => jsonResponse({ status: "ok", version: "0.1.0" }),
      "/health/ready": () =>
        jsonResponse(
          {
            error: {
              code: "SERVICE_UNAVAILABLE",
              message: "The service is temporarily unavailable.",
              correlation_id: "corr-42",
            },
          },
          503,
        ),
    });
    render(<SystemStatus />);
    expect(await screen.findByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("corr-42")).toBeInTheDocument();

    const callsBefore = fetchSpy.mock.calls.length;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("Unavailable");
    expect(fetchSpy.mock.calls.length).toBeGreaterThan(callsBefore);
  });

  it("renders server-provided text as text, not markup", async () => {
    stubFetch({
      "/health/live": () => jsonResponse({ status: "ok", version: "0.1.0" }),
      "/health/ready": () =>
        jsonResponse(
          { error: { code: "X", message: "<img src=x onerror=alert(1)>", correlation_id: "c" } },
          503,
        ),
    });
    const { container } = render(<SystemStatus />);
    expect(await screen.findByText(/<img src=x/)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
