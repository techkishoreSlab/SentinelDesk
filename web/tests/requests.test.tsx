import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { parseRequest } from "../src/features/requests/api";
import { SubmitRequestPanel } from "../src/features/requests/RequestPanels";

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "sd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("request parser", () => {
  it("parses request payload", () => {
    const parsed = parseRequest({
      id: "r1",
      status: "AWAITING_APPROVAL",
      decision_reason: "POLICY_REQUIRE_APPROVAL",
      raw_request: "Install git",
      device_id: "d1",
      software_id: "s1",
      catalogue_version_id: "v1",
      software_slug: "git",
      software_name: "Git",
      version: "2.50.0",
      explanation: "needs approval",
      policy_revision: 1,
      idempotency_key: "k",
      request_version: 1,
      created_at: "2026-11-17T00:00:00Z",
      updated_at: "2026-11-17T00:00:00Z",
      expires_at: null,
      replayed: false,
    });
    expect(parsed.status).toBe("AWAITING_APPROVAL");
    expect(parsed.softwareSlug).toBe("git");
  });
});

describe("SubmitRequestPanel", () => {
  it("submits a software request", async () => {
    document.cookie = "sd_csrf=csrf-1";
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? "GET";
      if (method === "GET" && url.startsWith("/api/v1/devices")) {
        return Promise.resolve(
          json([
            {
              id: "d1",
              device_name: "Mac",
              device_status: "ACTIVE",
            },
          ]),
        );
      }
      if (method === "GET" && url === "/api/v1/software/requests") {
        return Promise.resolve(json({ items: [] }));
      }
      if (method === "POST" && url === "/api/v1/software/requests") {
        return Promise.resolve(
          json({
            id: "r1",
            status: "AWAITING_APPROVAL",
            decision_reason: "POLICY_REQUIRE_APPROVAL",
            raw_request: "Install git",
            device_id: "d1",
            software_id: "s",
            catalogue_version_id: "v",
            software_slug: "git",
            software_name: "Git",
            version: "2.50.0",
            explanation: "needs administrator approval",
            policy_revision: 1,
            idempotency_key: "k",
            request_version: 1,
            created_at: "2026-11-17T00:00:00Z",
            updated_at: "2026-11-17T00:00:00Z",
            expires_at: null,
            replayed: false,
          }),
        );
      }
      return Promise.resolve(json({ error: { code: "NOT_FOUND", message: url } }, 404));
    });

    const user = userEvent.setup();
    render(<SubmitRequestPanel />);
    await user.click(await screen.findByRole("button", { name: /submit request/i }));
    expect(await screen.findByText(/AWAITING_APPROVAL/i)).toBeInTheDocument();
    expect(screen.getByText(/needs administrator approval/i)).toBeInTheDocument();
  });
});
