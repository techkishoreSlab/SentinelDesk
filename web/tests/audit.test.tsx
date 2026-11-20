import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditPanel } from "../src/features/audit/AuditPanel";
import { parseAuditPage } from "../src/features/audit/api";

const PAGE = {
  items: [
    {
      id: "11111111-1111-1111-1111-111111111111",
      seq: 12,
      occurred_at: "2026-11-17T02:00:00+00:00",
      actor_type: "USER",
      actor_id: null,
      action: "ACCESS_DENIED",
      resource_type: "api",
      resource_id: "/api/v1/admin/ops/metrics",
      correlation_id: "cid-1",
      result: "DENIED",
      reason_code: "MISSING_PERMISSION",
      event_hash: "a".repeat(64),
      metadata: {},
    },
  ],
  next_before_seq: null,
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("audit panel", () => {
  it("parses audit pages", () => {
    const page = parseAuditPage(PAGE);
    expect(page.items[0]?.action).toBe("ACCESS_DENIED");
    expect(page.items[0]?.result).toBe("DENIED");
  });

  it("lists audit events from the API", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith("/api/v1/admin/audit?")) {
        return Promise.resolve(
          new Response(JSON.stringify(PAGE), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      throw new Error(`unexpected ${url}`);
    });
    render(<AuditPanel />);
    expect(await screen.findByRole("heading", { name: "Audit history" })).toBeInTheDocument();
    expect(await screen.findByText(/ACCESS_DENIED/)).toBeInTheDocument();
    expect(screen.getByText("DENIED")).toBeInTheDocument();
  });
});
