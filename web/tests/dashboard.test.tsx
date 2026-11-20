import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Dashboard } from "../src/features/session/Dashboard";
import type { Me } from "../src/features/session/api";

const ADMIN: Me = {
  id: "8d0f6a3e-0000-4000-8000-000000000099",
  email: "security.admin@sentinel.test",
  displayName: "Security Admin",
  identityProvider: "local",
  roles: ["SECURITY_ADMIN"],
  permissions: [
    "approval:read",
    "catalogue:read",
    "security:read",
    "device:manage",
    "integration:read",
    "audit:read",
  ],
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Dashboard navigation", () => {
  it("shows tools nav and opens Overview / Audit", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "/api/v1/admin/ops/metrics") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              generated_at: "2026-11-17T02:53:30.850057+00:00",
              requests_by_status: {},
              jobs_by_status: {},
              approvals_awaiting: 0,
              job_queue_depth: 0,
              job_queue_oldest_age_seconds: null,
              devices_total: 0,
              devices_stale_15m: 0,
              notification_delivery_issues: 0,
              install_outcomes: {},
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
        );
      }
      if (url.startsWith("/api/v1/admin/audit?")) {
        return Promise.resolve(
          new Response(JSON.stringify({ items: [], next_before_seq: null }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      if (url === "/api/v1/admin/approvals") {
        return Promise.resolve(
          new Response(
            JSON.stringify([
              {
                request_id: "r-pending",
                status: "AWAITING_APPROVAL",
                decision_reason: "POLICY_REQUIRE_APPROVAL",
                raw_request: "Install Go",
                requester_email: "employee.one@sentinel.test",
                device_name: "Mac",
                software_name: "Go",
                version: "go1.27.4",
                sha256_prefix: "98b66686",
                threat_verdict: "CLEAN",
                request_version: 1,
                created_at: "2026-11-17T00:00:00Z",
              },
            ]),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
        );
      }
      throw new Error(`unexpected ${url}`);
    });

    render(<Dashboard me={ADMIN} onSignedOut={() => undefined} />);
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Audit" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Approvals, 1 pending" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enroll" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Home" })).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "Overview" }));
    expect(await screen.findByRole("heading", { name: "Operations overview" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Audit" }));
    expect(await screen.findByRole("heading", { name: "Audit history" })).toBeInTheDocument();
  });

  it("keeps employees on chat without admin tools", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith("/api/v1/devices") || url === "/api/v1/software/requests") {
        return Promise.resolve(
          new Response(JSON.stringify(url.includes("requests") ? { items: [] } : []), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      throw new Error(`unexpected ${url}`);
    });
    render(
      <Dashboard
        me={{
          ...ADMIN,
          roles: ["EMPLOYEE"],
          permissions: ["request:create", "device:read_own"],
        }}
        onSignedOut={() => undefined}
      />,
    );
    expect(await screen.findByRole("button", { name: "Home" })).toBeInTheDocument();
    expect(screen.getByText("Your provisioning agent")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Overview" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Audit" })).toBeNull();
  });
});
