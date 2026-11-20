import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentChat } from "../src/features/chat/AgentChat";

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

describe("AgentChat", () => {
  it("answers greetings locally without calling the catalogue", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith("/api/v1/devices")) {
        return Promise.resolve(json([]));
      }
      throw new Error(`unexpected ${url}`);
    });

    render(
      <AgentChat
        displayName="Employee One"
        history={[]}
        selectedId={null}
        onHistoryChange={() => undefined}
        onSelect={() => undefined}
      />,
    );

    expect(await screen.findByText(/I'm Sentinel/i)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Message the provisioning agent"), "hi");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(await screen.findByText(/How may I help you/i)).toBeInTheDocument();
    expect(
      fetchSpy.mock.calls.every(([input]) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        return url.startsWith("/api/v1/devices");
      }),
    ).toBe(true);
  });

  it("does not catalogue-search “continue” after NOT_FOUND", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? "GET";
      if (method === "GET" && url.startsWith("/api/v1/devices")) {
        return Promise.resolve(json([{ id: "d1", device_name: "Mac", device_status: "ACTIVE" }]));
      }
      if (method === "POST") {
        throw new Error("continue must not POST");
      }
      throw new Error(`unexpected ${method} ${url}`);
    });

    render(
      <AgentChat
        displayName="Employee One"
        history={[
          {
            id: "r1",
            status: "NOT_FOUND",
            decisionReason: "SOFTWARE_NOT_IN_CATALOGUE",
            rawRequest: "I want to install Vscode",
            softwareSlug: null,
            softwareName: null,
            version: null,
            explanation: "not in catalogue",
            requestVersion: 1,
            replayed: false,
            createdAt: "2026-11-17T00:00:00Z",
          },
        ]}
        selectedId="r1"
        onHistoryChange={() => undefined}
        onSelect={() => undefined}
      />,
    );

    expect(await screen.findByText(/catalogue/i)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Message the provisioning agent"), "continue..");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(await screen.findByText(/already checked/i)).toBeInTheDocument();
    expect(fetchSpy.mock.calls.some(([, init]) => (init?.method ?? "GET") === "POST")).toBe(false);
  });

  it("submits an install message and shows an agent reply", async () => {
    document.cookie = "sd_csrf=csrf-1";
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? "GET";
      if (method === "GET" && url.startsWith("/api/v1/devices")) {
        return Promise.resolve(json([{ id: "d1", device_name: "Mac", device_status: "ACTIVE" }]));
      }
      if (method === "GET" && url === "/api/v1/software/requests") {
        return Promise.resolve(
          json({
            items: [
              {
                id: "r1",
                status: "AWAITING_APPROVAL",
                decision_reason: "POLICY_REQUIRE_APPROVAL",
                raw_request: "Install git",
                software_slug: "git",
                software_name: "Git",
                version: "2.50.0",
                explanation: "needs administrator approval",
                request_version: 1,
                created_at: "2026-11-17T00:00:00Z",
                replayed: false,
              },
            ],
          }),
        );
      }
      if (method === "POST" && url === "/api/v1/software/requests") {
        return Promise.resolve(
          json({
            id: "r1",
            status: "AWAITING_APPROVAL",
            decision_reason: "POLICY_REQUIRE_APPROVAL",
            raw_request: "Install git",
            software_slug: "git",
            software_name: "Git",
            version: "2.50.0",
            explanation: "needs administrator approval",
            request_version: 1,
            created_at: "2026-11-17T00:00:00Z",
            replayed: false,
          }),
        );
      }
      throw new Error(`unexpected ${method} ${url}`);
    });

    render(
      <AgentChat
        displayName="Employee One"
        history={[]}
        selectedId={null}
        onHistoryChange={() => undefined}
        onSelect={() => undefined}
      />,
    );

    expect(await screen.findByText("Your provisioning agent")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Message the provisioning agent"), "Install git");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(await screen.findByText("needs administrator approval")).toBeInTheDocument();
    expect(screen.getByText("AWAITING_APPROVAL")).toBeInTheDocument();
  });
});
