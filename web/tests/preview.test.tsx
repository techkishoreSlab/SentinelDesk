import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { parsePreview } from "../src/features/preview/api";
import { PreviewPanel } from "../src/features/preview/PreviewPanel";

const PREVIEW = {
  status: "REQUIRE_APPROVAL",
  intent: {
    intent: "INSTALL_SOFTWARE",
    software_query: "git",
    edition: null,
    requested_version: null,
    platform_preference: null,
    clarification_required: false,
    clarification_question: null,
    confidence: 0.4,
    source: "fallback",
  },
  match: {
    software_id: "s",
    software_slug: "git",
    display_name: "Git",
    matched_alias: "git",
    catalogue_version_id: "v",
    version: "2.50.0",
  },
  policy: {
    outcome: "REQUIRE_APPROVAL",
    reason_code: "POLICY_REQUIRE_APPROVAL",
    public_message: "Your request is waiting for administrator approval.",
    compatible: true,
    compatibility_reason: "COMPATIBLE",
    threat_verdict: "CLEAN",
    threat_provider: "internal_digest_list",
    policy_decision: "REQUIRE_APPROVAL",
    auto_approve_eligible: false,
    details: {},
  },
  explanation: "Git (2.50.0) matches the catalogue and needs administrator approval.",
  tool_trace: [
    "extract_intent",
    "resolve_catalogue_alias",
    "pick_catalogue_version",
    "evaluate_policy",
    "explain_decision",
  ],
  gemini_configured: false,
  model: null,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "sd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

describe("preview parser", () => {
  it("parses preview payload", () => {
    const parsed = parsePreview(PREVIEW);
    expect(parsed.status).toBe("REQUIRE_APPROVAL");
    expect(parsed.intent.source).toBe("fallback");
    expect(parsed.match?.softwareSlug).toBe("git");
    expect(parsed.toolTrace).toHaveLength(5);
  });
});

describe("PreviewPanel", () => {
  it("submits natural language preview", async () => {
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
              os_family: "macos",
              architecture: "x86_64",
            },
          ]),
        );
      }
      if (method === "POST" && url === "/api/v1/software/preview") {
        return Promise.resolve(json(PREVIEW));
      }
      return Promise.resolve(json({ error: { code: "NOT_FOUND", message: url } }, 404));
    });

    const user = userEvent.setup();
    render(<PreviewPanel />);
    const input = await screen.findByLabelText(/what do you want to install/i);
    await user.clear(input);
    await user.type(input, "Install git");
    await user.click(screen.getByRole("button", { name: /^preview$/i }));
    expect(await screen.findByText(/needs administrator approval/i)).toBeInTheDocument();
    expect(screen.getByText(/via fallback/i)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("REQUIRE_APPROVAL");
  });
});
