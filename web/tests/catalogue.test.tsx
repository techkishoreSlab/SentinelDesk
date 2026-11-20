import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CatalogueSearch } from "../src/features/catalogue/CataloguePanels";
import { parseSearchHit } from "../src/features/catalogue/api";
import { parseEvaluation } from "../src/features/security/api";

const HIT = {
  software: {
    id: "s1",
    slug: "visual-studio-code",
    display_name: "Visual Studio Code",
    description: "editor",
    publisher: "Microsoft",
    category: "developer-tools",
    lifecycle_status: "ACTIVE",
    risk_level: "LOW",
    aliases: ["vscode"],
  },
  matched_alias: "vscode",
  active_versions: [
    {
      id: "v1",
      software_id: "s1",
      version: "1.138.0",
      os_family: "macos",
      architecture: "x86_64",
      release_status: "ACTIVE",
      metadata_complete: true,
      package_identifier: "com.microsoft.VSCode",
    },
  ],
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

describe("catalogue parsers", () => {
  it("parses search hits and policy evaluation", () => {
    expect(parseSearchHit(HIT).software.displayName).toBe("Visual Studio Code");
    expect(
      parseEvaluation({
        outcome: "REQUIRE_APPROVAL",
        reason_code: "POLICY_REQUIRE_APPROVAL",
        public_message: "Your request is waiting for administrator approval.",
        compatible: true,
        compatibility_reason: "COMPATIBLE",
        threat_verdict: "CLEAN",
        threat_provider: "internal_digest_list",
        ban_rule_id: null,
        policy_decision: "REQUIRE_APPROVAL",
        policy_revision: 1,
        auto_approve_eligible: false,
        software_id: "s",
        software_slug: "git",
        catalogue_version_id: "v",
        details: {},
      }).outcome,
    ).toBe("REQUIRE_APPROVAL");
  });
});

describe("CatalogueSearch", () => {
  it("searches and shows policy evaluation control", async () => {
    document.cookie = "sd_csrf=csrf-1";
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? "GET";
      if (method === "GET" && url.startsWith("/api/v1/devices")) return Promise.resolve(json([]));
      if (method === "GET" && url.includes("/api/v1/catalogue/search")) {
        expect(url).toContain(encodeURIComponent("vscode"));
        return Promise.resolve(json([HIT]));
      }
      throw new Error(`unexpected ${method} ${url}`);
    });

    const user = userEvent.setup();
    render(<CatalogueSearch />);
    await user.type(screen.getByLabelText("Search approved software"), "vscode");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("Visual Studio Code")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Evaluate policy" })).toBeDisabled();
  });
});
