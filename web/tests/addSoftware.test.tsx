import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AddSoftwareWizard } from "../src/features/catalogue/CataloguePanels";
import { parseDraft } from "../src/features/catalogue/api";
import { ApiError } from "../src/lib/api";

const PRESET = {
  id: "slack",
  name: "Slack",
  publisher: "Slack Technologies, LLC",
  category: "communication",
  kind: "MACOS_DMG_APP",
  team_id: "BQR82RBBHL",
  architectures: ["universal"],
  description: "Team chat",
  require_approval: false,
  in_catalogue: false,
};

const DRAFT = {
  draft_id: "a".repeat(32),
  expires_at: 1_900_000_000,
  kind: "MACOS_DMG_APP",
  name: "Slack",
  version: "4.47.69",
  identifier: "com.tinyspeck.slackmacgap",
  architecture: "universal",
  minimum_os_version: "12.0",
  team_id: "BQR82RBBHL",
  publisher: "Slack Technologies, LLC",
  signer: "Developer ID Application: Slack Technologies, LLC (BQR82RBBHL)",
  payload_path: "Slack.app",
  package_size_bytes: 200 * 1024 * 1024,
  sha256: "b".repeat(64),
  suggested_slug: "slack",
  suggested_aliases: ["slack"],
  require_approval_default: false,
  existing_software: null,
  already_in_catalogue: null,
  warnings: [],
  preset_id: "slack",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
}

afterEach(() => {
  vi.restoreAllMocks();
  document.cookie = "sd_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

describe("draft parser", () => {
  it("parses an inspection draft and rejects unknown kinds", () => {
    const draft = parseDraft(DRAFT);
    expect(draft.kind).toBe("MACOS_DMG_APP");
    expect(draft.teamId).toBe("BQR82RBBHL");
    expect(draft.payloadPath).toBe("Slack.app");
    expect(() => parseDraft({ ...DRAFT, kind: "WINDOWS_MSI" })).toThrow();
  });

  it("keeps error details for hints", () => {
    const err = new ApiError("PACKAGE_REJECTED", "nope", 422, null, {
      reason: "UNSIGNED_APP",
      hint: "Ask the vendor for a signed build.",
    });
    expect(err.detail("hint")).toMatch(/signed build/);
    expect(err.detail("missing")).toBeNull();
  });
});

describe("AddSoftwareWizard", () => {
  it("adds a preset in two clicks: inspect, review, commit", async () => {
    document.cookie = "sd_csrf=csrf-1";
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = urlOf(input);
      const method = init?.method ?? "GET";
      calls.push(`${method} ${url}`);
      if (method === "GET" && url.endsWith("/presets")) return Promise.resolve(json([PRESET]));
      if (method === "POST" && url.endsWith("/inspect")) {
        expect(JSON.parse(init?.body as string)).toEqual({ preset_id: "slack" });
        return Promise.resolve(json(DRAFT));
      }
      if (method === "POST" && url.endsWith("/commit")) {
        const body = JSON.parse(init?.body as string) as Record<string, unknown>;
        expect(body["draft_id"]).toBe(DRAFT.draft_id);
        expect(body["require_approval"]).toBe(false);
        return Promise.resolve(
          json({
            status: "ADDED",
            software_id: "s1",
            slug: "slack",
            display_name: "Slack",
            version: { version: "4.47.69" },
            policy: "AUTO_APPROVE",
          }),
        );
      }
      throw new Error(`unexpected ${method} ${url}`);
    });

    const onIngested = vi.fn();
    const user = userEvent.setup();
    render(<AddSoftwareWizard onIngested={onIngested} />);
    await user.click(await screen.findByRole("button", { name: /Slack/ }));
    expect(await screen.findByText("Signature verified")).toBeInTheDocument();
    expect(screen.getByText("BQR82RBBHL")).toBeInTheDocument();
    expect(screen.getByText("Disk image with app (.dmg)")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add to catalogue" }));
    expect(await screen.findByText(/is now in the catalogue/)).toBeInTheDocument();
    expect(onIngested).toHaveBeenCalledOnce();
    expect(calls.filter((c) => c.startsWith("POST"))).toHaveLength(2);
  });

  it("shows the backend hint when a package is rejected", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = urlOf(input);
      if ((init?.method ?? "GET") === "GET") return Promise.resolve(json([]));
      expect(url).toContain("/inspect/upload?filename=Tool.dmg");
      expect((init?.headers as Record<string, string>)["Content-Type"]).toBe(
        "application/octet-stream",
      );
      return Promise.resolve(
        json(
          {
            error: {
              code: "PACKAGE_REJECTED",
              message: "This package can't be added to the catalogue.",
              correlation_id: "c1",
              details: { reason: "UNSIGNED_APP", hint: "The app isn't signed by a developer." },
            },
          },
          422,
        ),
      );
    });

    const user = userEvent.setup();
    render(<AddSoftwareWizard />);
    await user.click(screen.getByRole("tab", { name: "Upload file" }));
    const file = new File(["x"], "Tool.dmg", { type: "application/octet-stream" });
    await user.upload(screen.getByLabelText("Package file"), file);
    await user.click(screen.getByRole("button", { name: "Check package" }));
    expect(await screen.findByText("This package can't be added to the catalogue.")).toBeVisible();
    expect(screen.getByText("The app isn't signed by a developer.")).toBeVisible();
  });
});
