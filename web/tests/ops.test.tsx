import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OpsOverview } from "../src/features/ops/OpsOverview";
import { parseOpsMetrics } from "../src/features/ops/api";

const SAMPLE = {
  generated_at: "2026-11-17T02:53:30.850057+00:00",
  requests_by_status: { QUEUED: 0, FAILED: 1 },
  jobs_by_status: { FAILED_VERIFICATION: 1 },
  approvals_awaiting: 0,
  job_queue_depth: 0,
  job_queue_oldest_age_seconds: null,
  devices_total: 2,
  devices_stale_15m: 2,
  notification_delivery_issues: 2,
  install_outcomes: { succeeded: 0, failed: 0, failed_verification: 1 },
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ops metrics", () => {
  it("parses the admin metrics payload", () => {
    const m = parseOpsMetrics(SAMPLE);
    expect(m.devicesTotal).toBe(2);
    expect(m.installOutcomes.failed_verification).toBe(1);
  });

  it("renders overview tiles from the API", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(SAMPLE), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    render(<OpsOverview />);
    expect(await screen.findByRole("heading", { name: "Operations overview" })).toBeInTheDocument();
    expect(await screen.findByText("Awaiting approval")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
  });
});
