import { describe, expect, it } from "vitest";

import {
  installHeadline,
  installPhases,
  isActiveInstallStatus,
  isTerminalRequestStatus,
} from "../src/features/requests/installPhase";

describe("installPhase", () => {
  it("detects active and terminal statuses", () => {
    expect(isActiveInstallStatus("QUEUED")).toBe(true);
    expect(isActiveInstallStatus("RUNNING")).toBe(true);
    expect(isActiveInstallStatus("AWAITING_APPROVAL")).toBe(false);
    expect(isTerminalRequestStatus("SUCCEEDED")).toBe(true);
    expect(isTerminalRequestStatus("QUEUED")).toBe(false);
  });

  it("builds install phases for running jobs", () => {
    const phases = installPhases("RUNNING");
    expect(phases[2]?.active).toBe(true);
    expect(phases[0]?.done).toBe(true);
    expect(installHeadline("RUNNING")).toMatch(/Installing/i);
  });
});
