import { describe, expect, it } from "vitest";

import {
  formatInstallElapsed,
  installFailureCopy,
  installHeadline,
  installPhases,
  installProgressView,
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

  it("maps device result codes to friendly copy", () => {
    expect(installFailureCopy("APP_IN_USE")).toMatch(/Quit it/);
    expect(installFailureCopy("INSTALLER_UNSUPPORTED")).toMatch(/update/i);
    expect(installFailureCopy("SOMETHING_NEW")).toBeNull();
    expect(installFailureCopy(null)).toBeNull();
  });

  it("maps download bytes into the preparing band", () => {
    const mid = installProgressView({
      status: "DISPATCHED",
      progressPhase: "DOWNLOADING",
      progressBytesDone: 128 * 1024 * 1024,
      progressBytesTotal: 256 * 1024 * 1024,
    });
    expect(mid.indeterminate).toBe(false);
    expect(mid.percent).toBe(33); // 10 + 0.5*45
    expect(mid.detail).toMatch(/Downloading/);
  });

  it("keeps install/verify indeterminate without inventing a climb", () => {
    const now = Date.UTC(2026, 0, 1, 12, 0, 0);
    const installing = installProgressView(
      {
        status: "RUNNING",
        progressPhase: "INSTALLING",
        progressBytesDone: null,
        progressBytesTotal: null,
        progressUpdatedAt: new Date(now - 30_000).toISOString(),
      },
      now,
    );
    expect(installing.indeterminate).toBe(true);
    expect(installing.detail).toMatch(/Installing/);

    const verifying = installProgressView({
      status: "VERIFYING",
      progressPhase: "VERIFYING",
    });
    expect(verifying.indeterminate).toBe(true);
    expect(installProgressView({ status: "SUCCEEDED" }).percent).toBe(100);
  });

  it("flags stale installing progress when the agent stopped updating", () => {
    const now = Date.UTC(2026, 0, 1, 12, 10, 0);
    const view = installProgressView(
      {
        status: "RUNNING",
        progressPhase: "INSTALLING",
        progressUpdatedAt: new Date(Date.UTC(2026, 0, 1, 12, 0, 0)).toISOString(),
      },
      now,
    );
    expect(view.detail).toMatch(/No recent update/);
  });

  it("formats elapsed time", () => {
    const started = new Date(Date.UTC(2026, 0, 1, 12, 0, 0)).toISOString();
    const now = Date.UTC(2026, 0, 1, 12, 1, 5);
    expect(formatInstallElapsed(started, now)).toBe("1m 05s");
  });
});
