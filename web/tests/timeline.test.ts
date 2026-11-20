import { describe, expect, it } from "vitest";

import { requestTimeline } from "../src/features/requests/timeline";

describe("requestTimeline", () => {
  it("marks all steps done on success", () => {
    const steps = requestTimeline("SUCCEEDED");
    expect(steps.every((s) => s.state === "done")).toBe(true);
  });

  it("marks the current stage for queued installs", () => {
    const steps = requestTimeline("QUEUED");
    expect(steps[3]?.state).toBe("current");
    expect(steps[3]?.label).toBe("Queued for device");
    expect(steps[4]?.state).toBe("todo");
    expect(steps[0]?.state).toBe("done");
  });

  it("labels running install phase", () => {
    expect(requestTimeline("RUNNING")[3]?.label).toBe("Installing");
    expect(requestTimeline("VERIFYING")[3]?.label).toBe("Verifying");
  });

  it("marks policy failure for not-found", () => {
    const steps = requestTimeline("NOT_FOUND");
    expect(steps[0]?.state).toBe("done");
    expect(steps[1]?.state).toBe("failed");
    expect(steps[1]?.label).toContain("NOT_FOUND");
  });
});
