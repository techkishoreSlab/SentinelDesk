/** Map request status to a short progress timeline (spec §14.2). */

export type TimelineStep = {
  id: string;
  label: string;
  state: "done" | "current" | "todo" | "failed";
};

const TERMINAL_FAIL = new Set([
  "BLOCKED",
  "INCOMPATIBLE",
  "NOT_FOUND",
  "REJECTED",
  "EXPIRED",
  "CANCELLED",
  "FAILED",
  "FAILED_VERIFICATION",
  "SECURITY_CHECK_UNAVAILABLE",
  "ALREADY_INSTALLED",
]);

/** Stage index 0..4 for the happy path; -1 means early terminal. */
function stageIndex(status: string): number {
  switch (status) {
    case "RECEIVED":
    case "UNDERSTANDING":
    case "NEEDS_CLARIFICATION":
    case "POLICY_CHECK":
      return 0;
    case "AWAITING_APPROVAL":
    case "SECURITY_REVIEW":
      return 1;
    case "AUTO_APPROVED":
    case "APPROVED":
    case "READY_TO_INSTALL":
      return 2;
    case "QUEUED":
    case "DISPATCHED":
    case "RUNNING":
    case "VERIFYING":
      return 3;
    case "SUCCEEDED":
      return 4;
    default:
      return -1;
  }
}

function stageLabel(i: number, status: string): string {
  const base = [
    "Received",
    "Policy / review",
    "Approved",
    "Install on device",
    "Completed",
  ] as const;
  if (i !== 3) return base[i] ?? "Step";
  switch (status) {
    case "QUEUED":
      return "Queued for device";
    case "DISPATCHED":
      return "Preparing package";
    case "RUNNING":
      return "Installing";
    case "VERIFYING":
      return "Verifying";
    default:
      return base[3];
  }
}

export function requestTimeline(status: string): TimelineStep[] {
  const idx = stageIndex(status);
  const failed = TERMINAL_FAIL.has(status);

  return [0, 1, 2, 3, 4].map((i) => {
    const id = String(i);
    const label = stageLabel(i, status);
    if (status === "SUCCEEDED") {
      return { id, label, state: "done" as const };
    }
    if (failed) {
      if (idx >= 0) {
        if (i < idx) return { id, label, state: "done" as const };
        if (i === idx) return { id, label: `${label} · ${status}`, state: "failed" as const };
        return { id, label, state: "todo" as const };
      }
      if (i === 1) return { id, label: `${label} · ${status}`, state: "failed" as const };
      if (i === 0) return { id, label, state: "done" as const };
      return { id, label, state: "todo" as const };
    }
    if (i < idx) return { id, label, state: "done" as const };
    if (i === idx) return { id, label, state: "current" as const };
    return { id, label, state: "todo" as const };
  });
}
