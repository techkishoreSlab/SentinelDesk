/** Human install phases for the agent activity card (derived from request status). */

export type InstallPhase = {
  id: string;
  label: string;
  active: boolean;
  done: boolean;
  failed: boolean;
};

const ACTIVE_INSTALL = new Set(["QUEUED", "DISPATCHED", "RUNNING", "VERIFYING"]);

export function isActiveInstallStatus(status: string): boolean {
  return ACTIVE_INSTALL.has(status);
}

export function isTerminalRequestStatus(status: string): boolean {
  return (
    status === "SUCCEEDED" ||
    status === "FAILED" ||
    status === "FAILED_VERIFICATION" ||
    status === "CANCELLED" ||
    status === "EXPIRED" ||
    status === "REJECTED" ||
    status === "BLOCKED" ||
    status === "NOT_FOUND" ||
    status === "INCOMPATIBLE" ||
    status === "ALREADY_INSTALLED" ||
    status === "SECURITY_CHECK_UNAVAILABLE"
  );
}

export function installPhaseIndex(status: string): number {
  switch (status) {
    case "QUEUED":
      return 0;
    case "DISPATCHED":
      return 1;
    case "RUNNING":
      return 2;
    case "VERIFYING":
      return 3;
    case "SUCCEEDED":
      return 4;
    default:
      return -1;
  }
}

const PHASE_LABELS = [
  "Queued for device",
  "Preparing package",
  "Installing",
  "Verifying",
  "Completed",
] as const;

export function installPhases(status: string): InstallPhase[] {
  const idx = installPhaseIndex(status);
  const failed =
    status === "FAILED" ||
    status === "FAILED_VERIFICATION" ||
    status === "CANCELLED" ||
    status === "EXPIRED";

  return PHASE_LABELS.map((label, i) => {
    const id = String(i);
    if (status === "SUCCEEDED") {
      return { id, label, active: false, done: true, failed: false };
    }
    if (failed && idx < 0) {
      // Failed after/during install without a clear stage: mark Installing.
      if (i < 2) return { id, label, active: false, done: true, failed: false };
      if (i === 2)
        return { id, label: `${label} · ${status}`, active: false, done: false, failed: true };
      return { id, label, active: false, done: false, failed: false };
    }
    if (failed && idx >= 0) {
      if (i < idx) return { id, label, active: false, done: true, failed: false };
      if (i === idx)
        return { id, label: `${label} · ${status}`, active: false, done: false, failed: true };
      return { id, label, active: false, done: false, failed: false };
    }
    if (i < idx) return { id, label, active: false, done: true, failed: false };
    if (i === idx) return { id, label, active: true, done: false, failed: false };
    return { id, label, active: false, done: false, failed: false };
  });
}

export function installHeadline(status: string): string {
  switch (status) {
    case "AWAITING_APPROVAL":
      return "Paused — waiting for an approver";
    case "QUEUED":
      return "Queued — your Mac agent will pick this up next";
    case "DISPATCHED":
      return "Preparing package on your device";
    case "RUNNING":
      return "Installing software…";
    case "VERIFYING":
      return "Verifying installation…";
    case "SUCCEEDED":
      return "Installation completed";
    case "FAILED":
    case "FAILED_VERIFICATION":
      return "Installation did not verify successfully";
    default:
      return status.replaceAll("_", " ");
  }
}
