/** Human install phases for the agent activity card (derived from request status). */

export type InstallPhase = {
  id: string;
  label: string;
  active: boolean;
  done: boolean;
  failed: boolean;
};

/** Mid-job progress fields from the control plane (agent-reported). */
export type InstallProgressInput = {
  status: string;
  progressPhase?: string | null;
  progressBytesDone?: number | null;
  progressBytesTotal?: number | null;
  /** ISO time of last agent progress POST; used to detect orphaned installs. */
  progressUpdatedAt?: string | null;
};

/** Prefer job claim time for elapsed; fall back to request createdAt. */
export function installElapsedAnchorIso(input: {
  createdAt: string;
  jobClaimedAt?: string | null;
}): string {
  return input.jobClaimedAt || input.createdAt;
}

export type InstallProgressView = {
  /** 0–100 when known; null means indeterminate (install/verify). */
  percent: number | null;
  /** When true, animate the bar without claiming a precise %. */
  indeterminate: boolean;
  detail: string;
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

/** Employee-facing copy for device install result codes and archive compatibility reasons. */
const INSTALL_FAILURE_COPY: Record<string, string> = {
  APP_IN_USE: "The app is open on your Mac. Quit it, then say “try again”.",
  DOWNGRADE_REFUSED:
    "Your Mac already has a newer version than the catalogue, so nothing was changed.",
  NEWER_VERSION_INSTALLED:
    "Your Mac already has a newer version than the catalogue — you're up to date.",
  INSTALLER_UNSUPPORTED:
    "Your Sentinel agent needs an update before it can install this app. Ask IT to update it.",
  INSTALL_INTERRUPTED:
    "The install was interrupted (agent restarted). Say “try again”.",
  DESTINATION_CONFLICT:
    "Another app with the same name is in Applications. IT needs to sort that out first.",
  TEAM_ID_MISMATCH: "The download wasn't signed by the expected developer, so it was blocked.",
  SIGNATURE_INVALID: "The app's signature didn't check out, so it was blocked for safety.",
  GATEKEEPER_REJECTED: "macOS Gatekeeper didn't trust this app, so it was blocked.",
  BUNDLE_ID_MISMATCH: "The download contained a different app than approved, so it was stopped.",
  SYMLINK_REJECTED: "The download had unsafe file links, so it was blocked.",
  ZIP_PATH_REJECTED: "The zip had unsafe file paths, so it was blocked.",
  INSTALLER_TIMEOUT: "The installer took too long and was stopped. Say “try again”.",
  DIGEST_MISMATCH: "The downloaded file didn't match the approved one, so it was blocked.",
  DOWNLOAD_FAILED: "The download didn't finish. Check your connection and say “try again”.",
  INSUFFICIENT_DISK: "Your Mac needs more free disk space for this install.",
  DMG_LICENSE_PROMPT:
    "This disk image asks for a licence click, which can't be automated. IT can repackage it.",
  DMG_ATTACH_FAILED: "The disk image couldn't be opened on your Mac. Say “try again” or ask IT.",
  PAYLOAD_NOT_FOUND: "The app wasn't where the catalogue expected inside the download.",
  VERSION_MISMATCH: "The download contained a different version than approved, so it was stopped.",
  PRIVILEGED_SERVICE_UNAVAILABLE:
    "The Sentinel install helper isn't running on your Mac. Ask IT to reinstall the agent.",
};

export function installFailureCopy(code: string | null | undefined): string | null {
  return code ? (INSTALL_FAILURE_COPY[code] ?? null) : null;
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

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"] as const;
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 ? 0 : v >= 10 ? 0 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

/**
 * Honest progress for the activity card.
 * Download band 10–55% from real bytes; install/verify are indeterminate in 55–95%;
 * succeeded is 100%. Never invents a climbing timer %.
 */
function progressStale(progressUpdatedAt: string | null | undefined, nowMs: number): boolean {
  if (!progressUpdatedAt) return false;
  const at = Date.parse(progressUpdatedAt);
  if (!Number.isFinite(at)) return false;
  // Install/verify progress is posted once at phase entry; downloads refresh often.
  // After ~3 minutes with no update while still RUNNING, the agent likely died mid-job.
  return nowMs - at > 3 * 60 * 1000;
}

export function installProgressView(
  input: InstallProgressInput,
  nowMs: number = Date.now(),
): InstallProgressView {
  const { status, progressPhase, progressBytesDone, progressBytesTotal, progressUpdatedAt } = input;

  if (status === "SUCCEEDED") {
    return { percent: 100, indeterminate: false, detail: "Completed" };
  }
  if (status === "QUEUED") {
    return { percent: 5, indeterminate: false, detail: "Waiting for your Mac…" };
  }
  if (
    status === "FAILED" ||
    status === "FAILED_VERIFICATION" ||
    status === "CANCELLED" ||
    status === "EXPIRED"
  ) {
    return { percent: null, indeterminate: false, detail: "" };
  }

  const phase = (progressPhase ?? "").toUpperCase();
  const done =
    typeof progressBytesDone === "number" && Number.isFinite(progressBytesDone)
      ? Math.max(0, progressBytesDone)
      : null;
  const total =
    typeof progressBytesTotal === "number" &&
    Number.isFinite(progressBytesTotal) &&
    progressBytesTotal > 0
      ? progressBytesTotal
      : null;

  if (phase === "DOWNLOADING" || (status === "DISPATCHED" && phase !== "INSTALLING")) {
    if (done !== null && total !== null) {
      const ratio = Math.min(1, done / total);
      const percent = Math.round(10 + ratio * 45);
      return {
        percent,
        indeterminate: false,
        detail: `Downloading ${formatBytes(done)} of ${formatBytes(total)}`,
      };
    }
    if (done !== null && done > 0) {
      return {
        percent: null,
        indeterminate: true,
        detail: `Downloading ${formatBytes(done)}…`,
      };
    }
    return {
      percent: 12,
      indeterminate: true,
      detail: "Preparing package…",
    };
  }

  if (phase === "VERIFYING" || status === "VERIFYING") {
    return { percent: 92, indeterminate: true, detail: "Verifying installation…" };
  }

  if (phase === "INSTALLING" || status === "RUNNING") {
    if (progressStale(progressUpdatedAt, nowMs)) {
      return {
        percent: 60,
        indeterminate: true,
        detail: "No recent update from your Mac — waiting for the agent…",
      };
    }
    return { percent: 60, indeterminate: true, detail: "Installing on your Mac…" };
  }

  if (status === "DISPATCHED") {
    return { percent: 15, indeterminate: true, detail: "Preparing package…" };
  }

  return { percent: null, indeterminate: true, detail: "Working…" };
}

export function formatInstallElapsed(startedAtIso: string, nowMs: number = Date.now()): string {
  const started = Date.parse(startedAtIso);
  if (!Number.isFinite(started) || started > nowMs) return "";
  const sec = Math.floor((nowMs - started) / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}
