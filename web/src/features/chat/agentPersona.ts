/** Conversational install agent: multi-turn context + niche scope (not a general chatbot). */

import { installFailureCopy } from "../requests/installPhase";
import { guardInput, guardOutputText, isContinuePhrase } from "./guardrails";

export type ThreadContext = {
  lastInstallPrompt: string | null;
  lastStatus: string | null;
  lastReason: string | null;
};

export type AgentPlan =
  { kind: "reply"; text: string } | { kind: "install"; prompt: string; resumeNote?: string };

const GREETING_START = /^(hi|hello|hey|howdy|yo|sup|good\s+(morning|afternoon|evening))\b/i;
const IDENTITY = /^(who\s+are\s+you|what\s+are\s+you|what('?s| is)\s+your\s+name|your\s+name\??)/i;
const HELP = /^(help|help\s+me|what\s+can\s+you\s+do|how\s+do\s+(you|i)\s+work|how\s+may\s+i\b)/i;
const THANKS = /^(thanks|thank\s+you|thx|ok|okay|cool|great|nice)[\s!.?]*$/i;
const INSTALL_VERB = /\b(install|get|add|setup|set\s+up|download|provision|deploy)\b/i;
const WANT_INSTALL = /\b(i\s+want\s+to\s+install|i\s+need\s+to\s+install|can\s+you\s+install)\b/i;

export type LocalTurn =
  | { kind: "greeting" }
  | { kind: "identity" }
  | { kind: "help" }
  | { kind: "thanks" }
  | { kind: "install"; query: string }
  | { kind: "unclear" };

export function classifyTurn(raw: string): LocalTurn {
  const text = raw.trim().replace(/\s+/g, " ");
  if (!text) return { kind: "unclear" };
  if (IDENTITY.test(text)) return { kind: "identity" };
  if (HELP.test(text)) return { kind: "help" };
  if (THANKS.test(text)) return { kind: "thanks" };
  if (GREETING_START.test(text) && !INSTALL_VERB.test(text)) return { kind: "greeting" };
  if (
    INSTALL_VERB.test(text) ||
    WANT_INSTALL.test(text) ||
    /^[a-z0-9][\w .+-]{0,80}$/i.test(text)
  ) {
    return { kind: "install", query: text };
  }
  return { kind: "unclear" };
}

export function agentWelcome(displayName: string): string {
  const first = displayName.split(/\s+/)[0] || "there";
  return (
    `Hello ${first} — I'm Sentinel, your organisation's software provisioning agent.\n\n` +
    `I help you install approved software on your enrolled devices: I match the catalogue, ` +
    `evaluate policy, and open a tracked request when you're ready.\n\n` +
    `How may I help you today?`
  );
}

export function localAgentReply(turn: LocalTurn): string | null {
  switch (turn.kind) {
    case "greeting":
      return (
        "Hi — I'm Sentinel, your software provisioning agent. " +
        "I help install approved applications on your device. How may I help you?"
      );
    case "identity":
      return (
        "My name is Sentinel. I'm the SentinelDesk agent for policy-governed software " +
        "provisioning — not a general chatbot. Tell me what you'd like installed, " +
        "for example “Install git” or “Install Visual Studio Code”."
      );
    case "help":
      return (
        "I can:\n" +
        "• Understand a natural-language install request\n" +
        "• Match it to your organisation's approved catalogue\n" +
        "• Check device compatibility and security policy\n" +
        "• Open a tracked request (auto-approve, approval queue, or block)\n\n" +
        "You can say “continue” or “try again” after a request and I'll reuse that context.\n" +
        "Try: “Install git”."
      );
    case "thanks":
      return "You're welcome. When you're ready, tell me what software to install.";
    case "unclear":
      return (
        "I'm Sentinel — I specialise in installing approved software on your devices. " +
        "How may I help you today?"
      );
    case "install":
      return null;
  }
}

function normalizeInstallPrompt(text: string): string {
  if (INSTALL_VERB.test(text) || WANT_INSTALL.test(text)) return text;
  return `Install ${text}`;
}

/**
 * Plan the next agent action using thread memory (ChatGPT/Claude-style continuity).
 * Does not call models for tool selection (decision D1 — deterministic control plane).
 */
export function planAgentTurn(raw: string, ctx: ThreadContext): AgentPlan {
  const gated = guardInput(raw);
  if (!gated.ok) {
    return { kind: "reply", text: guardOutputText(gated.message) };
  }
  const text = gated.text;

  if (isContinuePhrase(text)) {
    if (!ctx.lastInstallPrompt) {
      return {
        kind: "reply",
        text: guardOutputText(
          "Happy to continue — tell me which approved software to install " +
            "(for example “Install git” or “Install Visual Studio Code”).",
        ),
      };
    }
    if (ctx.lastStatus === "NOT_FOUND") {
      return {
        kind: "reply",
        text: guardOutputText(
          `We already checked the catalogue for “${ctx.lastInstallPrompt}” and it wasn't found. ` +
            "Try a different product name from your organisation's catalogue, " +
            "or ask a software admin to add it — then tell me the new name.",
        ),
      };
    }
    if (ctx.lastStatus === "ALREADY_INSTALLED") {
      return {
        kind: "reply",
        text: guardOutputText(
          `“${ctx.lastInstallPrompt}” is already installed on this device. ` +
            "Name another approved app if you'd like me to provision something else.",
        ),
      };
    }
    if (ctx.lastReason === "DEVICE_STALE" || ctx.lastStatus === "INCOMPATIBLE") {
      const stale =
        ctx.lastReason === "DEVICE_STALE"
          ? "Your device hasn't checked in recently (stale heartbeat), so installs are paused. " +
            "Keep the Sentinel desktop agent running so it can heartbeat, then say “try again”."
          : `The last attempt for “${ctx.lastInstallPrompt}” was blocked (${ctx.lastReason ?? ctx.lastStatus ?? "policy"}). ` +
            "Fix that condition, then say “try again”.";
      // Still allow retry via install so a fresh heartbeat can succeed.
      return {
        kind: "install",
        prompt: ctx.lastInstallPrompt,
        resumeNote: guardOutputText(stale + " I'll retry that install request now."),
      };
    }
    return {
      kind: "install",
      prompt: ctx.lastInstallPrompt,
      resumeNote: guardOutputText(
        `Continuing with your previous request: “${ctx.lastInstallPrompt}”.`,
      ),
    };
  }

  const turn = classifyTurn(text);
  if (turn.kind !== "install") {
    const reply = localAgentReply(turn) ?? localAgentReply({ kind: "unclear" });
    return {
      kind: "reply",
      text: guardOutputText(
        reply ??
          "I'm Sentinel — I specialise in installing approved software on your devices. How may I help you today?",
      ),
    };
  }

  return { kind: "install", prompt: normalizeInstallPrompt(turn.query) };
}

export function updateThreadContext(
  _ctx: ThreadContext,
  installPrompt: string,
  status: string,
  reason: string | null,
): ThreadContext {
  return {
    lastInstallPrompt: installPrompt,
    lastStatus: status,
    lastReason: reason,
  };
}

export function friendlyPreviewCopy(
  status: string,
  explanation: string,
  reason?: string | null,
): string {
  const code = reason || status;
  if (
    code === "DEVICE_STALE" ||
    (status === "INCOMPATIBLE" && /stale/i.test(explanation + (reason ?? "")))
  ) {
    return guardOutputText(
      "Your Mac is enrolled, but it hasn't checked in recently, so installs are paused for safety. " +
        "Make sure the Sentinel desktop agent is running (it sends heartbeats). " +
        "When it's fresh again, say “try again” and I'll continue.",
    );
  }
  if (status === "UNKNOWN_INTENT" || status === "NEEDS_CLARIFICATION") {
    if (/sentinel/i.test(explanation)) return guardOutputText(explanation);
    return guardOutputText(
      "I'm Sentinel, your organisation's software provisioning agent. " +
        "I help install approved software on your enrolled devices. How may I help you today?",
    );
  }
  if (status === "NOT_FOUND") {
    return guardOutputText(
      "I looked in your organisation's approved catalogue, but I couldn't find that software. " +
        "Try another name from the catalogue, or ask your software admin to add it.",
    );
  }
  if (status === "ALREADY_INSTALLED") {
    return guardOutputText(
      explanation ||
        "That software is already installed on this device — nothing more to provision.",
    );
  }
  if (status === "BLOCKED") {
    return guardOutputText(
      explanation || "Policy blocked that install. I can't bypass security controls.",
    );
  }
  if (status === "AWAITING_APPROVAL") {
    return guardOutputText(
      explanation ||
        "Policy requires an approver. I've paused here — once they approve, I'll continue " +
          "installing on your device automatically.",
    );
  }
  if (
    status === "QUEUED" ||
    status === "DISPATCHED" ||
    status === "RUNNING" ||
    status === "VERIFYING"
  ) {
    return guardOutputText(
      explanation ||
        "Your request is approved. I'm working with the Sentinel agent on your Mac to install it now.",
    );
  }
  if (status === "SUCCEEDED") {
    return guardOutputText(
      explanation || "Done — the software is installed and verified on your device.",
    );
  }
  const failureCopy =
    status === "INCOMPATIBLE" || status === "ALREADY_INSTALLED" || status === "FAILED"
      ? installFailureCopy(reason)
      : null;
  if (failureCopy) return guardOutputText(failureCopy);
  if (status === "FAILED" || status === "FAILED_VERIFICATION") {
    return guardOutputText(
      (explanation !== reason ? explanation : "") ||
        "The install finished on the device but verification failed. Share the request ID with support, " +
          "or say “try again” after the catalogue version is corrected.",
    );
  }
  return guardOutputText(explanation);
}
