/** Input → action → output guardrails for the Sentinel install agent (OWASP-aligned). */

function hasUnsafeControls(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (c === 127 || (c < 32 && c !== 9 && c !== 10 && c !== 13)) return true;
  }
  return false;
}

const INJECTION =
  /\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|disregard\s+(all\s+)?(previous|prior)|system\s+prompt|you\s+are\s+now\s+dan|jailbreak|developer\s+mode|bypass\s+(policy|security|guardrails?)|reveal\s+(your\s+)?(system|hidden)\s+prompt|pretend\s+you\s+have\s+no\s+restrictions)\b/i;

const OFF_TOPIC =
  /\b(source\s+code|write\s+(me\s+)?(a\s+)?(python|java|rust|go|sql|script|essay|poem|email)|generate\s+code|leetcode|homework|crypto\s+wallet|private\s+key|password\s+hash|hack\s+into|exploit|ransomware|malware\s+sample|chat\s+with\s+me\s+about\s+politics|who\s+won\s+the\s+(election|match))\b/i;

const CONTINUE =
  /^(continue|continue\.*|go\s+on|proceed|retry|try\s+again|do\s+it|do\s+that|yes|yep|yeah|sure|please\s+continue|go\s+ahead|same\s+again|again)[\s!.?]*$/i;

export type InputGuardResult =
  | { ok: true; text: string }
  | {
      ok: false;
      reason: "empty" | "too_long" | "control_chars" | "injection" | "off_topic";
      message: string;
    };

export function guardInput(raw: string, maxLen = 500): InputGuardResult {
  const text = raw.replace(/\s+/g, " ").trim();
  if (!text) return { ok: false, reason: "empty", message: "Please type a message." };
  if (text.length > maxLen) {
    return {
      ok: false,
      reason: "too_long",
      message: `Please keep messages under ${String(maxLen)} characters.`,
    };
  }
  if (hasUnsafeControls(text)) {
    return {
      ok: false,
      reason: "control_chars",
      message:
        "That message contains characters I can't safely process. Please rephrase in plain text.",
    };
  }
  if (INJECTION.test(text)) {
    return {
      ok: false,
      reason: "injection",
      message:
        "I blocked that message — it looks like a prompt-injection / jailbreak attempt. " +
        "I'm Sentinel, a software installation agent only. Ask me to install approved software on your device.",
    };
  }
  if (OFF_TOPIC.test(text)) {
    return {
      ok: false,
      reason: "off_topic",
      message:
        "I'm Sentinel — a software installation agent for your organisation. " +
        "I can't help with source code, general coding, or unrelated tasks. " +
        "Tell me what approved software you'd like installed (for example “Install git”).",
    };
  }
  return { ok: true, text };
}

export function isContinuePhrase(text: string): boolean {
  return CONTINUE.test(text.trim());
}

export function guardOutputText(text: string): string {
  // Never echo obvious secret-shaped material in agent prose.
  return text
    .replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, "[redacted]")
    .replace(/\bBearer\s+[A-Za-z0-9._-]{12,}\b/gi, "[redacted]");
}
