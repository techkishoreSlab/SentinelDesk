# Mac demo this week (always-on agent)

Scope: **macOS only** for this demo. Windows/Linux agents come later.

## What the head should see

1. Menu bar: **Sentinel · Online** (or **Installing…** while a job runs). No Terminal window.
2. Web chat: employee asks for software → approval (if required) → install completes on the enrolled Mac.
3. Catalogue admin: **Add software** via HTTPS URL or .pkg upload (SHA-256 automatic).

## Production recommendations (applied)

| Topic | Recommendation | Demo default |
|---|---|---|
| New CLI / developer tools (Go, gh, …) | `REQUIRE_APPROVAL` | Checked on by default in Add software |
| Auto-approve | Only low-risk, vetted apps with pin + signature | Off unless you uncheck |
| Threat intel | Fail closed; pin digests on ingest | `pinned.sha256` in package store |
| Agent UX | Always-on LaunchAgent + menu bar | `make macos-agent-install` |
| Privileged install | Root LaunchDaemon (D2) | Still required for actual pkg install |

## One-time Mac setup

```bash
make up
mkdir -p /Users/Shared/SentinelDesk/packages
make macos-desktop-install   # Sentinel.app → /Applications (click anytime)
# Share with other Macs: make macos-desktop → dist/macos/*.zip
# If privileged installs are needed for the demo:
#   follow Phase 8 / D2 root LaunchDaemon install (separate from user agent)
```

Details: [`MAC_DESKTOP_APP.md`](MAC_DESKTOP_APP.md). Enroll the Mac in the web UI, then leave **Sentinel** running in the menu bar.

## Add software (A + B)

1. Sign in as software admin → **Catalogue** → **Add software**.
2. **HTTPS URL** or **Upload .pkg**.
3. Leave **Require approval** on for Go/gh-class tools.
4. Submit → package staged under `/Users/Shared/SentinelDesk/packages`, digest pinned.

## Demo script (≈10 minutes)

1. Point at menu bar: Online.
2. Employee chat: “install Go” (or catalogue title) → awaiting approval.
3. Approver approves in **Approvals**.
4. Menu bar flips to Installing… then Online; verify with `go version` / `gh --version` as appropriate.
5. Show Audit / Overview for the install trail.

## Stop agent later

```bash
launchctl bootout "gui/$(id -u)/com.sentineldesk.agent"
launchctl bootout "gui/$(id -u)/com.sentineldesk.menubar"
```
