# SentinelDesk — Hackathon Guide

One-page guide for running the demo and explaining the product to your hackathon head.

---

## What it is

**SentinelDesk** is an enterprise software request + install platform:

1. Employee asks for software in chat (e.g. “install Go”).
2. Policy decides: auto-approve or send to an Approver.
3. A Mac **endpoint agent** installs the approved package on the enrolled machine.
4. Every step is audited.

**This week’s demo is macOS-first.** Windows/Linux agents are later.

| Layer | What it does |
|---|---|
| Web console | Chat, Approvals, Catalogue, Audit (`http://localhost:5173`) |
| Backend + DB | Auth, catalogue, policy, jobs, audit trail |
| Agent gateway | TLS API the Mac agent talks to (`https://localhost:8443`) |
| **Sentinel.app** | Menu-bar app: runs the agent; on the builder Mac it can also start/stop the local Docker stack |

---

## Prerequisites

- Docker Desktop running (Engine green)
- This repo at `~/Documents/Sentinel_Desk` (or your clone path)
- One-time: `make init` (creates `.env` + signing keys if missing)
- Package store folder:

```bash
mkdir -p /Users/Shared/SentinelDesk/packages
```

Dev logins (local only): see `secrets/dev-accounts.txt`  
Accounts include `employee.one`, `approver`, `software.admin`, `platform.admin` — all `@sentinel.test`.

---

## How to run

### Option A — Click the desktop app (recommended for demos)

```bash
cd ~/Documents/Sentinel_Desk
make up                          # first time / if stack is down
make macos-desktop-install       # installs /Applications/Sentinel.app
open /Applications/Sentinel.app
```

**Open Sentinel** (with Local demo stack on):

- Starts Docker Compose (backend + gateway)
- Starts the Mac agent
- Opens the web console

Menu bar should show **Online** (or briefly Offline while heartbeats catch up).

### Option B — Terminal only

```bash
cd ~/Documents/Sentinel_Desk
make up
cd web && npm ci && npm run dev   # http://localhost:5173
```

Then install/open Sentinel for the agent, or use `make macos-agent-install` for the LaunchAgent path.

### First-time Mac enrollment

1. Sign in as an admin who can manage devices.
2. Create an enrollment token for an **employee** user.
3. Enroll from the agent / Sentinel flow so the device appears **ACTIVE**.
4. Keep **Sentinel** running in the menu bar during installs.

---

## How to stop

### Stop the desktop app (demo Mac)

- Menu bar → **Quit Sentinel**, or popover → Quit (⌘Q).

With Local demo stack enabled, quit also:

- Stops the agent
- Runs `docker compose down`

### Stop the stack from Terminal

```bash
cd ~/Documents/Sentinel_Desk
make down
```

### Stop LaunchAgents only (if you used `macos-agent-install`)

```bash
launchctl bootout "gui/$(id -u)/com.sentineldesk.agent"
launchctl bootout "gui/$(id -u)/com.sentineldesk.menubar"
```

---

## How to add software to the catalogue

Use the **software admin** account (`software.admin@sentinel.test`).

1. Open `http://localhost:5173` → sign in.
2. Go to **Catalogue** → **Add software**.
3. Choose source:
   - **HTTPS URL** (installer download), or
   - **Upload .pkg**
4. Fill title / alias people will say in chat (e.g. “Go”, “gh”).
5. Leave **Require approval** checked for CLI / developer tools (recommended).
6. Submit.

What happens behind the scenes:

- Package is staged under `/Users/Shared/SentinelDesk/packages`
- SHA-256 is computed and **pinned** in the catalogue
- Employees can resolve it by alias in chat
- Installs go through policy → optional Approvals → agent job

**Note:** Actual `.pkg` install on the Mac still needs the privileged install daemon (Phase 8 / D2). Catalogue + request + job flow works without it; privileged install is for real package execution.

### Seeded demo catalogue (optional)

If the catalogue looks empty:

```bash
cd ~/Documents/Sentinel_Desk/backend
uv run python -m app.cli seed-catalogue
```

---

## 10-minute demo script (for your head)

1. **Menu bar** — Sentinel shows Online. “This is the endpoint agent on the employee Mac.”
2. **Employee chat** — Sign in as `employee.one` → ask “install Go” (or another catalogue title).
3. **Approval** — If require-approval is on, sign in as `approver` → **Approvals** → approve.
4. **Install** — Menu bar flips to Installing… then Online. Verify with `go version` / `gh --version` if that package was installed.
5. **Audit** — Show Audit / Overview: who asked, who approved, what ran.

### Roles to mention

| Role | Job in the demo |
|---|---|
| Employee | Requests software in chat |
| Approver | Approves / denies installs |
| Software admin | Adds packages to the catalogue |
| Auditor | Reads the hash-chained audit log |
| Platform admin | Users, roles, devices |

---

## Architecture in one picture

```
Employee browser ──► Web (5173) ──► Backend API (8000)
                                         │
                                         ├── Postgres (catalogue, jobs, audit)
                                         │
Mac Sentinel.app ──TLS──► Agent gateway (8443)
   │
   └── installs approved packages on this Mac
```

**SaaS vs local demo**

| Mode | Control plane | Sentinel.app |
|---|---|---|
| Real SaaS | Always-on cloud / shared host | Agent only (connect by URL) |
| This hackathon laptop | Docker Compose in the repo | Can start/stop stack on open/quit |

Shared zip builds leave “Local demo stack” **off**. Your builder Mac install turns it **on** for convenience.

---

## Troubleshooting (quick)

| Symptom | Fix |
|---|---|
| Menu bar: Control plane / docker compose failed | Start Docker Desktop; reopen Sentinel; check `~/Library/Application Support/com.SentinelDesk.Agent/stack.log` |
| Offline · retry… | Wait ~10–30s after open; confirm `make up` / containers healthy |
| No “Add software” | Sign in as `software.admin`, not platform admin only |
| Port 5173 already in use | Fine — Sentinel skips starting Vite if something already serves the console |
| Gatekeeper blocks .app | System Settings → Privacy & Security → Open Anyway |

---

## One-liners for the head

- **Problem:** Shadow IT and unsafe installers; no approval trail.
- **Product:** Chat request → policy → approval → verified install on the Mac → audit.
- **Trust:** Pinned digests, require-approval for risky tools, device enrollment + TLS agent channel.
- **Demo surface:** Menu-bar Online + web chat + Approvals + Catalogue Add software.

---

## Related docs (deeper detail)

| Doc | When to open it |
|---|---|
| [`DEMO_THIS_WEEK.md`](DEMO_THIS_WEEK.md) | Short Mac demo checklist |
| [`MAC_DESKTOP_APP.md`](MAC_DESKTOP_APP.md) | Sentinel.app build / share / SaaS vs demo stack |
| [`ENVIRONMENT_SETUP.md`](ENVIRONMENT_SETUP.md) | Full prerequisites, seeds, Entra, checks |
| [`PROJECT_PROGRESS.md`](PROJECT_PROGRESS.md) | Phase scorecard and what is validated |
