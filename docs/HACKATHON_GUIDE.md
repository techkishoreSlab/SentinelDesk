# SentinelDesk — Hackathon Guide

**Use this doc on a new Mac after cloning from GitHub.**  
It matches the current repo: Docker control plane, web console, Sentinel.app agent, privileged install daemon, chat install progress.

---

## What it is

Enterprise software request → policy/approval → **verified install on the enrolled Mac** → audit trail.

| Layer | URL / location | Role |
|---|---|---|
| Web console | `http://localhost:5173` | Chat, Approvals, Catalogue, Enroll, Audit |
| Backend API | `http://localhost:8000` | Auth, catalogue, policy, jobs |
| Agent gateway (TLS) | `https://localhost:8443` | What the Mac agent talks to |
| Sentinel.app | Menu bar | Runs agent; can start/stop local Docker on this Mac |
| Privileged daemon | LaunchDaemon | Root install into `/Applications` (`.pkg` / `.dmg` / `.zip`) |

macOS only for this demo. Windows/Linux agents are later.

---

## New Mac — prerequisites

Install these **before** cloning:

| Tool | Why |
|---|---|
| **Docker Desktop** | Postgres + backend + TLS gateway (`make up`) |
| **Xcode Command Line Tools** | `swiftc` for Sentinel.app (`xcode-select --install`) |
| **Rust** (`rustup`) | Builds `sentinel-agent` / privileged daemon |
| **uv** + Python 3.12 | Backend CLI (`seed-dev`, `dev-certs`) |
| **Node.js + npm** | Web console (`npm run dev`) |
| Mac **admin password** | Privileged LaunchDaemon install |

```bash
# Typical PATH for tools installed via rustup / pip --user
export PATH="$HOME/.cargo/bin:$HOME/Library/Python/3.10/bin:$PATH"
```

Docker Desktop must show **Engine running** (green) before `make up`.

---

## From GitHub clone → full product (do once)

Replace `YOUR_ORG/Sentinel_Desk` with your real GitHub URL.

### 1. Clone

```bash
cd ~/Documents
git clone https://github.com/YOUR_ORG/Sentinel_Desk.git
cd Sentinel_Desk
```

`.env`, `dev-keys/`, `dev-certs/`, and `secrets/dev-accounts.txt` are **git-ignored**. A fresh clone does not include passwords or signing keys — the next steps create them.

### 2. Init secrets + package store

```bash
make init
mkdir -p /Users/Shared/SentinelDesk/packages
```

Creates `.env` and job-signing keys if missing (safe to re-run; does not overwrite existing secrets).

### 3. Start the control plane

```bash
make up
curl -s http://localhost:8000/health/ready
```

Expect JSON with `"status":"ready"` and database OK.  
This builds/starts Postgres, migrations, backend (`:8000`), and agent gateway (`:8443`).

### 4. Seed accounts + demo catalogue + security

```bash
cd ~/Documents/Sentinel_Desk/backend
uv run python -m app.cli seed-dev
uv run python -m app.cli seed-catalogue
uv run python -m app.cli seed-security
```

Passwords are written **once** to:

`~/Documents/Sentinel_Desk/secrets/dev-accounts.txt`

| Email | Use for |
|---|---|
| `employee.one@sentinel.test` | Chat / request software |
| `approver@sentinel.test` | Approvals |
| `software.admin@sentinel.test` | Catalogue → Add software |
| `platform.admin@sentinel.test` | Enroll device token |
| `auditor@sentinel.test` | Audit trail |

Keep that file private. Do not commit it.

### 5. Web console

```bash
cd ~/Documents/Sentinel_Desk/web
npm ci
npm run dev
```

Open **http://localhost:5173** (use `localhost`, not `127.0.0.1`).

### 6. Sentinel.app (menu-bar agent)

```bash
cd ~/Documents/Sentinel_Desk
make macos-desktop-install
open /Applications/Sentinel.app
```

- Gatekeeper may block first open → **System Settings → Privacy & Security → Open Anyway**.
- Preferences (seeded for local demo):
  - Backend: `https://localhost:8443`
  - Web console: `http://localhost:5173`
  - Local demo stack: **on** (this Mac runs Docker via Sentinel)

### 7. Privileged install daemon (required for real installs)

Without this, installs fail with `PRIVILEGED_SERVICE_UNAVAILABLE` or stay pkg-only.

```bash
cd ~/Documents/Sentinel_Desk
SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E ./scripts/install-privileged-launchdaemon.sh
```

Enter the Mac admin password when prompted. Daemon supports **pkg, dmg, and zip** app installs when this step succeeds.

### 8. Enroll this Mac (token alone is not enough)

**A. Create token (browser)**

1. Sign in as `platform.admin@sentinel.test`.
2. Left nav → **Enroll**.
3. Owner → `employee.one@sentinel.test`.
4. **Create enrollment token** → copy `sde_…` (shown once).

**B. Consume token (Terminal on this Mac)**

```bash
AGENT="/Applications/Sentinel.app/Contents/MacOS/sentinel-agent"
export SENTINEL_BACKEND_URL="https://localhost:8443"
export SENTINEL_CA_CERT="$HOME/Documents/Sentinel_Desk/dev-certs/ca.pem"

"$AGENT" enroll
# Paste the token at the prompt (it will not echo), then Enter
```

Re-enroll if needed: `"$AGENT" enroll --force`.

**C. Confirm**

1. Keep Sentinel.app open → menu bar should reach **Online**.
2. Sign in as `employee.one@sentinel.test` → **My devices** → this Mac **ACTIVE**.

---

## Day-of demo (after setup)

1. Docker Desktop green.
2. `make up` (if containers are down).
3. `cd web && npm run dev` (if console is not already up).
4. Open **Sentinel.app** → Online.
5. Employee chat → request software (device selected).
6. Approver → **Approvals** → approve (if required).
7. Watch install card (download % when known; indeterminate during install/verify) → **SUCCEEDED**.
8. Optional: show Audit / Overview.

### Suggested request

- Seeded titles (Git, VS Code, …) or **Catalogue → Add software** (Popular apps / URL / upload).
- Prefer an app **not already** on the Mac, or you may get `ALREADY_INSTALLED` / newer-version messaging.
- Prefer **universal** or matching CPU (Intel vs Apple Silicon) packages.

### 10-minute talk track

1. Menu bar Online = endpoint agent on the employee Mac.
2. Employee asks in chat → policy may require approval.
3. Approver approves → agent installs with digest / Team ID checks.
4. Audit shows who asked, who approved, what ran.

---

## How to stop

| Action | How |
|---|---|
| Quit Sentinel | Menu bar → Quit (⌘Q). With Local demo stack on, this also stops the agent and can run `docker compose down`. |
| Stop stack only | `cd ~/Documents/Sentinel_Desk && make down` |
| Old LaunchAgent path only | `launchctl bootout "gui/$(id -u)/com.sentineldesk.agent"` and `…/com.sentineldesk.menubar` |

---

## Architecture

```
Browser (5173) ──► Backend (8000) ──► Postgres
                         ▲
Mac Sentinel.app ──TLS──► Agent gateway (8443)
   │
   └── privileged daemon → /Applications
```

Ports bind to **127.0.0.1** only. This Mac runs its own stack; another laptop cannot share this backend without networking changes.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose` / migrate failed | Docker Engine green; `make up`; if migrate can’t find a revision, rebuild: `docker compose up -d --build --wait` |
| Sentinel **Issue** / stack failed | `~/Library/Application Support/com.SentinelDesk.Agent/stack.log` |
| Offline forever | Wait 10–30s; `curl localhost:8000/health/ready`; reopen Sentinel |
| No enrolled device in chat | Finish enroll steps (token **and** `sentinel-agent enroll`) |
| `PRIVILEGED_SERVICE_UNAVAILABLE` | Re-run section 7 (LaunchDaemon) |
| Stuck **RUNNING** after restart | Agent should close interrupted jobs on next start; otherwise wait for job TTL or ask again |
| CSRF / login odd | Use `http://localhost:5173`, not `127.0.0.1` |
| Gatekeeper blocks app | Privacy & Security → Open Anyway |
| Empty catalogue | Re-run `seed-catalogue` or Add software as `software.admin` |
| No “Add software” | Sign in as `software.admin@sentinel.test` |

---

## One-liners for the head

- **Problem:** Shadow IT and unsafe installers; no approval trail.
- **Product:** Chat → policy → approval → verified Mac install → audit.
- **Trust:** Pinned digests, Team ID checks, enrollment + TLS agent channel.
- **Demo:** Menu-bar Online + web chat + Approvals + Catalogue.

---

## Related docs

| Doc | When |
|---|---|
| [`INTEL_MAC_DEMO_FROM_SCRATCH.md`](INTEL_MAC_DEMO_FROM_SCRATCH.md) | Extra detail / print checklist |
| [`MAC_DESKTOP_APP.md`](MAC_DESKTOP_APP.md) | Sentinel.app build / share zip |
| [`ENVIRONMENT_SETUP.md`](ENVIRONMENT_SETUP.md) | Tool versions, Entra, deeper env |
| [`PROJECT_PROGRESS.md`](PROJECT_PROGRESS.md) | Phase scorecard |
