# Intel Mac demo — from scratch to software install

> **Primary path for a fresh GitHub clone:** use [`HACKATHON_GUIDE.md`](HACKATHON_GUIDE.md) first.  
> This file is the longer print-style checklist (same product steps).

Clean checklist for a **new Intel (x86_64) Mac**.  
Follow every section in order. Do not skip the privileged daemon if you want a real install.

**Assumptions**

- This Mac runs the full demo stack itself (Docker + web + agent).
- The agent gateway is bound to `localhost` only, so a second laptop cannot share another Mac’s backend without networking changes.
- Passwords live in `secrets/dev-accounts.txt` (never paste them into chat or slides).

---

## 0. What you need before starting

| Item | Why |
|---|---|
| Intel Mac (x86_64), macOS recent enough for Docker Desktop | Demo machine |
| Admin password for this Mac | Privileged install daemon needs `sudo` |
| Docker Desktop installed and **Engine running** (green) | Backend + DB + TLS gateway |
| This repo on the Mac | Build agent, desktop app, daemon |
| Network for first package download | Catalogue ingest / installs |

Suggested clone path:

```bash
cd ~/Documents
# If you already have the zip/clone elsewhere, put it here:
# ~/Documents/Sentinel_Desk
```

---

## 1. One-time repo + Docker stack

```bash
cd ~/Documents/Sentinel_Desk

# Creates .env + signing keys if missing (safe to re-run; does not overwrite)
make init

# Package store used by catalogue ingest + agent
mkdir -p /Users/Shared/SentinelDesk/packages

# Postgres + migrate + backend (:8000) + TLS agent gateway (:8443)
make up
```

Wait until containers are healthy. Quick check:

```bash
curl -s http://localhost:8000/health/ready
```

You want a ready response that mentions the database as OK.

---

## 2. Create accounts (seed)

Accounts are created by the seed CLI (not by signing up in the browser).

```bash
cd ~/Documents/Sentinel_Desk/backend

# Prefer uv if installed; otherwise use your project Python the same way you usually run backend tools
uv run python -m app.cli seed-dev
uv run python -m app.cli seed-catalogue
uv run python -m app.cli seed-security
```

Passwords are written to:

`~/Documents/Sentinel_Desk/secrets/dev-accounts.txt`

| Account | Role in the demo |
|---|---|
| `employee.one@sentinel.test` | Requests software in chat |
| `approver@sentinel.test` | Approves installs |
| `software.admin@sentinel.test` | Adds packages to the catalogue |
| `platform.admin@sentinel.test` | Issues enrollment tokens / manages devices |

Open that file once, keep it private, use it for every sign-in below.

---

## 3. Start the web console

```bash
cd ~/Documents/Sentinel_Desk/web
npm ci
npm run dev
```

Open: **http://localhost:5173**  
(Use `localhost`, not `127.0.0.1` — CSRF expects localhost.)

Leave this terminal running during the demo.

---

## 4. Install Sentinel on this Intel Mac

### 4a. Menu-bar app (agent)

```bash
cd ~/Documents/Sentinel_Desk
make macos-desktop-install
open /Applications/Sentinel.app
```

- First launch may be blocked by Gatekeeper → **System Settings → Privacy & Security → Open Anyway**.
- Menu bar shows a Sentinel shield. Status may be Offline until enrollment (next section).
- Preferences should point at:
  - Backend: `https://localhost:8443`
  - Web console: `http://localhost:5173`
  - Local demo stack: **on** is fine on this builder/demo Mac

### 4b. Privileged install daemon (required for real installs)

The menu-bar agent downloads packages. A **root LaunchDaemon** performs the install into `/Applications`.

```bash
cd ~/Documents/Sentinel_Desk

# Preview only (optional):
./scripts/install-privileged-launchdaemon.sh --print-plist

# Real install (enter Mac admin password when prompted):
SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E ./scripts/install-privileged-launchdaemon.sh
```

Without this step, jobs often end as `PRIVILEGED_SERVICE_UNAVAILABLE` or stay pkg-gated.

---

## 5. Enroll this Mac as the employee’s device

Enrollment is **two parts**: create a one-time token in the web UI, then enroll the agent on the Mac.

### 5a. Create the enrollment token (platform admin)

1. Browser → http://localhost:5173  
2. Sign in as **`platform.admin@sentinel.test`** (password from `secrets/dev-accounts.txt`).  
3. Open **Enroll** in the left nav.  
4. Device owner → select **`employee.one@sentinel.test`**.  
5. Click **Create enrollment token**.  
6. Copy the token (`sde_…`). It is shown **once** and expires (~60 minutes).

Do **not** paste the token into chat, screenshots, or the command line as an argument.

### 5b. Enroll the agent on this Mac

In Terminal:

```bash
# Binary lives inside the app after macos-desktop-install:
AGENT="/Applications/Sentinel.app/Contents/MacOS/sentinel-agent"

export SENTINEL_BACKEND_URL="https://localhost:8443"
export SENTINEL_CA_CERT="$HOME/Documents/Sentinel_Desk/dev-certs/ca.pem"

# Interactive: paste the token when prompted (no echo)
"$AGENT" enroll
```

If the device was enrolled before and you need a clean enroll:

```bash
"$AGENT" enroll --force
```

Success looks like an `enrolled` event with a `device_id` (credential is **not** printed).

### 5c. Confirm enrollment

1. Keep **Sentinel.app** running (menu bar → aim for **Online**).  
2. Sign out of platform admin.  
3. Sign in as **`employee.one@sentinel.test`**.  
4. Open **My devices** → you should see this Mac as **ACTIVE**, architecture **x86_64** (or similar Intel label).

---

## 6. Make sure demo software exists (catalogue)

### Option A — Use seeded catalogue titles

Seed already adds demo titles (e.g. Git / VS Code). Prefer a title that is **not already installed** on this Mac, or the result may be `ALREADY_INSTALLED` / “newer version installed”.

### Option B — Add a fresh Intel-friendly app (recommended for a live install)

1. Sign in as **`software.admin@sentinel.test`**.  
2. **Catalogue → Add software**.  
3. Pick one:
   - **Popular apps** (Chrome, Firefox, Slack, …) — fine on Intel when the vendor ships universal/x86_64  
   - **Download link** — paste an `https://…` URL to `.pkg` / `.dmg` / `.zip`  
   - **Upload file** — drop a local installer  
4. Wait for **Inspecting…** to finish.  
5. On **Review**, leave **Require approval** **ON** for the approval story.  
6. **Add to catalogue**.

Intel tip: prefer **universal** or **x86_64** builds. Arm-only packages will fail compatibility on this machine.

---

## 7. End-to-end install demo (the show)

Keep **Sentinel** Online in the menu bar the whole time.

### 7a. Employee requests software

1. Sign in as **`employee.one@sentinel.test`**.  
2. Open **Home / chat**.  
3. Confirm the enrolled device is selected in the device dropdown.  
4. Type something clear, for example:

   > install Firefox  

   (or the exact catalogue name you added)

5. You should see a request card: often **AWAITING_APPROVAL** if require-approval is on, or it may go straight to **QUEUED** if auto-approved.

### 7b. Approver decides (if required)

1. Sign out → sign in as **`approver@sentinel.test`**.  
2. Open **Approvals**.  
3. Open the pending request → **Approve**.  
4. Status should become **QUEUED**.

### 7c. Watch the install on the Intel Mac

1. Menu bar: **Installing…** (or Online while download progress updates in the web card).  
2. In the employee chat card you should see honest progress:
   - download bytes when known  
   - indeterminate bar during install / verify  
3. Status ends as **SUCCEEDED**.  
4. Confirm the app under `/Applications` (or the CLI with `go version` / `gh --version` for CLI tools).

### 7d. Show the audit trail (optional closer)

Sign in as **`auditor@sentinel.test`** (or an admin with audit access) → **Audit** / Overview: who requested, who approved, what the device reported.

---

## 8. Quick “day of demo” order (print this)

1. Docker Desktop green  
2. `make up`  
3. `npm run dev` in `web/`  
4. Open **Sentinel.app** → Online  
5. Confirm privileged daemon already installed (section 4b)  
6. Employee chat → request software  
7. Approver → approve  
8. Watch install succeed → open the app  

If this Mac was never enrolled: do section 5 first (platform admin token → `sentinel-agent enroll`).

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `curl` ready fails / Offline forever | `make up`; wait for healthy containers; reopen Sentinel |
| Gatekeeper blocks Sentinel.app | Privacy & Security → Open Anyway |
| No enrolled device in chat | Complete section 5; check **My devices** as employee |
| `PRIVILEGED_SERVICE_UNAVAILABLE` | Re-run section 4b (LaunchDaemon) |
| `INSTALLER_UNSUPPORTED` | Rebuild/reinstall daemon after agent updates; ensure daemon advertises DMG/ZIP |
| `APP_IN_USE` | Quit the app being upgraded (e.g. Chrome), then ask again |
| `ALREADY_INSTALLED` / newer version | Pick another catalogue title or a fresh Add software item |
| CSRF / login weirdness | Use `http://localhost:5173`, not `127.0.0.1` |
| Keychain prompt after rebuild | Click **Always Allow**, or re-enroll |
| Catalogue empty | Re-run `seed-catalogue` (section 2) or Add software |

---

## 10. How to stop cleanly

```bash
# Quit Sentinel from the menu bar (⌘Q) — with Local demo stack on, this can also stop Docker

# Or from Terminal:
cd ~/Documents/Sentinel_Desk
make down
```

---

## Roles cheat sheet

| Who | Email | Does |
|---|---|---|
| Employee | `employee.one@sentinel.test` | Chat request + My devices |
| Approver | `approver@sentinel.test` | Approvals |
| Software admin | `software.admin@sentinel.test` | Catalogue → Add software |
| Platform admin | `platform.admin@sentinel.test` | Enroll token |
| Auditor | `auditor@sentinel.test` | Audit trail |

Passwords: `secrets/dev-accounts.txt` only.

---

## Related docs

| Doc | Use when |
|---|---|
| [`HACKATHON_GUIDE.md`](HACKATHON_GUIDE.md) | Short pitch + day-to-day runbook |
| [`MAC_DESKTOP_APP.md`](MAC_DESKTOP_APP.md) | Sentinel.app build / share zip details |
| [`DEMO_THIS_WEEK.md`](DEMO_THIS_WEEK.md) | Short 10-minute script |
| [`ENVIRONMENT_SETUP.md`](ENVIRONMENT_SETUP.md) | Deeper env / seed / Entra notes |
