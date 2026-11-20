# Environment Setup

Validated on: macOS 26.5, Intel x86_64 (2026-11-16). Other hosts are not yet validated.

## 1. Prerequisites

| Tool | Version used | Install |
|---|---|---|
| Docker Desktop | 29.4.3 / Compose v5.1.3 | Start it from Finder/Spotlight; wait for "Engine running" |
| Rust | 1.100.0 (pinned in `endpoint/rust-toolchain.toml`) | Official `rustup-init` from static.rust-lang.org (verify its `.sha256`), then `rustup-init -y --profile minimal -c rustfmt -c clippy` |
| uv | 0.13.8 | `python3 -m pip install --user uv` (binary in `~/Library/Python/3.10/bin`) |
| Python | 3.12.16 (managed by uv) | `uv python install 3.12` |
| Node / npm | 24.13.0 / 11.6.2 | Already present |

Homebrew on this Intel/macOS 26 host has no bottles for `rustup`/`uv` dependencies and compiles
OpenSSL and CMake from source (>30 min), so the official installers above are used instead.

Add to your shell for the session:

```bash
export PATH="$HOME/Library/Python/3.10/bin:$HOME/.cargo/bin:$PATH"
```

## 2. First-time configuration

```bash
make init        # runs scripts/dev-init.sh
```

`dev-init.sh`:
- creates `.env` from `.env.example` with a random 64-char `SESSION_SECRET` and random Postgres password (mode 600);
- generates an Ed25519 job-signing keypair in `dev-keys/` (directory mode 700);
- never overwrites an existing `.env` or keypair and never prints secret values.

`.env`, `dev-keys/`, `*.pem`, `*.key` are git-ignored. Do not put secrets in `VITE_*` variables or web source.

## 3. Run

```bash
make up                      # dev-certs (if missing) -> postgres -> migrate -> backend + agent-gateway
curl http://127.0.0.1:8000/health/ready
cd web && npm ci && npm run dev    # open http://localhost:5173 (proxies /api and /health to :8000)
cd endpoint && cargo build --release
./endpoint/target/release/sentinel-agent check-backend --backend https://localhost:8443 --ca-cert dev-certs/ca.pem
make down
```

### 3a. Development TLS and the endpoint agent (Phase 3)

- `make dev-certs` (run automatically by `make up`) writes a private dev CA and a server
  certificate for `localhost`, `127.0.0.1`, `::1` to `dev-certs/` (git-ignored, mode 700). It
  refuses when `APP_ENV=production`. Renew with `cd backend && uv run python -m app.cli dev-certs --force`
  and restart the stack.
- `agent-gateway` serves the API over TLS 1.3 on `https://localhost:8443`. Agents must use it;
  browsers keep using the web app on `localhost:5173`.
- The agent trusts **only** the CA given by `--ca-cert` (or `SENTINEL_CA_CERT`); the path is
  remembered at enrollment. Without a CA file it uses the public Mozilla root set.
- Agent environment variables (all optional except during enroll):

| Variable | Purpose |
|---|---|
| `SENTINEL_BACKEND_URL` | Backend origin for `enroll` / `check-backend` |
| `SENTINEL_CA_CERT` | PEM CA file to trust exclusively |
| `SENTINEL_ENROLLMENT_TOKEN` | One-time token for non-interactive enrollment (otherwise prompted without echo; never pass it as an argument) |
| `SENTINEL_AGENT_CONFIG_DIR` | Override the state directory (default `~/Library/Application Support/com.SentinelDesk.Agent` on macOS) |

- Credential storage: macOS login Keychain, service `com.sentineldesk.agent.device-credential`,
  account = device id (view in Keychain Access). `--credential-store file` stores it 0600 in the
  config directory instead (weaker; used by automated tests).
- `sentinel-agent forget --yes` deletes local state and the stored credential. It does not revoke
  the credential on the server; quarantine the device for that.
- Exit codes: 0 success, 1 error, 2 usage, 3 credential revoked/expired or device quarantined.
- Backend setting: `DEVICE_CREDENTIAL_TTL_DAYS` (default 30, 1–365). Enrollment token TTL uses
  `DEVICE_ENROLLMENT_TTL_MINUTES` (capped at 60).

Ports are bound to `127.0.0.1` only. The backend container runs as uid 10001, read-only root
filesystem, all capabilities dropped, `no-new-privileges`. The signing keys are mounted as
Compose secrets at `/run/secrets/…`.

## 4. Checks

```bash
make check                 # backend fmt/lint/mypy/unit, web fmt/type/lint/test/build, rust fmt/clippy/test/build
make backend-integration   # requires `make up`; drops/recreates the disposable `sentinel_test` DB, migrates it, runs integration tests
```

The integration harness refuses to run unless the database name ends in `_test`; it never touches
the `sentinel` development database.

## 4a. Database roles and development accounts

- `POSTGRES_USER` (owner) runs migrations only (`MIGRATION_DATABASE_URL`).
- `sentinel_app` (`DATABASE_URL`, password `APP_DB_PASSWORD`) is what the backend uses: no superuser,
  no DDL, INSERT/SELECT only on `audit_events`, read-only `roles`.
- Existing `.env` files are upgraded in place by `make init` (backup written to `.env.backup-<time>`).

Create synthetic local accounts (development only; refuses in production):

```bash
cd backend && uv run python -m app.cli seed-dev                    # creates missing accounts
cd backend && uv run python -m app.cli seed-dev --reset-passwords  # rotates all seeded passwords
cd backend && uv run python -m app.cli seed-catalogue              # demo software/versions/aliases
cd backend && uv run python -m app.cli seed-security               # bans, policies, demo-malware fixture
```

Passwords are written once to `secrets/dev-accounts.txt` (mode 600, git-ignored) and never printed
or logged. Accounts: `employee.one`, `employee.two`, `approver`, `software.admin`, `security.admin`,
`auditor`, `platform.admin` — all `@sentinel.test`.

Catalogue seed (idempotent) adds: Visual Studio Code, Git, Restricted Remote Access Tool,
Contoso Notepad for Windows (incompatibility demo), and a PENDING_REVIEW incomplete editor.
Digests are synthetic (`sha256("sentineldesk-demo::…")`), not real package bytes.

Security seed adds: ban on `restricted-remote-access`, bans on demo-malware hash/package id,
policies (VS Code auto-approve, Git require approval, Contoso allow), and catalogue fixture
`demo-malware-sample` (synthetic — not real malware).

Phase 7 request workflow: `POST /api/v1/software/requests` persists a request after the same
orchestrator/policy path as preview. Approvers use `GET/POST /api/v1/admin/approvals…`.
Outlook Graph mail is optional — without `GRAPH_SENDER` (+ Entra), notification rows are marked
`NOT_CONFIGURED` and web approval still works. Approved/auto-approved requests create a `QUEUED`
job. Phase 8: agent claims signed jobs, verifies Ed25519, downloads the pkg, and calls
`sentinel-privileged` over a Unix socket. Use `approver@sentinel.test` (from `seed-dev`) for the
approval queue; self-approval is forbidden.

Agent job env (optional overrides):
- `SENTINEL_JOB_PUBLIC_KEY` — PEM public key (default: `<config-dir>/job_signing_public.pem`;
  copy from `dev-keys/job_signing_public.pem`).
- `SENTINEL_PRIVILEGED_SOCKET` — default `/var/run/sentineldesk/privileged.sock`.
- `SENTINEL_PACKAGE_DIR` — download cache (default: `<config-dir>/packages`).

Stage the GitHub CLI candidate (download + digest only, no install):
`./scripts/stage-gh-pkg.sh`

LaunchDaemon install is **gated on decision D2**. Preview plist:
`./scripts/install-privileged-launchdaemon.sh --print-plist`.
After explicit owner approval only:
`SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E ./scripts/install-privileged-launchdaemon.sh`.

## 5. Configuration validation rules (`backend/app/core/config.py`)

- `SESSION_SECRET` ≥ 32 chars and not a placeholder.
- `DATABASE_URL` must be `postgresql+asyncpg://` with host and database; placeholder password rejected.
- `CORS_ALLOWED_ORIGINS`: explicit `http(s)://host[:port]` origins only; no `*`, no paths.
- Entra: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` all-or-none. `GRAPH_*` requires Entra.
- `GEMINI_API_KEY` and `GEMINI_MODEL` together. Optional `GEMINI_TIMEOUT_SECONDS` (default 8) and
  `GEMINI_MAX_OUTPUT_TOKENS` (default 256). Both `JOB_SIGNING_*_KEY_PATH` together and must exist.
- Without Gemini credentials, `POST /api/v1/software/preview` still works via deterministic exact-alias
  fallback for phrases like “Install VS Code” / “Install git”.
- Production: https API/CORS origins and signing keys required; OpenAPI docs disabled; HSTS on.
- Validation messages never echo secret values. Integration status reports only configured/not_configured.

## 6. Credentials by phase

| Phase | Integration | Variables | Where to obtain |
|---|---|---|---|
| 1–4 | none external | generated locally | `make init` |
| 2 (optional live) | Entra ID OIDC | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_REDIRECT_URI` | [Register an app](https://learn.microsoft.com/entra/identity-platform/quickstart-register-app) |
| 5 | Threat intel (VirusTotal) | `THREAT_INTEL_PROVIDER=virustotal`, `THREAT_INTEL_API_KEY` | [VirusTotal API key](https://docs.virustotal.com/docs/please-give-me-an-api-key) |
| 6 | Gemini | `GEMINI_API_KEY`, `GEMINI_MODEL` (use a current flash model e.g. `gemini-3.5-flash-lite`; `gemini-2.0-flash` is retired), optional `GEMINI_TIMEOUT_SECONDS=30` | [Google AI Studio API keys](https://ai.google.dev/gemini-api/docs/api-key) |
| 7 (optional live) | Graph Mail.Send | `GRAPH_SENDER`, `GRAPH_SCOPES` + Entra vars | [Graph sendMail permissions](https://learn.microsoft.com/graph/api/user-sendmail) |

Put credentials only in `.env` (never in chat, source, or tickets).

### Stop / restart local services

- Stop backend stack: `make down` (or `docker compose down`).
- Stop privileged LaunchDaemon (after D2 install):  
  `sudo launchctl bootout system/com.sentineldesk.privileged`  
  and remove `/Library/LaunchDaemons/com.sentineldesk.privileged.plist` if desired.
- Restart stack later: `make up`.
- Restart LaunchDaemon later (only with D2):  
  `SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E ./scripts/install-privileged-launchdaemon.sh`

Phase 9 ops: `GET /api/v1/admin/ops/metrics` (security/platform admin),  
`POST /api/v1/admin/ops/purge-expired` (platform admin), or  
`cd backend && uv run python -m app.cli purge-expired`.

Phase 10 UI: open `http://localhost:5173` (not `127.0.0.1`). After sign-in, use the
primary nav — **Overview** / **Audit** need `integration:read` or `audit:read`
(e.g. `security.admin@sentinel.test`). Employee home shows request timelines.

## 7. Microsoft Entra ID sign-in (optional live test)

Needed only to test real Microsoft sign-in. Everything else works with local accounts. The same
app registration is reused for Outlook/Graph in Phase 7.

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) with an account that
   can register applications. On a corporate tenant this may require IT; a free
   [Microsoft 365 developer tenant](https://learn.microsoft.com/office/developer-program/microsoft-365-developer-program)
   or any personal Azure tenant works for testing.
2. **Identity → Applications → App registrations → New registration**
   - Name: `SentinelDesk (dev)`
   - Supported account types: **Accounts in this organizational directory only (Single tenant)**
   - Redirect URI: platform **Web**, value `http://localhost:5173/api/v1/auth/callback`
3. On the app's **Overview** page copy:
   - *Directory (tenant) ID* → `ENTRA_TENANT_ID`
   - *Application (client) ID* → `ENTRA_CLIENT_ID`
4. **Certificates & secrets → Client secrets → New client secret** (e.g. 90 days). Copy the
   **Value** column immediately (not the Secret ID) → `ENTRA_CLIENT_SECRET`.
5. **API permissions**: Microsoft Graph delegated `openid`, `profile`, `email` (User.Read is added by
   default and is harmless). If the tenant blocks user consent, an admin must click *Grant admin consent*.
6. **Token configuration** (optional): add optional claim `email` to the ID token. Without it the
   backend falls back to `preferred_username`.
7. Edit `.env` (do not paste these anywhere else):

   ```dotenv
   ENTRA_TENANT_ID=<directory-tenant-guid>
   ENTRA_CLIENT_ID=<application-client-guid>
   ENTRA_CLIENT_SECRET=<secret value>
   ENTRA_REDIRECT_URI=          # leave empty: defaults to ${WEB_BASE_URL}/api/v1/auth/callback
   ```

8. `make up` (restarts the backend with the new settings), open `http://localhost:5173`; a
   **Sign in with Microsoft** button appears. First sign-in creates an `EMPLOYEE` account keyed by
   tenant + object ID. If a local account already uses the same email, sign-in is refused with
   "account link required" (no automatic linking).

Reference: [Register an application](https://learn.microsoft.com/entra/identity-platform/quickstart-register-app),
[OIDC auth code flow](https://learn.microsoft.com/entra/identity-platform/v2-protocols-oidc).

## 8. Mac always-on agent + catalogue ingest (this-week demo)

macOS only for now; scale to other OS later. Full script: [`DEMO_THIS_WEEK.md`](DEMO_THIS_WEEK.md).

```bash
mkdir -p /Users/Shared/SentinelDesk/packages
make up
make macos-agent-install    # LaunchAgent + menu bar “Sentinel · Online”
```

- Compose mounts `/Users/Shared/SentinelDesk/packages` into the backend as `/data/packages`.
- Catalogue → **Add software**: HTTPS URL or .pkg upload; SHA-256/size auto; default **require approval**.
- Privileged pkg install still needs the Phase 8 root LaunchDaemon (separate from the user agent).
