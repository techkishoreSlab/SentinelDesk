# Project Progress Scorecard

Phase order per decision D4: Phase 5 = policy engine, Phase 6 = AI orchestration.

| Phase | Name | Status | Score | Manual validation | Approval |
|---|---|---|---:|---|---|
| 0 | Repository assessment and plan | COMPLETE | 90 | Not required | Approved 2026-11-16 |
| 1 | Foundation and dev environment | VALIDATED | 92 | PASS (owner, 2026-11-16) | Approved 2026-11-16 |
| 2 | Database, authN, authZ | VALIDATED | 91 | PASS steps 1–3; live Entra BLOCKED (owner, 2026-11-17) | Approved 2026-11-17 |
| 3 | Endpoint agent foundation | VALIDATED | 90 | PASS (owner, 2026-11-17) | Approved 2026-11-17 |
| 4 | Catalogue and compatibility | VALIDATED | 91 | PASS (owner, 2026-11-17) | Approved 2026-11-17 |
| 5 | Security intelligence and policy engine | VALIDATED | 90 | PASS (owner, 2026-11-17) | Approved 2026-11-17 |
| 6 | AI orchestration and tool system | VALIDATED | 91 | PASS (owner, 2026-11-17) | Approved 2026-11-17 |
| 7 | Request workflow | VALIDATED | 90 | PASS (owner, 2026-11-17) | Approved 2026-11-17 |
| 8 | Real installation | VALIDATED | 90 | PASS (owner, 2026-11-17) — gh 2.104.0 installed | Approved 2026-11-17 (D2) |
| 9 | Recovery, observability, audit | VALIDATED | 90 | PASS (owner, 2026-11-17) — metrics JSON | Approved 2026-11-17 |
| 10 | Frontend experience | VALIDATED | 90 | PASS (owner, 2026-11-17) — nav + Audit + employee Home | Approved 2026-11-17 |
| 11 | Integration/security testing | NOT STARTED | — | — | — |
| 12 | Deployment and demo | IN PROGRESS | — | Mac demo path this week | — |

## Phase 0
- Completed: spec read; host/tool detection; credential map; risks; plan. Decisions D1–D5 recorded.

## Phase 1
- Completed: repo layout; `.env.example`/`.env`/`dev-init.sh`; validated settings; JSON logging with
  redaction; standard error format; correlation IDs; security headers; body-size limit; strict CORS;
  `/health/live` and `/health/ready`; async SQLAlchemy + Alembic baseline; hardened Compose stack;
  React/TS app with typed API client; Rust workspace with strict protocol crate and agent connectivity check;
  Makefile; CI workflow file.
- Failed tests: none outstanding (5 defects found and fixed, see TEST_REPORT).
- Blocked: CI execution and Windows/Linux Rust builds (no runner).
- Manual validation (owner, 2026-11-16): readiness returned `database: ok`; web app showed
  "Ready / Backend v0.1.0 / database: ok"; `make down && make up` ended with postgres and backend
  Healthy and migrate Exited (0). All three steps PASS.
- Approved by owner 2026-11-16 ("yes start phase 2").

## Phase 2
- Completed:
  - Schema: 24 tables covering spec §11 plus documented extensions (sessions, auth throttle, OIDC
    login state, enrollment tokens, device credentials, aliases, security checks, integration config),
    47 CHECK constraints, migrations 0002/0003; `alembic check` reports no model drift.
  - Least-privilege runtime role `sentinel_app` (no superuser/createrole/createdb/bypassrls); owner
    role used only for migrations. `audit_events` INSERT/SELECT only; `roles` read-only.
  - Append-only, SHA-256 hash-chained audit log (triggers block UPDATE/DELETE/TRUNCATE even for the
    owner); chain verification endpoint detects tampering.
  - Local auth: Argon2id, timing-equalized unknown-account path, account + IP lockout, server-side
    sessions (hashed tokens, idle 30 min / absolute 8 h), HttpOnly cookie, double-submit CSRF + Origin check.
  - Entra ID OIDC: auth code + PKCE (S256), hashed single-use state, nonce, RS256-only, tenant JWKS
    with rotation refetch, issuer/audience/tenant checks, `tid:oid` identity, JIT EMPLOYEE only,
    email-conflict refuses auto-linking.
  - RBAC for six roles loaded from DB per request; denials audited. Devices IDOR-safe (404).
    Platform-admin role assignment with self-change and last-admin guards, audited.
  - Audit search (filters, seq cursor) and integration status endpoints. Dev seed CLI.
  - Web: sign-in form, Microsoft button only when configured, signed-in card, sign-out with CSRF header.
- Failed tests: none outstanding (defects found and fixed listed in TEST_REPORT).
- Blocked: live Entra sign-in (no tenant credentials yet); CI execution (no runner).
- Manual validation (owner, 2026-11-17), confirmed from backend request logs and the audit chain:
  employee sign-in 200; employee → `/admin/users` 403 with `ACCESS_DENIED` audited; auditor
  `/admin/audit/verify` and `/admin/audit` 200; sign-outs 204; chain valid (20 events).
  First attempts failed with `CSRF_FAILED` because the app was opened at `127.0.0.1`; the dev
  server now redirects to `localhost` (K16).
- Live Entra: redirect to Microsoft issued (302) but no callback returned; remains BLOCKED (K9).
- Approved by owner 2026-11-17 ("Start Phase 3").

## Phase 3
- Completed:
  - Enrollment: admin-issued one-time tokens (`sde_…`, SHA-256 hashed, ≤ 60 min, owner must be an
    active EMPLOYEE, revocable); atomic single-use consumption; device created ACTIVE; audited.
  - Device authentication: per-device bearer credentials (`sdc_…`, hashed, 30-day TTL), never
    cookies. Revoked/expired credentials audited. Rotation with a 10-minute grace that ends on
    first use of the new credential.
  - Heartbeat: strict facts schema (OS, build, architecture, CPU, memory, disk, up to 1000 installed
    software items); 5 s minimum gap (429); facts snapshot stored only on change or hourly;
    OS/architecture change rejected (403) and audited. `jobs/next` returns 204 (jobs are Phase 8).
  - Quarantine (DEVICE_MANAGE or SECURITY_MANAGE): revokes all credentials, audited with a reason code.
  - TLS: dev CA (ECDSA P-256) + loopback server certificate (`make dev-certs`); `agent-gateway`
    Compose service on 127.0.0.1:8443 serves the API over TLS 1.3 (TLS 1.1 refused).
  - Rust agent (`sentinel-agent`): `enroll`, `heartbeat`, `run`, `rotate-credential`, `status`,
    `forget`, `check-backend`. Trusts only the configured CA; credential in the macOS login
    Keychain (file store only on explicit opt-in); token read from env or a no-echo prompt, never
    argv; state file 0600 in a 0700 directory; JSON logs without secrets; jittered heartbeat,
    capped exponential backoff, stops with exit code 3 when revoked or quarantined.
  - Facts collection (macOS): SystemVersion.plist, `/Applications/*.app` bundle IDs, installer
    receipts; every value sanitized to backend bounds, unsafe values dropped.
  - Web: "My devices" (employee), "Enroll a device" (token shown once), "Fleet devices" with
    reason-coded quarantine (device/security admins).
  - Migration 0004: `device_facts` memory/disk columns widened to BIGINT (int32 overflow found in testing).
- Failed tests: none outstanding (defects found and fixed listed in TEST_REPORT).
- Blocked: Windows/Linux agent builds and runtime (no host, R1); CI execution (K5).
- Manual validation (owner, 2026-11-17): enroll via Keychain → PASS (`device_id` issued,
  `credential_store: keychain`); heartbeat ACTIVE → PASS; Fleet showed
  `Proglint-MacBook-Pro.local` ACTIVE; quarantine → QUARANTINED; post-quarantine heartbeat
  `DEVICE_UNAUTHENTICATED` exit 3 → PASS; `forget --yes` → PASS.
- Approved by owner 2026-11-17 ("start Phase 4").

## Phase 4
- Completed:
  - Exact catalogue alias matching (normalized, case-insensitive) over ACTIVE software only.
  - Employee search (`GET /catalogue/search`), list and software detail (ACTIVE only).
  - Compatibility evaluator for spec §8.2 steps 1–8 with structured reason codes
    (`DEVICE_STALE`, `OS_UNSUPPORTED`, `ARCH_UNSUPPORTED`, `OS_VERSION_TOO_OLD`,
    `INSUFFICIENT_*`, `PACKAGE_METADATA_INCOMPLETE`, `PACKAGE_NOT_APPROVED`,
    `ALREADY_INSTALLED`, `COMPATIBLE`). Security/approval deferred to Phase 5.
  - Admin catalogue CRUD: create software/aliases, create/patch versions, lifecycle changes;
    ACTIVE versions require every mandatory field; `source_reference` rejects raw URLs;
    mutations audited.
  - External catalogue connector Protocol + null implementation (imports would be PENDING_REVIEW).
  - Demo seed (`seed-catalogue`): VS Code (macos x86_64/arm64), Git, restricted remote-access,
    Contoso Notepad (Windows-only), incomplete PENDING_REVIEW editor. Digests are SHA-256 of
    demo labels, not real packages.
  - Web: Catalogue search + compatibility check; Catalogue admin list for software admins.
  - Setting `DEVICE_STALE_AFTER_SECONDS` (default 900).
- Failed tests: none outstanding.
- Blocked: banned-software hard blocks and threat intel (Phase 5); request workflow (Phase 7);
  real install (Phase 8).
- Manual validation (owner, 2026-11-17): search `vscode` → PASS; re-enroll ACTIVE device → PASS;
  VS Code → `ALREADY_INSTALLED` → PASS; Git → `COMPATIBLE` → PASS; Contoso Notepad →
  `OS_UNSUPPORTED` → PASS; Catalogue admin seed list → PASS.
- Approved by owner 2026-11-17 ("phase 4 working fine , start phase 5").

## Phase 5
- Completed:
  - Deterministic policy engine (spec §9.1 order): ban → package trust → threat intel →
    compatibility → organisational policy. Hard blocks beat every approval path.
  - Banned software matcher (CATALOGUE_ID / PUBLISHER / PACKAGE_ID / HASH / SIGNING_ID).
  - Threat intel: internal denied/pinned digest lists + VirusTotal hash lookup provider;
    missing/unavailable ⇒ INDETERMINATE ⇒ fail closed when mandatory (D3). Demo packages
    are pinned CLEAN only outside production.
  - Software policies: ALLOW (+ optional auto-approve), REQUIRE_APPROVAL, BLOCK.
  - `POST /security/evaluate` for employees; admin banned/policy/threat-status APIs.
  - Security check rows recorded (no raw provider payloads).
  - Seed: bans (restricted-remote-access, demo-malware hash/package), policies (VS Code
    auto-approve, Git require approval, Contoso allow), demo-malware-sample fixture.
  - Web: Catalogue **Evaluate policy**; Security admin banned-rules panel.
- Failed tests: none outstanding.
- Blocked: live VirusTotal (optional; needs API key); request workflow (Phase 7); install (Phase 8).
- Manual validation (owner, 2026-11-17): after heartbeat refresh — Git `REQUIRE_APPROVAL`
  · threat CLEAN → PASS; VS Code `ALREADY_INSTALLED` · threat CLEAN → PASS; banned remote
  access / demo-malware `BLOCKED` → PASS; Contoso `INCOMPATIBLE` → PASS; security bans
  panel → PASS.
- Approved by owner 2026-11-17 ("phase 5 working fine , start phase 6").

## Phase 6
- Completed:
  - Strict `SoftwareIntent` schema (extra=forbid; no URLs/commands); server-side prompts with
    `<user_request>` delimiters (spec §7.2–7.3).
  - Gemini REST client (`generateContent` + JSON schema): timeout/rate-limit errors, one repair
    retry on invalid JSON/schema, then deterministic fallback (D1).
  - Fixed tool registry (model never selects tools): `extract_intent` → `resolve_catalogue_alias`
    → `pick_catalogue_version` → `evaluate_policy` → `explain_decision`.
  - `POST /api/v1/software/preview` (preview only — no `software_requests` persistence; Phase 7).
  - Web **Request preview** panel for employees (`request:create`).
  - Config: `GEMINI_TIMEOUT_SECONDS`, `GEMINI_MAX_OUTPUT_TOKENS` (optional; key+model still paired).
- Failed tests: none outstanding.
- Blocked: request workflow / approvals (Phase 7); install (Phase 8).
- Manual validation (owner, 2026-11-17): Gemini configured (`gemini-3.5-flash-lite`);
  vague “microsoft code editor” → VS Code `ALREADY_INSTALLED` via gemini → PASS;
  `Git` → `REQUIRE_APPROVAL` via gemini → PASS; `Photoshop` → `NOT_FOUND` via gemini → PASS;
  schema/model fixes for live API validated.
- Approved by owner 2026-11-17 ("approve phase 6 and start phase 7").
- Score: 91.

## Phase 7
- Completed:
  - `POST/GET /api/v1/software/requests` (+ detail/cancel): persist orchestrator outcome, idempotency,
    optimistic `version`, expiry window.
  - Status mapping from policy/preview outcomes; `AUTO_APPROVED` → binding + `QUEUED` job;
    `AWAITING_APPROVAL` → Outlook outbox rows (`NOT_CONFIGURED` when Graph unset).
  - `GET /api/v1/admin/approvals` + `POST …/{request_id}/decision`: binding hash, self-approval
    forbidden, version conflict / already-decided races.
  - Web: **Software request** + **Approval queue** panels.
- Failed tests: none outstanding.
- Blocked: live Graph/Outlook send (optional); real package install (Phase 8).
- Manual validation (owner, 2026-11-17): Git submit → AWAITING_APPROVAL → approver Approve → queue empty → employee sees QUEUED; VS Code → ALREADY_INSTALLED → PASS.
- Approved by owner 2026-11-17 ("approve phase 7 , start phase 8").
- Score: 90.

## Phase 8
- Status: VALIDATED (D2 approved; LaunchDaemon installed; live GitHub CLI install succeeded).
- Completed: signed jobs; agent verify→download→IPC; root LaunchDaemon; official `gh` 2.104.0
  installed on owner Mac (`/usr/local/bin/gh`). Receipt id corrected to `com.github.cli`.
- Note: first live job reported `FAILED_VERIFICATION` only because catalogue had wrong
  package id; installer itself succeeded (confirmed by `gh --version`).
- Score: 90.
- Approved by owner 2026-11-17 (D2 + live install evidence).
- Owner stopped LaunchDaemon + `docker compose down` on 2026-11-17 before Phase 9 (Go
  second-install left for later). Binary remains at `/usr/local/sentineldesk/bin/`.

## Phase 9
- Status: VALIDATED (owner opened `/api/v1/admin/ops/metrics` as security.admin).
- Completed: `GET /api/v1/admin/ops/metrics` (security/platform/auditor);
  `POST /api/v1/admin/ops/purge-expired` + CLI `purge-expired` (K12);
  abandoned-job expiry on agent job claim; audit search `result=` filter;
  health/integrations unchanged (already §15.3).
- Score: 90.
- Approved by owner 2026-11-17 (metrics screenshot).

## Phase 10
- Status: VALIDATED (owner screenshots 2026-11-17).
- Completed (spec §14):
  - Permission-gated primary nav (Home, Approvals, Catalogue, Security, Devices,
    Overview, Audit, Enroll) replacing stacked admin panels.
  - Employee Home: devices + software request + preview; request progress timelines
    and request ID for support.
  - Admin Overview: live `/admin/ops/metrics` tiles (no fake charts).
  - Audit panel: search by action/result + chain verify; read-only.
  - Existing Approvals / Catalogue / Security / Devices / Enroll panels wired into nav.
  - Established dark navy theme preserved; empty/loading/error states on new panels.
- Failed tests: none (`make web-check` PASS — 37 tests).
- Manual validation (owner, 2026-11-17): security.admin → Audit with live
  LOGIN_SUCCEEDED/LOGOUT events → PASS; employee.one → Home + Catalogue only
  (no Overview/Audit), devices + software request → PASS.
- Score: 90.
- Approved by owner 2026-11-17 (UI screenshots).

## Phase 12 (Mac demo path — in progress)
- Scope: macOS first; always-on agent UX; catalogue ingest; require-approval for Go/gh.
- Completed so far: catalogue ingest + Add software wizard; premium chat/approvals UX;
  shareable **Sentinel.app** desktop (`make macos-desktop` / `make macos-desktop-install`);
  docs `DEMO_THIS_WEEK.md`, `MAC_DESKTOP_APP.md`.
- Next: owner install desktop app, demo walkthrough; Windows/Linux later.
