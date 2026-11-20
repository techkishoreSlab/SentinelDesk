# Test Report

## Phase 0

No application code; automated test categories NOT APPLICABLE. Host detection commands and a
GitHub Releases API query (gh v2.104.0 macOS pkg exists) were executed.

## Phase 1 — 2026-11-16, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format | `uv run ruff format --check .` | PASS — 20 files already formatted |
| Backend lint | `uv run ruff check .` (incl. bandit `S` rules) | PASS — all checks passed |
| Backend types | `uv run mypy` (strict) | PASS — 12 source files, no issues |
| Backend unit | `uv run pytest -q` | PASS — 36 passed |
| Backend integration (real PostgreSQL 17) | `make backend-integration` | PASS — 3 passed (run twice, before and after migration round-trip) |
| Migrations | `alembic downgrade base` → `upgrade head` | PASS — `0001 (head)` |
| Compose stack | `docker compose up -d --build --wait backend` | PASS — postgres healthy, migrate exited 0, backend healthy |
| Readiness under DB outage | stop postgres → `/health/ready` | PASS — 503 while down, `/health/live` 200, recovered to 200 in 2 s |
| Container hardening | `id`, write to `/app` | PASS — uid 10001, read-only FS |
| Web format/types/lint | `npm run format:check`, `typecheck`, `lint` | PASS |
| Web unit | `npm test` (Vitest + RTL) | PASS — 7 passed |
| Web build | `npm run build` | PASS — 223 kB JS (69.9 kB gzip) |
| Web → backend (real) | Vite proxy `/health/live`, `/health/ready`; browser screenshot | PASS — live 200, ready 503 rendered as "Unavailable" with correlation ID (DB not yet up at the time) |
| Rust format/lint | `cargo fmt --check`, `cargo clippy -D warnings` | PASS |
| Rust unit | `cargo test --workspace` | PASS — 10 passed (protocol 6, agent 4) |
| Rust release build | `cargo build --release` | PASS — 2.8 MB `sentinel-agent` |
| Agent → backend (real) | `sentinel-agent check-backend --backend http://127.0.0.1:8000` | PASS — host uvicorn and Docker backend both `result: ok` |
| Agent TLS policy | `--backend http://10.0.0.5:8000` | PASS — rejected: plain http only for loopback |
| Python deps | `uvx pip-audit` | PASS — no known vulnerabilities |
| Web deps | `npm audit` | PASS — 0 vulnerabilities (after minimatch override, see KNOWN_ISSUES) |
| Rust deps | `cargo audit` | PASS — 107 crates, 1509 advisories, none matched |
| Secret scan | pattern scan of the 64 trackable files and `web/dist` | PASS — no `.env`/keys tracked, no secret patterns |
| Log secret leak | grep backend container logs for password/secret | PASS — 0 matches |
| CI workflow | `.github/workflows/ci.yml` | BLOCKED — no remote repository/runner yet; never executed |
| Windows/Linux endpoint build | CI matrix | BLOCKED — not executed (no runner) |

### Owner manual validation (2026-11-16)

| Step | Result | Evidence |
|---|---|---|
| `curl /health/ready` | PASS | `{"status":"ready","checks":{"database":"ok"}}` |
| Web app at :5173 | PASS | Screenshot: "Ready", "Backend v0.1.0", "database: ok" |
| `make down && make up` | PASS | postgres Healthy, migrate Exited, backend Healthy |

### Defects found and fixed during Phase 1

1. Chunked oversized request bodies would have been turned into HTTP 400 by FastAPI; now 413 (test added).
2. Uvicorn `color_message` leaked ANSI escape sequences into JSON logs; control sequences now stripped (test added).
3. Agent URL validator reported the wrong error for `file://` URLs (scheme now checked first; test caught it).
4. `dev-init.sh` aborted silently under `pipefail` when generating random secrets; fixed.
5. React effect called `setState` synchronously (lint error); restructured.

## Phase 2 — 2026-11-16, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format | `uv run ruff format --check .` | PASS — 59 files already formatted |
| Backend lint | `uv run ruff check .` (incl. bandit `S` rules) | PASS |
| Backend types | `uv run mypy` (strict) | PASS — 44 source files |
| Backend unit | `uv run pytest -q` | PASS — 71 passed (passwords, tokens, RBAC, audit hashing/metadata, Entra token validation with local RSA keys) |
| Backend integration (real PostgreSQL 17, disposable `sentinel_test` DB) | `make backend-integration` | PASS — 37 passed |
| Entra callback (SIMULATED IdP, mock transport, local RSA keys) | part of integration suite | PASS — provisioning, replay rejection, nonce/issuer/audience/expiry/wrong-code/IdP-error rejection, email-conflict |
| Entra callback (LIVE Microsoft tenant) | manual | BLOCKED — no tenant credentials configured |
| Migrations | `alembic downgrade base` → `upgrade head` on `sentinel_test`; `alembic check` | PASS — 3 down, 3 up, no model drift |
| Dev DB migration | `make up` (0001 → 0003) | PASS — backend healthy as `sentinel_app` |
| DB privileges (dev DB) | `psql` grant/trigger inspection | PASS — `sentinel_app` non-superuser; audit INSERT,SELECT; roles SELECT; 2 append-only triggers |
| Seed CLI | `python -m app.cli seed-dev` twice | PASS — 7 accounts, second run no-op; file mode 600, dir 700, git-ignored |
| Live API smoke (Docker backend) | `curl` | PASS — providers, 401 anon, 403 no Origin, 401 bad password, 503 Entra not configured, security headers |
| Log secret leak | grep backend logs for submitted password | PASS — 0 matches |
| Web format/types/lint | `npm run format:check`, `typecheck`, `lint` | PASS |
| Web unit | `npm test` | PASS — 16 passed (7 Phase 1 + 9 session) |
| Web build | `npm run build` | PASS — 228.6 kB JS (71.4 kB gzip) |
| Rust fmt/clippy/test/build | `make endpoint-check` | PASS — 10 tests (unchanged this phase) |
| Python deps | `uvx pip-audit --strict` | PASS — no known vulnerabilities |
| Web deps | `npm audit` | PASS — 0 vulnerabilities |
| Rust deps | `cargo audit` | PASS |
| Secret scan | patterns (Google/Azure/GitHub/Slack keys, private keys) over trackable files; sensitive-file staging check | PASS — none |
| CI workflow | updated for runtime/test DB roles | BLOCKED — never executed (no runner) |

Integration scenarios covered: login success with hardened cookies; wrong password vs unknown user
indistinguishable; disabled user; missing/hostile Origin; lockout after 5 failures; logout CSRF
(missing, forged, wrong Origin) and session revocation with replayed cookie; idle expiry;
deactivated user; unauthenticated access; Entra not configured; employee 403 on admin endpoints
with audited denials; auditor read-only; device IDOR (404); role assign/remove with audit and
idempotency; self-change, CSRF, invalid role, extra field and unknown user guards; integration
status has no secrets; runtime role cannot UPDATE/DELETE/TRUNCATE audit or modify roles; owner
blocked by append-only trigger; chain verifies, detects tampering; 10 concurrent appends stay linear.

### Defects found and fixed during Phase 2

1. mypy: `on_conflict_do_update().returning()` reassigned to a narrower variable type; fixed.
2. Production-config test broke once `LOCAL_AUTH_ENABLED` became mandatory in production; test updated.
3. `assert` used for runtime config checks in Entra code (stripped under `python -O`); replaced with explicit errors.
4. Test settings inherited values from the developer's shell/.env (would flip Entra tests once
   credentials are added); tests now build settings from explicit values only.
5. SQLAlchemy 2.1 deprecation (`Result.tuples()`) in seed CLI; fixed.
6. Web lint: deprecated React `FormEvent` type and an unnecessary assertion; fixed.

## Phase 3 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format | `uv run ruff format --check .` | PASS — 70 files |
| Backend lint | `uv run ruff check .` (incl. bandit `S` rules) | PASS |
| Backend types | `uv run mypy` (strict) | PASS — 51 source files |
| Backend unit | `uv run pytest -q` | PASS — 74 passed (+3 dev-cert tests: chain, SANs, EKU, permissions, no overwrite) |
| Backend integration (real PostgreSQL 17, `sentinel_test`) | `make backend-integration` | PASS — 60 passed (22 agent API + 1 agent e2e + 37 Phase 2) |
| Agent ↔ backend e2e (real Rust binary, uvicorn over TLS with a throwaway CA, file credential store in a temp dir) | `tests/integration/test_agent_e2e.py` | PASS — rogue-CA rejection without consuming the token; enroll; 0700/0600 files; token reuse refused; failed re-enroll keeps the old enrollment; heartbeat; rotate (exactly one live credential); status; quarantine → `run` exits 3; forget; no token/credential in any agent output |
| Migrations | `alembic downgrade base` → `upgrade head`; `alembic check` | PASS — 4 down, 4 up, head `0004`, no drift |
| Dev DB | `make up` applies 0004; backend + agent-gateway healthy | PASS |
| TLS gateway | `curl`/`openssl s_client` against 127.0.0.1:8443 | PASS — pinned CA verifies for `localhost` and `127.0.0.1`; system trust alone fails; TLS 1.3 negotiated; TLS 1.1 refused |
| Agent smoke vs Docker gateway | `sentinel-agent check-backend` | PASS — OK with `--ca-cert dev-certs/ca.pem`; fails without it; `status` unenrolled and `enroll` without token fail cleanly |
| Rust fmt/clippy (`-D warnings`)/test/build | `make endpoint-check` | PASS — 31 tests (19 agent: TLS CA loading, state perms/symlink/tamper, file store, facts scanning + sanitization + caps, real host facts valid, jitter, backoff, token format; 12 protocol) |
| Web format/types/lint/test/build | `make web-check` | PASS — 22 tests (+6 devices: parsers, owner filter, one-time token + CSRF header, reason-gated quarantine); 235.2 kB JS (73.0 kB gzip) |
| Python deps | `uvx pip-audit --strict` | PASS — no known vulnerabilities |
| Web deps | `npm audit` | PASS — 0 vulnerabilities |
| Rust deps | `cargo audit` | PASS — 155 crates, none matched |
| Secret scan | gitignore-aware pattern scan (private keys, Google/GitHub/Slack keys, `sde_`/`sdc_` secrets) | PASS — only all-`A` test placeholders; `dev-certs/`, `secrets/`, `.env`, `target/` not trackable |
| Keychain credential store (real macOS Keychain) | manual | PENDING — owner validation step 2 |
| Windows / Linux agent | — | BLOCKED — no host (R1); the code compiles only for the macOS target here |
| CI workflow | — | BLOCKED — never executed (K5) |

### Defects found and fixed during Phase 3

1. `device_facts.memory_total_bytes`/`disk_free_bytes` were int32; a 16 GiB Mac overflowed. Widened to BIGINT (migration 0004).
2. Audit metadata keys `enrollment_token_id` / `credentials_revoked` were rejected by the secret-key filter; renamed (`enrollment_id`, `revoked_count`).
3. Integration body-size cap (4 KB) returned 413 instead of the intended 422; harness cap raised to 1 MiB.
4. Invalid uvicorn flag `--proxy-headers=false` in Compose; replaced with `--no-proxy-headers`.
5. `enroll --force` deleted the existing enrollment before the new one succeeded, so a bad token left the device unenrolled; old credential now removed only after the new one is persisted (e2e assertion added).

## Phase 4 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format/lint/types | `make backend-check` (ruff, mypy strict) | PASS — 81 files / 60 typed sources |
| Backend unit | `uv run pytest -q` | PASS — 79 passed (+5 catalogue: normalize, version compare, mandatory fields, reason-order blocks) |
| Backend integration | `make backend-integration` | PASS — 65 passed (+5 catalogue API: alias search, unknown empty, OS mismatch, already-installed, stale, IDOR 404, admin create/activate, URL source rejected, incomplete ACTIVE refused, Git COMPATIBLE) |
| Catalogue seed | `python -m app.cli seed-catalogue` | PASS — 5 software, 6 versions, 11 aliases |
| Web format/types/lint/test/build | `make web-check` | PASS — 24 tests (+2 catalogue); 240.8 kB JS (74.3 kB gzip) |
| Rust | `make endpoint-check` | PASS — 31 tests (unchanged) |
| Python/Web/Rust deps | pip-audit / npm audit / cargo audit | PASS |
| Secret scan | gitignore-aware key patterns | PASS — no private keys / API key shapes |
| Banned software / threat intel | — | DEFERRED — Phase 5 |
| CI | — | BLOCKED — never executed (K5) |

## Phase 5 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format/lint/types | `make backend-check` | PASS — 68 typed sources |
| Backend unit | `uv run pytest -q` | PASS — 83 (+4 threat digest / fail-closed unit tests) |
| Backend integration | `make backend-integration` | PASS — 73 (+8: ban hard-block, malware block, Git REQUIRE_APPROVAL, VS Code AUTO_APPROVE, ALREADY_INSTALLED, OS_UNSUPPORTED, unpinned INDETERMINATE fail-closed, security admin list + employee 403) |
| Security seed | `python -m app.cli seed-security` | PASS — 3 bans, 3 policies, 1 malware fixture |
| Web | `make web-check` | PASS — 24 tests; policy evaluate control |
| Rust | `make endpoint-check` | PASS — 31 tests |
| Dep audits | pip-audit / npm audit / cargo audit | PASS |
| Live VirusTotal | — | BLOCKED — no API key (optional; internal pins cover demo) |
| CI | — | BLOCKED — never executed (K5) |

## Phase 6 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format/lint/types | `make backend-check` | PASS — 79 typed sources |
| Backend unit | `uv run pytest -q` | PASS — 89 (+6 AI: intent schema, fallback phrasing, StaticIntentExtractor, Gemini schema repair, Gemini timeout) |
| Backend integration | `make backend-integration` | PASS — 78 (+5: fallback Git REQUIRE_APPROVAL, VS Code AUTO_APPROVE, NOT_FOUND + banned BLOCKED, StaticGemini + timeout fallback, foreign device 404) |
| Web | `make web-check` | PASS — 26 tests; Request preview panel |
| Rust | `make endpoint-check` | PASS (unchanged) |
| Live Gemini | — | PASS (owner) — `gemini-3.5-flash-lite`; vague VS Code / Git / Photoshop paths |
| CI | — | BLOCKED — never executed (K5) |

## Phase 7 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format/lint/types | `make backend-check` | PASS — 87 typed sources |
| Backend unit | `uv run pytest -q` | PASS — 92 (+3 binding/transition; Gemini model-not-found already counted in Phase 6+) |
| Backend integration | `make backend-integration` | PASS — 81 (+3: Git AWAITING_APPROVAL + idempotency, self-approval forbidden + approve→QUEUED, VS Code auto→QUEUED) |
| Web | `make web-check` | PASS — 28 tests; Software request + Approval queue |
| Live Outlook Graph | — | BLOCKED — `GRAPH_SENDER` not configured (notifications `NOT_CONFIGURED`) |
| CI | — | BLOCKED — never executed (K5) |

## Phase 8 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend unit (signing) | `uv run pytest -q tests/test_jobs_unit.py` | PASS — sign/verify + canonical JSON matches agent |
| Backend integration | `make backend-integration` | PASS — 83 (+2: signed claim→started→result fail-closed; empty 204) |
| Endpoint fmt/clippy/test | `cargo fmt/clippy/test --workspace` | PASS — agent job runner + privileged binary |
| LaunchDaemon script | `./scripts/install-privileged-launchdaemon.sh` | PASS — builds binary, refuses install without D2 env |
| Live LaunchDaemon install | `SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2` + admin install | PASS — `com.sentineldesk.privileged` running; socket ping `PONG` |
| Stage `gh` pkg | `./scripts/stage-gh-pkg.sh` | PASS — digest `5a4dd756…42281df6`, 28841135 bytes |
| Live `gh` pkg install via agent | approve + `sentinel-agent run --max-cycles 2` | PASS — `gh version 2.104.0` installed; first job `FAILED_VERIFICATION` due to wrong receipt id (`github.cli`→`com.github.cli`, fixed) |
| Job public key path | agent config dir | Fixed — key must live at `~/Library/Application Support/com.SentinelDesk.Agent/job_signing_public.pem` |
| CI | — | BLOCKED — never executed (K5) |

## Phase 9 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Backend format/lint/types | `make backend-check` | PASS — 95 typed sources |
| Backend unit | `uv run pytest -q tests/test_ops_unit.py` | PASS |
| Backend integration | `make backend-integration` | PASS — 85 (+2 ops metrics/purge) |
| Retention / metrics APIs | `/api/v1/admin/ops/*` | PASS (automated) |
| Owner manual metrics | `GET /api/v1/admin/ops/metrics` as security.admin | PASS — JSON with requests/jobs/devices/install_outcomes |
| CI | — | BLOCKED — never executed (K5) |

## Phase 10 — 2026-11-17, macOS 26.5 x86_64

| Suite | Command | Result |
|---|---|---|
| Web format/types/lint/test/build | `make web-check` | PASS — 37 tests (+9: timeline, ops parse/render, audit parse/render, dashboard nav); 264.2 kB JS (79.4 kB gzip) |
| New UI surfaces | Dashboard nav, OpsOverview, AuditPanel, request timelines | Covered by unit/component tests |
| Owner manual UI | security.admin Audit + employee Home gated nav | PASS — screenshots 2026-11-17 |
| CI | — | BLOCKED — never executed (K5) |
