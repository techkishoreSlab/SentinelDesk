# Known Issues, Risks and Decisions

## Decisions (approved by product owner, 2026-11-16)

| ID | Decision |
|---|---|
| D1 | Deterministic orchestrator runs the agent loop over a fixed typed tool registry. Gemini only extracts intent, asks clarification, and explains. Model output never selects tools (spec §7.3). Do **not** adopt LangChain/LangGraph tool-calling for installs — keep allowlisted catalogue + policy tools; multi-turn continuity and guardrails live in the chat agent layer + fallback intent. |
| D2 | macOS privileged service = root LaunchDaemon with a closed typed command surface. Installed only after explicit owner approval in Phase 8. |
| D3 | Mandatory threat intel = VirusTotal hash lookup + internal pinned-digest list. Missing key/unavailable ⇒ `INDETERMINATE` ⇒ fail closed. |
| D4 | Phase order swapped: Phase 5 = Security intelligence and policy engine, Phase 6 = AI orchestration and tools. |
| D5 | Environment variable names follow spec §20 (`ENTRA_*`, `GRAPH_*`). |

## Open issues

| ID | Severity | Issue | Plan |
|---|---|---|---|
| K1 | Low | `typescript-eslint` pinned to 8.72.2: 8.73.0 is published but its `@typescript-eslint/types@8.73.0` dependency is missing from npm. | Re-check and upgrade in a later phase. |
| K2 | Low | `minimatch` forced to 11.0.8 via npm `overrides` for `@typescript-eslint/typescript-estree` (GHSA-g3hv-75wg-m249, dev-only lint tooling). Lint verified working. | Remove override once upstream ships a fixed range. |
| K3 | Low | Dev signing private key file is mode 644 (so the uid-10001 container can read the bind-mounted secret); protected by `dev-keys/` mode 700. Dev only. | Production uses a secret manager/KMS (spec §9.9). |
| K4 | Medium | Endpoint↔backend TLS not yet implemented; agent allows plain http only to loopback. | Resolved in Phase 3: dev CA, TLS 1.3 `agent-gateway`, agent trusts only the configured CA. |
| K5 | Medium | CI workflow written but never executed (no remote). Windows/Linux Rust builds unverified. | Execute when a remote/runner exists. |
| K6 | Info | Docker Desktop crashes when launched from the agent session ("opening tray: starting electron"); owner must start it manually. | Documented in ENVIRONMENT_SETUP. |
| K7 | Info | Homebrew builds `rustup`/`uv` deps from source on this host; official installers used instead. | Documented. |
| K8 | Info | `uv` installed under `~/Library/Python/3.10/bin`, not on PATH by default. | Documented PATH export. |
| K9 | Medium | Live Entra ID sign-in not tested; only a simulated IdP. | Owner supplies tenant credentials in `.env` (ENVIRONMENT_SETUP §7), then manual test. |
| K10 | Medium | Client IP is the direct peer; `X-Forwarded-For` is ignored. Behind a reverse proxy all users would share one IP throttle bucket. | Add trusted-proxy configuration in Phase 12 deployment. |
| K11 | Low | Account lockout can be triggered by anyone who knows an email (15 min). Inherent trade-off of lockout. | Accept for dev; consider progressive delay + CAPTCHA-free backoff in Phase 11. |
| K12 | Low | Expired `sessions`, `oidc_login_states` and `auth_throttle` rows are not purged. | Phase 9: `POST /api/v1/admin/ops/purge-expired` + `python -m app.cli purge-expired`. |
| K13 | Low | Migration 0003 sets the runtime role password via `ALTER ROLE … PASSWORD`; it would appear in Postgres logs if `log_statement=all`, and in `alembic upgrade --sql` offline output. | Do not use offline SQL mode; production uses managed secrets/IAM auth (Phase 12). |
| K14 | Info | `LAST_PLATFORM_ADMIN` guard is defense-in-depth: the API forbids self role changes, so it is not reachable via HTTP and has no integration test. | Keep; re-evaluate if service accounts can change roles. |
| K15 | Info | Argon2id (64 MiB) per login attempt; concurrent attempts are throttled per account/IP but not globally bounded. | Global concurrency limit for `/auth/login` in Phase 11. |
| K17 | Medium | The `agent-gateway` (TLS, :8443) serves the whole API, not only `/api/v1/agent/*`; browser routes are reachable there too (still behind session/CSRF). | Phase 12: route only agent paths through the agent-facing listener / reverse proxy. |
| K18 | Low | Dev server private key is mode 644 inside `dev-certs/` (mode 700) so the uid-10001 container can read it; server cert valid 90 days (`make dev-certs` regenerates only if missing; use `--force` to renew). Dev only. | Production certificates from a managed CA. |
| K19 | Info | The macOS Keychain ties an item's access to the binary's code signature. The dev agent is unsigned, so after a rebuild macOS may prompt "sentinel-agent wants to use your confidential information" when reading the credential. Click "Always Allow" or re-enroll. | Code-sign the agent (Phase 12). |
| K20 | Low | The agent does not yet verify job signatures because it executes no jobs; `jobs/next` payloads are logged and ignored. | Resolved in Phase 8: Ed25519 verify before download/IPC. |
| K21 | Info | The agent→backend e2e test needs the Rust binary; it skips when the binary is absent (CI's Python job has no Rust toolchain). `make backend-integration` builds it first. | Add a combined CI job when CI runs (K5). |
| K22 | Low | Facts are collected on every heartbeat (scan of `/Applications` and receipts, bounded to 5000 entries each). Cheap on this host; not profiled on large fleets. | Cache inventory between heartbeats in Phase 9 if needed. |
| K23 | Info | Catalogue search is exact alias/slug/display-name only (no fuzzy search). | Phase 6: Gemini (when configured) extracts a software query; matching remains exact alias/slug/name. Without Gemini, deterministic fallback handles “Install VS Code” / “Install git”. |
| K24 | Low | Demo package digests are SHA-256 of fixed labels (`sentineldesk-demo::…`), not bytes of real installers. Sufficient for catalogue/compat; real digests required before Phase 8 install. | github-cli 2.104.0 uses real SHA-256 pin; other demo rows remain synthetic. |
| K25 | Info | Software policies and banned rules tables exist but are not evaluated yet (Phase 5). Restricted remote-access is in the ACTIVE catalogue and will look "compatible" until banned. | Resolved in Phase 5: bans/policies evaluated via `/security/evaluate`. |
| K26 | Medium | Without VirusTotal credentials, digests not on the internal pin/deny lists yield INDETERMINATE and block (fail closed). Local demo packages are auto-pinned only when `APP_ENV != production`. | Set `THREAT_INTEL_API_KEY` for live VT, or pin digests via `THREAT_INTEL_PINNED_DIGESTS`. |
| K27 | Info | Policy evaluation records a `security_checks` row per call; no TTL short-circuit cache read yet (TTL stored for Phase 7/8 freshness). | Cache lookup before provider call in Phase 7 if rate limits bite. |
| K28 | Low | SUSPICIOUS threat verdict routes to SECURITY_REVIEW (never auto-approve). No security-review UI yet. | Surface review queue in Phase 7/10. |
| K29 | Info | Live Gemini needs a current model id; `gemini-2.0-flash` returns 404. Schema must use Gemini responseSchema form (no `additionalProperties` / union `type` arrays). | Resolved for Phase 6: `gemini-3.5-flash-lite` + Gemini responseSchema; key via `x-goog-api-key`. |
| K30 | Info | Preview remains non-persistent; real requests use `/software/requests`. | Phase 7: submit/list/cancel + admin approval queue; install still Phase 8. |
| K31 | Info | Outlook approval email is outbox-only when Graph is not configured (`NOT_CONFIGURED`). | Set Entra + `GRAPH_SENDER` for live send; web approval works without it. |
| K32 | Info | Phase 8 install path fails closed with `PRIVILEGED_SERVICE_UNAVAILABLE` until the LaunchDaemon is installed (decision D2). | Resolved 2026-11-17: D2 approved; daemon installed (`com.sentineldesk.privileged`). |
| K33 | Low | Catalogue `github-cli` package receipt id is seeded as `github.cli`; confirm against `pkgutil --pkg-info` after first approved install. | Resolved: real receipt is `com.github.cli` (install succeeded; first job reported FAILED_VERIFICATION). |
| K16 | Info | Vite dev server binds 127.0.0.1 but cookies/CSRF/Entra redirect use `http://localhost:5173`. Open the app at `localhost`, not `127.0.0.1`, or the Origin check rejects sign-in. Hit during owner validation. | Fixed: dev server now redirects `127.0.0.1:5173` → `localhost:5173` (307). |

## Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | Only macOS x86_64 is physically testable | Windows/Linux adapters return `PLATFORM_ADAPTER_NOT_AVAILABLE`; report build status only |
| R2 | VS Code already installed (1.138.0) | Use it to demonstrate `ALREADY_INSTALLED`; use GitHub CLI pkg for the real install |
| R3 | Entra/Graph need tenant admin consent on a corporate tenant | Keep web approval primary; mark live tests BLOCKED until credentials exist |
| R4 | Sandbox/network allowlist may block Gemini endpoint | Run live Gemini tests with explicit network permission |
| R5 | Corporate EDR (CrowdStrike) may flag the privileged LaunchDaemon | Owner approval and IT check before Phase 8 install |
| R6 | Spec schema lacks sessions, enrollment tokens, aliases, security checks tables | Resolved in Phase 2: added as documented extensions (migration 0002) |
