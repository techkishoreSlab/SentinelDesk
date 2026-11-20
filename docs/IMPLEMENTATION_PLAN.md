# SentinelDesk — Phase 0 Assessment and Implementation Plan

Source of truth: `MASTER_PRODUCT_SPEC.md` v1.0 (2132 lines, SHA-256 `5d1112a4…c065`).
Assessment date: 2026-11-16.

## 1. Repository assessment

The workspace was empty (no code, no git history). Phase 0 added only: the spec copy,
`.gitignore`, git init, and the `docs/` tracking files. No application code exists yet.

## 2. Host assessment (actually detected)

| Item | Detected | Impact |
|---|---|---|
| OS | macOS 26.5 (build 25F71), Darwin 25.5.0 | macOS is the only physically testable OS |
| CPU | Intel Core i7-9750H, x86_64, 12 logical CPUs | Catalogue entry must target `x86_64` (universal pkg OK) |
| RAM / disk | 16 GiB / 71 GiB free | Sufficient |
| Python | 3.10.11 (python.org), 3.14 (Homebrew) | Backend runtime pinned to 3.12 in Docker; host dev via `uv` |
| Node / npm | 24.13.0 / 11.6.2 | OK for React + Vite |
| Rust | **not installed** | Must install `rustup` before Phase 1 gate |
| Docker | Docker Desktop 29.4.3, Compose v5.1.3; **daemon not running** | Must be started before Phase 1 gate |
| PostgreSQL | not on host | Run in Docker (postgres 17) |
| Xcode | Xcode.app present | `codesign`, `pkgutil`, `installer`, `spctl`, `security` available |
| Security software | CrowdStrike Falcon, FortiClient present | Machine appears corporate-managed; LaunchDaemon install may be flagged |
| Pre-installed apps relevant to demo | Visual Studio Code 1.138.0, Apple Git (CLT), AnyDesk | VS Code demo would resolve to `ALREADY_INSTALLED` |

## 3. Real-install candidate (unverified until Phase 8)

GitHub CLI `gh_2.104.0_macOS_universal.pkg` (28,841,135 bytes) published with a
checksum file on the official `cli/cli` releases. `gh` is not installed on the host.
Signature/notarization will be verified with `pkgutil --check-signature` and
`spctl --assess --type install` before it is admitted to the catalogue. If it fails,
an alternative signed pkg will be proposed — nothing is installed without approval.

## 4. Phase sequence

Follows the 12-phase execution prompt. Proposed adjustment (pending approval):
swap Phase 5 (AI orchestration) and Phase 6 (policy engine) to match spec §18,
so the orchestrator's tools call a real policy engine instead of placeholders.

## 5. Requirement traceability (high level)

| Spec section | Delivered in phase |
|---|---|
| §3 architecture, §4 stack, §20 env | 1 |
| §2 RBAC, §5 schema, §13 identity, §15.4 audit chain | 2 |
| §9.8 endpoint model, §11.1–11.2 lifecycle/inventory, §12.3 | 3 |
| §8 catalogue/compatibility, §19 seed data | 4 |
| §7 Gemini contract, agent loop | 5 (or 6 if swapped) |
| §9 policy, banned, threat intel, fail-closed | 6 (or 5 if swapped) |
| §10 approvals + Outlook | 7 |
| §9.9 signed jobs, §11.3–11.7 install/verify | 8 |
| §11.7, §15 recovery/observability | 9 |
| §14 frontend | 10 |
| §17 tests | 11 (plus per-phase tests) |
| §17.5, §26 acceptance | 12 |
