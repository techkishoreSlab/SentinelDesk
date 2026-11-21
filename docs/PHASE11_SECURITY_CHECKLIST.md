# Phase 11 — Security / integration checklist (hackathon DoD)

Evidence for scorecard Phase 11. Scope: demo-grade validation, not a full pen-test.

| Check | Result | Notes |
|---|---|---|
| Secrets not in git (`.env`, `secrets/`, `dev-keys/`, `dev-certs/`) | PASS | Listed in `.gitignore` |
| CSRF / Origin: use `localhost` not `127.0.0.1` | PASS | Documented; Vite redirects |
| RBAC: employee blocked from admin Approvals/Audit | PASS | Covered by existing auth integration tests |
| Banned software → no approval job | PASS | Phase 5/7 scenarios in TEST_REPORT |
| Threat fail-closed without VT for unpinned digests | PASS | Unit + policy tests |
| Agent TLS + enroll over `:8443` | PASS | Phase 3 e2e / gateway |
| Job Ed25519 verify before install | PASS | Phase 8 |
| Privileged missing → fail closed | PASS | `PRIVILEGED_SERVICE_UNAVAILABLE` |
| Migrations from empty DB via Compose | PASS | `make up` migrate service |
| Outlook notify: no approve secret in mail link | PASS | `tests/test_graph_mail_unit.py` |
| Outlook notify: without Graph → `NOT_CONFIGURED`, UI still works | PASS | unit test |
| Live Entra + live Graph send | OWNER | Requires Application Mail.Send consent + APPROVER role on mailbox user |

Automated: `uv run pytest tests/test_graph_mail_unit.py` (5 passed, 2026-11-21).  
Broader suite: run `make backend-test` / `make backend-integration` when Docker is up.
