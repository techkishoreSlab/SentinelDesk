# MASTER_PRODUCT_SPEC.md

# SentinelDesk --- AI-Assisted Enterprise Software Provisioning

**Document type:** Global source of truth for product design,
implementation, testing and delivery\
**Version:** 1.0\
**Status:** Approved baseline\
**Hackathon constraint:** 48 hours, one developer\
**Primary objective:** Deliver a secure, demonstrable, genuinely
functioning cross-platform software-request and provisioning
system---not a mock-up.

------------------------------------------------------------------------

## 0. Executive directive

Build **SentinelDesk**, an enterprise software provisioning platform. An
employee asks in natural language for software. SentinelDesk identifies
the device, checks organisational policy and the approved software
catalogue, selects a compatible package/version, obtains the required
approval, dispatches a signed and constrained installation job to the
endpoint, performs the installation, verifies the result, and records an
auditable outcome.

The product has two cooperating agents:

1.  **Cloud/orchestration agent:** a backend workflow that uses Gemini
    to interpret intent and explain recommendations. It is not trusted
    to authorize or execute privileged operations.
2.  **Endpoint agent:** a Rust user-mode component plus a privileged
    local service. It gathers device facts and performs only narrowly
    defined, locally validated actions.

The product must support Windows, macOS and Linux by architecture and
package-adapter design. The 48-hour deliverable must prove real
installation on the developer's available host OS and provide buildable,
testable platform adapters for the other operating systems. Do not claim
that all three operating systems have been physically validated unless
each has actually been tested on a real machine or CI runner.

### 0.1 Non-negotiable principles

-   Security decisions are deterministic, server-side and independently
    revalidated by the endpoint.
-   Gemini is an untrusted intent interpreter and explanation engine,
    never a policy authority.
-   Never execute model-generated shell commands, scripts, URLs, package
    names or arbitrary arguments.
-   The endpoint accepts only typed, allowlisted job instructions.
-   Default-deny: unknown software, unknown package source, failed
    mandatory verification, expired approval, invalid signature, stale
    policy, or unavailable mandatory threat check means **no
    installation**.
-   No silent privilege escalation. Privileged operations are isolated
    in a service with a tiny command surface.
-   No secrets in source control, logs, prompts, browser storage or
    endpoint-readable configuration.
-   Every state transition is authenticated, authorized, timestamped and
    auditable.
-   Fail safely and explain the block; do not weaken controls to make a
    demo pass.
-   Build the smallest complete vertical slice first. Avoid premature
    microservices.

### 0.2 Product promise

For a request such as "Install Visual Studio Code":

1.  Authenticate the employee.
2.  Identify the selected enrolled device.
3.  Collect and validate OS, architecture, version, memory, disk and
    installed-software facts.
4.  Search the internal catalogue and configured external catalogue
    connectors.
5.  Reject banned software before approval routing.
6.  Select only an explicitly approved compatible package and version.
7.  Show the user the software, publisher, version, source, permissions
    and reason for selection.
8.  Apply the approval policy.
9.  Obtain approval through the web dashboard and/or Outlook action
    link.
10. Dispatch a short-lived, signed, idempotent job to the intended
    endpoint.
11. Revalidate the job, package and policy on the endpoint.
12. Install through a platform-specific package adapter.
13. Verify installed state and version.
14. Report success/failure and preserve the audit trail.

------------------------------------------------------------------------

## 1. Scope and delivery contract

### 1.1 48-hour solo-developer MVP --- must ship

The MVP is one deployable backend, one web app, one Rust endpoint
executable/service, one database, and a background worker process. They
may be deployed together for the hackathon.

**Must-have working capabilities:**

-   Employee login using local development authentication; Entra ID
    integration implemented behind an identity-provider interface if
    credentials/tenant are available.
-   Admin login and role-based authorization.
-   Device enrollment with one-time enrollment token.
-   Endpoint heartbeat and device inventory.
-   Natural-language software request.
-   Gemini intent extraction through a strict JSON schema; deterministic
    fallback parser for the demo if Gemini is unavailable.
-   Internal software catalogue with version, OS, architecture,
    publisher, package source, hash, signature expectations, approval
    policy and security status.
-   Banned-software list checked before approval routing.
-   Compatibility and policy evaluation.
-   Approval queue in the web app.
-   Outlook notification adapter behind an interface; if Microsoft Graph
    credentials are supplied, send real mail. Otherwise clearly show
    "email adapter not configured" and keep web approval fully
    functional.
-   Endpoint polling or authenticated WebSocket job delivery. Prefer
    polling for MVP reliability.
-   Real installation of at least one safe, catalogue-approved
    application on the host OS using a pinned, verified package and an
    explicit adapter.
-   Installation verification.
-   Audit log and installation history.
-   Input, action and output guardrails.
-   Tests for policy decisions, approval, job validation, banned
    software and duplicate requests.
-   Docker-based local backend startup and documented endpoint build/run
    instructions.

**MVP must not:**

-   Install arbitrary software from arbitrary URLs.
-   Execute shell commands produced by Gemini.
-   Allow the model to add catalogue entries, change policy, approve
    requests or grant privileges.
-   Provide remote shell, arbitrary file transfer or remote desktop.
-   Run with unrestricted administrator/root privileges.
-   Claim full enterprise readiness, zero bugs or certification.
-   Claim real cross-platform validation where no test host exists.

### 1.2 Explicitly deferred

-   Full Intune/Jamf/SCCM/MDM write integration.
-   Multi-region high availability and large-scale fleet management.
-   Automatic software discovery from the public internet.
-   Autonomous malware remediation or endpoint detection and response.
-   Arbitrary application uninstall, driver/firmware updates, OS
    upgrades.
-   General-purpose remote command execution.
-   Complex dependency resolution and package composition.
-   Self-updating privileged agent.
-   Offline installation authorization.
-   Production Entra multi-tenant consent and full enterprise
    conditional-access configuration.
-   Automated rollback for packages that do not support safe rollback.

These are extension points, not hidden promises.

------------------------------------------------------------------------

## 2. User roles and permissions

Use RBAC with server-side enforcement on every protected API and every
job transition.

  -----------------------------------------------------------------------
  Role                    Allowed actions         Explicitly not allowed
  ----------------------- ----------------------- -----------------------
  Employee                Create request, view    Approve own request,
                          own requests, select    edit catalogue/policy,
                          own enrolled device,    dispatch arbitrary
                          cancel eligible pending actions
                          request                 

  Approver                Approve/reject requests Change security
                          assigned by policy,     verdict, alter package
                          view necessary request  hash, approve banned
                          evidence                software

  Software administrator  Manage catalogue        Override hard-block
                          entries, package        malware/banned verdict
                          metadata, compatibility without a separately
                          and lifecycle           defined break-glass
                                                  process

  Security administrator  Manage banned list,     Directly execute
                          threat policy, trusted  endpoint commands
                          publishers and security 
                          integrations            

  Auditor                 Read audit records and  Mutate requests,
                          reports                 approvals, policies or
                                                  installations

  Platform administrator  Manage identity         Bypass endpoint-side
                          settings, endpoint      validation
                          enrollment policy and   
                          system configuration    
  -----------------------------------------------------------------------

A user may hold multiple roles. Role assignment is an administrative
operation and must itself be audited. Never trust a role supplied by the
frontend.

### 2.1 Approval separation

-   Requester cannot approve their own request.
-   Approver identity must be authenticated and mapped to an authorized
    role.
-   Approval is bound to the exact request, device, catalogue item,
    version, package digest, policy revision and expiry.
-   Any change to those values invalidates the approval and requires a
    new decision.
-   Approval is not equivalent to authorization: the policy engine and
    endpoint still validate the job.

------------------------------------------------------------------------

## 3. System architecture

### 3.1 Logical architecture

``` mermaid
flowchart TB
    U[Employee / Admin Browser] --> WEB[React + TypeScript Web App]
    WEB --> API[FastAPI Application]
    API --> AUTH[Identity + RBAC]
    API --> ORCH[Request Orchestrator]
    ORCH --> GEM[Gemini Intent / Explanation Adapter]
    ORCH --> POLICY[Deterministic Policy Engine]
    POLICY --> CAT[Catalogue + Compatibility]
    POLICY --> THREAT[Threat Intelligence Adapter]
    ORCH --> APPROVAL[Approval Engine]
    APPROVAL --> MAIL[Microsoft Graph Outlook Adapter]
    ORCH --> DB[(PostgreSQL)]
    API --> AUDIT[Append-only Audit Events]
    API <--> EP[Authenticated Endpoint API]
    EP <--> USER[User-mode Rust Agent]
    USER <--> PRIV[Privileged Local Service]
    PRIV --> ADAPTER[Typed Package Adapters]
    ADAPTER --> OS[Windows / macOS / Linux]
```

### 3.2 Component responsibilities

**Web application** - Collects user intent and selected device. -
Displays catalogue results, request state, approval evidence and
installation status. - Provides admin catalogue, policy and approval
screens. - Never contains privileged credentials or package-signing
secrets. - Treats all API responses and user-generated text as
untrusted.

**FastAPI backend** - Authentication, authorization, validation and rate
limiting. - Request orchestration and state machine. - Deterministic
catalogue, compatibility and policy evaluation. - Approval workflow and
notification dispatch. - Endpoint enrollment, job issuance, heartbeat
and result ingestion. - Audit event creation. - Does not run endpoint
installation commands.

**Gemini adapter** - Converts natural language into a constrained
software-intent object. - Can suggest clarification questions and
produce human-readable explanations. - Must not return executable
commands or authoritative security decisions. - Strict schema
validation, output length limits, timeout, retry limits and
prompt-injection resistance. - If unavailable or invalid, fail closed
for ambiguous requests; use only a safe deterministic parser for
explicitly supported demo intents.

**Endpoint user agent** - Runs as the logged-in user. - Shows
device/connection status and installation progress. - Collects
non-sensitive device facts required for compatibility. - Communicates
with backend over TLS. - Does not have administrator privileges. - Does
not execute installation itself.

**Privileged local service** - Runs as a dedicated service identity with
only required OS permissions. - Accepts a small typed protocol from the
user agent/backend job handler. - Revalidates job signature, expiry,
nonce, target device, package digest, allowed installer type and policy
claims. - Uses fixed package-manager/installer adapters. - Never accepts
arbitrary command strings, executable paths, environment variables or
shell fragments from the network. - Records local execution evidence and
returns structured results.

### 3.3 Deployment topology for the hackathon

Use a modular monolith rather than microservices:

-   `backend`: FastAPI API.
-   `worker`: same Python package, separate process for email/outbox and
    job housekeeping.
-   `web`: React static build served by a web server or development
    server.
-   `postgres`: PostgreSQL.
-   `endpoint`: Rust binary/service built for the host OS.

Use Docker Compose for backend, worker and PostgreSQL. Endpoint agent
runs on the host, not inside the backend container, because it must
install software on the actual host machine.

### 3.4 Suggested repository structure

``` text
sentineldesk/
├── README.md
├── MASTER_PRODUCT_SPEC.md
├── .env.example
├── .gitignore
├── compose.yaml
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── API_CONTRACTS.md
│   ├── DEMO_RUNBOOK.md
│   └── SECURITY_OPERATIONS.md
├── backend/
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── migrations/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/          # config, logging, security, errors
│   │   ├── api/v1/
│   │   ├── auth/
│   │   ├── users/
│   │   ├── devices/
│   │   ├── catalogue/
│   │   ├── requests/
│   │   ├── policy/
│   │   ├── approvals/
│   │   ├── jobs/
│   │   ├── audit/
│   │   ├── notifications/
│   │   ├── integrations/
│   │   ├── ai/
│   │   ├── db/
│   │   └── schemas/
│   └── tests/
├── web/
│   ├── package.json
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   │   ├── requests/
│   │   │   ├── devices/
│   │   │   ├── catalogue/
│   │   │   ├── approvals/
│   │   │   ├── security/
│   │   │   └── audit/
│   │   ├── lib/
│   │   └── types/
│   └── tests/
├── endpoint/
│   ├── Cargo.toml
│   ├── crates/
│   │   ├── agent-core/
│   │   ├── agent-user/
│   │   ├── privileged-service/
│   │   ├── protocol/
│   │   └── platform-adapters/
│   └── tests/
├── catalogue/
│   └── seed/
└── scripts/
    ├── dev-up.sh
    ├── dev-down.sh
    └── seed-demo-data.py
```

Do not create empty modules just to match this tree. Add a module when
its responsibility is implemented.

------------------------------------------------------------------------

## 4. Technology decisions

  -----------------------------------------------------------------------
  Layer                   Choice                  Rules
  ----------------------- ----------------------- -----------------------
  Endpoint                Rust stable             Pin toolchain; use safe
                                                  Rust; minimize unsafe
                                                  blocks

  Backend                 Python + FastAPI        Pydantic validation,
                                                  SQLAlchemy 2, Alembic

  Database                PostgreSQL              Migrations; foreign
                                                  keys; constraints;
                                                  transactions

  Frontend                React + TypeScript      Strict TypeScript;
                                                  typed API client

  AI                      Gemini API              Server-side only;
                                                  strict structured
                                                  output

  Identity                Local dev auth + Entra  Never store Microsoft
                          ID adapter              passwords

  Email                   Microsoft Graph adapter OAuth scopes least
                                                  privilege

  Endpoint transport      HTTPS polling for MVP   Device-bound
                                                  credentials;
                                                  short-lived jobs

  Packaging               OS-specific adapters    No arbitrary package
                                                  URL or command

  Testing                 pytest, Vitest/RTL,     CI-friendly and
                          Rust tests, Playwright  deterministic
                          where feasible          
  -----------------------------------------------------------------------

### 4.1 Dependency policy

-   Use current stable versions at implementation time, then pin exact
    versions in lockfiles.
-   Commit `Cargo.lock`, Python lockfile and frontend lockfile.
-   Avoid unnecessary dependencies and abandoned packages.
-   Check license, maintenance status, known vulnerabilities and
    transitive dependencies before adding a dependency.
-   Do not use wildcard dependency versions in production manifests.
-   Run dependency and secret scanning before demo.
-   Do not copy unknown scripts from the internet into privileged code.

------------------------------------------------------------------------

## 5. Core domain model and database

Use UUID primary keys. Store timestamps in UTC (`timestamptz`). Use
explicit enums or constrained strings. Use foreign keys and indexes.
Apply migrations; do not rely on automatic table creation in production.

### 5.1 Tables

**users** - `id`, `email` (unique, normalized), `display_name`,
`identity_provider`, `external_subject` (nullable unique per provider),
`is_active`, `created_at`, `updated_at`.

**roles** - `id`, `name` (unique), `description`.

**user_roles** - `user_id`, `role_id`, `assigned_by`, `created_at`;
composite unique key.

**devices** - `id`, `owner_user_id`, `device_name`, `os_family`,
`os_version`, `architecture`, `agent_version`, `device_status`,
`last_seen_at`, `enrolled_at`, `policy_version`, `created_at`,
`updated_at`.

**device_credentials** - `id`, `device_id`, `credential_hash`,
`created_at`, `expires_at`, `revoked_at`, `last_used_at`. - Store only a
hash of device credentials. Never store raw enrollment or device tokens.

**device_facts** - `id`, `device_id`, `collected_at`, `cpu_arch`,
`cpu_cores`, `memory_total_bytes`, `disk_free_bytes`, `os_build`,
`installed_software_summary` (bounded JSON). - Do not collect unrelated
personal files, browser history, keystrokes, screenshots or user
content.

**catalogue_software** - `id`, `slug` (unique), `display_name`,
`description`, `publisher`, `category`, `lifecycle_status`,
`risk_level`, `created_at`, `updated_at`.

**catalogue_versions** - `id`, `software_id`, `version`, `os_family`,
`architecture`, `minimum_os_version`, `minimum_memory_bytes`,
`minimum_disk_bytes`, `installer_type`, `source_type`,
`source_reference`, `sha256`, `signature_publisher`,
`signature_required`, `package_size_bytes`, `release_status`,
`created_at`. - Unique compatibility key across
software/version/OS/architecture as appropriate. - `source_reference`
must refer to a trusted configured source, not a user-provided URL.

**software_policies** - `id`, `software_id` or `slug`, `decision`
(`ALLOW`, `REQUIRE_APPROVAL`, `BLOCK`), `auto_approve_eligible`,
`policy_revision`, `reason`, `effective_from`, `effective_to`,
`created_by`.

**banned_software** - `id`, `match_type` (`CATALOGUE_ID`, `PUBLISHER`,
`PACKAGE_ID`, `HASH`, `SIGNING_ID`), `match_value` (normalized),
`reason_code`, `public_message`, `severity`, `active`, `created_by`,
`created_at`. - Banned rules must be evaluated before any approval
notification is generated.

**software_requests** - `id`, `requester_id`, `device_id`, `raw_request`
(length-limited), `normalized_intent` JSON, `software_id`,
`catalogue_version_id`, `status`, `decision_reason`, `policy_revision`,
`idempotency_key`, `created_at`, `updated_at`, `expires_at`. - Do not
store unnecessary sensitive text. Redact secrets if detected.

**approvals** - `id`, `request_id`, `approver_id`, `decision`,
`comment`, `approval_binding_hash`, `created_at`, `expires_at`,
`channel`. - Unique constraint prevents duplicate decisions by same
approver where applicable.

**installation_jobs** - `id`, `request_id`, `device_id`,
`catalogue_version_id`, `status`, `job_nonce`, `job_payload_hash`,
`issued_at`, `expires_at`, `claimed_at`, `completed_at`,
`attempt_count`, `result_code`, `result_summary`. - Unique request/job
relation for idempotency.

**installation_results** - `id`, `job_id`, `device_id`, `started_at`,
`finished_at`, `exit_code`, `installed_version`, `verification_status`,
`result_details` JSON (bounded and sanitized).

**notifications** - `id`, `request_id`, `recipient_id`, `channel`,
`status`, `provider_message_id`, `attempt_count`, `last_error_code`,
`created_at`, `sent_at`.

**audit_events** - `id`, `occurred_at`, `actor_type`, `actor_id`,
`action`, `resource_type`, `resource_id`, `correlation_id`, `source_ip`
(where lawful/needed), `result`, `reason_code`, `metadata` JSON
(allowlisted fields only), `previous_hash`, `event_hash`. - Append-only
to application roles. Hash chaining is tamper-evidence, not a substitute
for protected backups or external log storage.

**integration_configs** - Store non-secret configuration and secret
references only. Actual secrets live in environment/secret manager.

### 5.2 Indexes and constraints

-   Unique normalized user email.
-   Unique device credential hash and device enrollment identity.
-   Index device owner/status/last_seen.
-   Index catalogue slug, release status, OS and architecture.
-   Index active banned rules by match type/value.
-   Index request requester/status/created_at.
-   Index approvals request/status/expiry.
-   Index jobs device/status/expiry.
-   Index audit resource/time and correlation ID.
-   Foreign keys with deliberate delete behavior. Prefer soft
    deactivation over cascading deletion for audit-critical entities.
-   Check constraints for valid status and non-negative sizes/attempt
    counts.
-   Use transactions for approval + job creation and state changes.

### 5.3 Data retention

Define retention by data category and organisational law/policy. Default
demo data should be synthetic. Minimize device facts. Provide a
documented deletion/anonymization process for personal data while
preserving legally required audit evidence.

------------------------------------------------------------------------

## 6. Request and installation state machine

All transitions must be explicit and validated in backend service code.
The frontend cannot set status directly.

``` mermaid
stateDiagram-v2
    [*] --> RECEIVED
    RECEIVED --> UNDERSTANDING
    UNDERSTANDING --> NEEDS_CLARIFICATION
    NEEDS_CLARIFICATION --> RECEIVED
    UNDERSTANDING --> POLICY_CHECK
    POLICY_CHECK --> BLOCKED
    POLICY_CHECK --> INCOMPATIBLE
    POLICY_CHECK --> SECURITY_REVIEW
    SECURITY_REVIEW --> BLOCKED
    SECURITY_REVIEW --> AWAITING_APPROVAL
    SECURITY_REVIEW --> AUTO_APPROVED
    AWAITING_APPROVAL --> REJECTED
    AWAITING_APPROVAL --> EXPIRED
    AWAITING_APPROVAL --> APPROVED
    AUTO_APPROVED --> READY_TO_INSTALL
    APPROVED --> READY_TO_INSTALL
    READY_TO_INSTALL --> QUEUED
    QUEUED --> DISPATCHED
    DISPATCHED --> RUNNING
    RUNNING --> VERIFYING
    VERIFYING --> SUCCEEDED
    VERIFYING --> FAILED
    QUEUED --> CANCELLED
    DISPATCHED --> EXPIRED
    RUNNING --> FAILED
```

Additional states may include `DEVICE_OFFLINE`, `CANCEL_REQUESTED`,
`REQUIRES_ADMIN_REMEDIATION`. Define transitions and terminal-state
behavior in code and tests.

### 6.1 State invariants

-   `BLOCKED` and `INCOMPATIBLE` never create an approval notification
    or install job.
-   A banned match is terminal `BLOCKED` unless an authorized security
    policy change removes the ban and a new request is submitted.
-   `AUTO_APPROVED` is permitted only when a deterministic policy says
    so and all mandatory security checks passed.
-   Approval is valid only for the exact immutable request binding.
-   Only an approved request may create a job.
-   Only the target enrolled device may claim its job.
-   Expired jobs cannot start.
-   Duplicate requests with the same idempotency key return the existing
    request.
-   A completed job cannot be run again.
-   Endpoint-reported success is not final until backend verification
    requirements are satisfied.

------------------------------------------------------------------------

## 7. AI orchestration and Gemini contract

### 7.1 AI is not the authority

Gemini may: - Extract software name, edition, version preference and
user intent. - Identify ambiguity and ask for clarification. - Summarize
catalogue matches supplied by backend. - Explain a deterministic
compatibility/policy decision in plain language.

Gemini may not: - Add or modify catalogue records. - Decide whether
software is banned. - Change policy or risk classification. - Approve a
request. - Create or sign installation jobs. - Choose an arbitrary
download URL. - Generate shell commands, scripts, PowerShell,
AppleScript, SQL or executable code for endpoint use. - Read secrets or
endpoint credentials. - Override a failed security check.

### 7.2 Structured intent schema

Example only; validate with Pydantic and reject unknown fields:

``` json
{
  "intent": "INSTALL_SOFTWARE",
  "software_query": "Visual Studio Code",
  "edition": null,
  "requested_version": "stable",
  "platform_preference": null,
  "clarification_required": false,
  "clarification_question": null,
  "confidence": 0.98
}
```

Rules: - `intent` is an enum. - `software_query` maximum 120
characters. - `requested_version` maximum 40 characters. - `confidence`
is advisory only and never controls security. - Reject extra fields. -
No URLs, commands, scripts or free-form action fields. - Normalize
software identity by matching only known catalogue aliases. - If no
unambiguous catalogue match exists, ask a clarification question or
return not found; do not guess.

### 7.3 Prompt-injection resistance

The user request, catalogue descriptions, package metadata and external
threat-intelligence text are untrusted data. They must never be treated
as system instructions.

-   Keep system instructions server-side.
-   Pass only the minimum relevant catalogue candidates to Gemini.
-   Delimit user text as data.
-   Do not pass secrets, tokens, private device data or full audit
    records to Gemini.
-   Do not let model output select tools or invoke arbitrary
    integrations.
-   Validate output against a strict schema.
-   Apply length/time/token limits.
-   Treat malformed, refused, low-confidence or unavailable responses as
    a controlled error.
-   Log model version, request correlation ID and schema-validation
    outcome, not secret prompt material.

### 7.4 AI failure behavior

-   Gemini timeout: use a deterministic exact alias lookup only;
    otherwise ask the user to clarify.
-   Invalid JSON/schema: reject and retry at most once with a
    constrained repair request; if still invalid, stop.
-   Prompt injection detected: ignore malicious instruction and continue
    only if the literal software intent can be safely extracted;
    otherwise block/clarify.
-   Model says software is safe: ignore as a security verdict.
-   Model recommends a version not in catalogue: ignore and explain only
    available catalogue versions.
-   Model unavailable: core catalogue, policy, approval and installation
    flow remains usable for exact supported requests.

------------------------------------------------------------------------

## 8. Catalogue and compatibility engine

### 8.1 Catalogue as source of truth

The internal catalogue controls what the organisation permits. External
catalogues/MDM connectors may enrich metadata or synchronize approved
records, but cannot silently make a package installable.

Each installable package record must specify: - Canonical software
identity and aliases. - Exact version. - Supported OS family and CPU
architecture. - Minimum OS version/build. - Minimum RAM and free disk
requirements where relevant. - Package type and trusted source
identifier. - SHA-256 digest. - Expected publisher/signing identity. -
Signature verification requirement. - Release channel and lifecycle
state. - Approval policy and security classification. - Verification
method after installation.

No package is installable if any mandatory field is missing.

### 8.2 Compatibility decision

Evaluate in this order:

1.  Device is enrolled, active and recently seen.
2.  OS family supported.
3.  CPU architecture supported.
4.  OS version/build meets minimum.
5.  Memory and disk requirements met.
6.  Package is active and approved for the target platform.
7.  Installed version/state is checked to avoid unnecessary reinstall.
8.  Package source and signature metadata are valid.
9.  Security checks pass.
10. Approval policy is evaluated.

Return structured reasons such as: - `DEVICE_NOT_ENROLLED` -
`DEVICE_STALE` - `OS_UNSUPPORTED` - `ARCH_UNSUPPORTED` -
`OS_VERSION_TOO_OLD` - `INSUFFICIENT_DISK` - `PACKAGE_NOT_APPROVED` -
`PACKAGE_METADATA_INCOMPLETE` - `ALREADY_INSTALLED` -
`SECURITY_CHECK_UNAVAILABLE`

Never recommend "latest" from the public internet. "Latest" means latest
active, approved catalogue version compatible with the device.

### 8.3 External catalogue integrations

Define a connector interface, not a hard dependency:

``` python
class CatalogueConnector(Protocol):
    async def search(self, query: str, platform: str) -> list[ExternalSoftwareRecord]: ...
    async def get_package_metadata(self, external_id: str) -> ExternalPackageMetadata: ...
```

Imported records enter `PENDING_REVIEW`. An administrator must validate
publisher, source, hash/signature, platform and policy before
activation. Never auto-import and auto-install.

------------------------------------------------------------------------

## 9. Security policy engine and guardrails

### 9.1 Decision order

The deterministic policy engine evaluates: 1. Authentication and
requester authorization. 2. Device ownership/authorization. 3. Request
schema and abuse controls. 4. Exact catalogue identity. 5. Banned
software matches. 6. Package trust and provenance. 7.
Threat-intelligence result. 8. Compatibility. 9. Organisational
allow/approval policy. 10. Approval requirement. 11. Job issuance
eligibility.

A hard block takes precedence over every approval path. A manager cannot
approve a banned or malware-positive package through ordinary approval.

### 9.2 Banned software behavior

When a request matches an active banned rule: - Set request status to
`BLOCKED`. - Do not create an approval task. - Do not send an Outlook
notification to an approver. - Do not create or dispatch an installation
job. - Show the employee a safe explanation, e.g. "This software is
blocked by your organisation's security policy. No installation was
attempted." - Record the policy rule ID and reason code in audit logs. -
Avoid exposing sensitive detection intelligence or exact bypass criteria
to the employee. - Alert security operations only if a separate security
policy explicitly requires it; this is not an approval notification.

Match on canonical catalogue ID, known package ID, publisher/signing
identity and known malicious hashes. Fuzzy name similarity may trigger
review but must not alone create a definitive malware accusation.

### 9.3 Input guardrails

-   Pydantic schema validation and strict field allowlists.
-   Max request length and rate limits.
-   Unicode normalization and control-character handling.
-   Reject path traversal, command fragments and suspicious URL fields
    where not expected.
-   Validate device IDs against the authenticated user's authorization.
-   Do not accept package URLs or installer paths from employees.
-   Sanitize rendered text to prevent XSS.
-   CSRF protection if cookie-based sessions are used.
-   Content Security Policy and secure headers.
-   File uploads are out of MVP scope; if later added, isolate, scan,
    size-limit and validate content.

### 9.4 Action guardrails

-   Only actions represented by a closed enum/protocol are accepted.
-   Endpoint package adapter uses a fixed executable and fixed argument
    template.
-   No shell invocation (`sh -c`, `bash -c`, `cmd /c`,
    `powershell -Command`) for server-supplied strings.
-   Package source is selected from trusted configuration/catalogue.
-   Verify SHA-256 before execution and verify publisher signature using
    native OS trust facilities where supported.
-   Recheck the package digest immediately before installation.
-   Restrict package file permissions and use a private temporary
    directory.
-   Reject symlinks/reparse-point tricks and unsafe destination paths.
-   Set timeout, output limits, CPU/memory limits where feasible.
-   Prevent concurrent conflicting installation jobs per device.
-   Use a job nonce and expiry; reject replay.
-   Require explicit target device binding.
-   Privileged service accepts only authenticated local IPC from the
    expected user agent/service identity.
-   The service has no generic "run command" method.
-   No arbitrary uninstall in MVP.
-   Do not weaken signature/hash verification to make demo packages
    work.

### 9.5 Output guardrails

-   Model and endpoint output are untrusted.
-   Sanitize error text before display.
-   Do not expose stack traces, secrets, internal paths, tokens,
    threat-provider raw responses or security bypass details.
-   Return stable public error codes and human-readable safe messages.
-   Limit output size and strip terminal control sequences.
-   Do not render model-generated HTML.
-   Separate factual result fields from AI-generated explanation.
-   Never report installation success without independent verification.

### 9.6 Fail-closed security checks

If a mandatory security source is unavailable, times out, returns
malformed data or cannot establish a trustworthy result: - Mark check as
`INDETERMINATE`. - Block installation. - Do not auto-approve. - Do not
dispatch a job. - Explain "Security verification is temporarily
unavailable; installation has been paused." - Record provider, check
type, timestamp and error code. - Permit retry after service recovery;
do not create an override button for ordinary admins.

### 9.7 Threat-intelligence design

Use a provider abstraction. Do not hard-code a specific commercial
provider.

``` python
class ThreatIntelProvider(Protocol):
    async def check_hash(self, sha256: str) -> ThreatVerdict: ...
```

Possible verdicts: `CLEAN`, `MALICIOUS`, `SUSPICIOUS`, `INDETERMINATE`.

-   `MALICIOUS`: hard block.
-   `SUSPICIOUS`: block or security review according to written policy;
    never auto-approve.
-   `INDETERMINATE`: fail closed if the check is mandatory.
-   `CLEAN`: continue to remaining controls; this is not proof that
    software is harmless.

Do not upload proprietary binaries to third-party scanners unless the
organisation explicitly authorizes it. Hash lookup is preferred. Cache
only according to provider terms and a short, documented TTL. Recheck at
install time if policy requires freshness.

### 9.8 Endpoint security model

**User-mode agent** - Runs as the logged-in user. - Stores device
credential using OS-protected credential storage where available. - Does
not store admin passwords. - Cannot write to privileged installation
directories. - Uses authenticated local IPC to privileged service.

**Privileged service** - Runs under a dedicated restricted service
identity where the OS supports it. - Exposes only typed install
operations. - Validates signed job envelope, device binding, expiry,
nonce, package digest, installer type and local policy. - Uses fixed
package-manager adapters. - Does not expose a network listener with
privileged methods. - Does not accept instructions directly from
Gemini. - Logs minimal structured execution metadata. - Uses secure file
ownership and permissions for binaries/configuration.

**Local IPC** - Windows: named pipe with ACL restricted to the service
and authorized local agent identity. - macOS: XPC or a Unix domain
socket protected by filesystem permissions and peer-credential checks. -
Linux: Unix domain socket with strict ownership/mode and peer-credential
checks. - Protocol messages must be versioned, length-bounded and
schema-validated.

### 9.9 Cryptographic controls

-   TLS 1.2+; prefer TLS 1.3.
-   Device-specific credentials, not a shared fleet secret.
-   Store credential hashes server-side; rotate and revoke credentials.
-   Use signed job envelopes with an asymmetric signing key held
    server-side.
-   Pin trusted signing public keys in the agent/service through a
    controlled release process.
-   Include `job_id`, `device_id`, `nonce`, `issued_at`, `expires_at`,
    `package_digest`, `catalogue_version_id`, `policy_revision` and
    `request_binding_hash` in the signed envelope.
-   Prevent replay with nonce persistence and one-time job claim.
-   Keep signing keys in a secret manager/KMS for production;
    environment variables only for local development.
-   Never embed Gemini API keys, Graph secrets or backend signing
    private keys in the desktop agent or web bundle.

### 9.10 Security incident handling

On suspected agent compromise, credential theft or signature mismatch: -
Revoke device credentials. - Mark device `QUARANTINED`. - Reject all
pending jobs for that device. - Preserve audit evidence. - Require
administrator re-enrollment after investigation. - Do not attempt
autonomous cleanup in MVP.

------------------------------------------------------------------------

## 10. Approval and Outlook workflow

### 10.1 Approval policy

Example policy classes:

  -----------------------------------------------------------------------
  Class                   Example                 Behavior
  ----------------------- ----------------------- -----------------------
  Approved standard       Known, low-risk         Auto-approve only if
                          catalogue application   policy explicitly
                                                  allows

  Controlled              Developer tools or      Admin approval
                          elevated-risk software  

  Restricted              Software needing        Block pending security
                          security review         review; not ordinary
                                                  approval

  Banned                  Known malicious or      Immediate block; no
                          prohibited software     approval notification

  Unknown                 Not in approved         No installation;
                          catalogue               catalogue review
                                                  workflow may be
                                                  requested separately
  -----------------------------------------------------------------------

"Auto-approval" is not a general AI decision. It is a deterministic
policy outcome for a pre-approved package/version/device class.

### 10.2 Approval binding

Approval must be cryptographically or transactionally bound to: -
Request ID. - Requester ID. - Device ID. - Canonical software ID. -
Exact version/package ID. - SHA-256 digest. - Policy revision. -
Expiry. - Approval-required reason.

Any change invalidates previous approval.

### 10.3 Web approval

-   Authenticated admin dashboard.
-   Show requester, device, software, version, publisher, package
    source, hash prefix, compatibility facts, security verdicts,
    requested reason and policy explanation.
-   Approve/reject with optional comment.
-   Require step-up authentication for sensitive actions where
    supported.
-   Prevent self-approval.
-   Use optimistic concurrency/version checks to prevent race
    conditions.
-   Record approver identity and timestamp.

### 10.4 Outlook notification

Use Microsoft Graph with least-privilege permissions. Keep OAuth
credentials on backend only.

Email must: - Contain a concise request summary and secure link to the
authenticated approval page. - Not contain a bearer token or reusable
approval secret in a query string. - Not permit approval solely by
opening an email. - Require the admin to authenticate and see the exact
request. - Expire when the request or approval expires. - Use an outbox
pattern so notification failure does not corrupt approval state. - Avoid
sending approval email for banned/malicious requests.

For a one-click experience, use a short-lived, single-use opaque token
only if security review approves the design; the safer MVP is a deep
link to the authenticated dashboard.

### 10.5 Race conditions

-   Only one terminal approval decision can win.
-   Use database transaction and row lock or compare-and-swap version.
-   If two admins decide concurrently, the second receives
    `ALREADY_DECIDED`.
-   If request changes or expires during review, reject the decision.
-   Approval notification retries must not create duplicate approval
    records.

------------------------------------------------------------------------

## 11. Endpoint agent and package installation

### 11.1 Agent lifecycle

1.  Install agent package using an administrator-controlled bootstrap.
2.  Enroll using a one-time token with short expiry.
3.  Exchange token for device-specific credential.
4.  Store credential using OS secure storage.
5.  Register device facts.
6.  Send periodic heartbeat.
7.  Poll for jobs using authenticated HTTPS.
8.  Validate and claim eligible job.
9.  Pass typed request to privileged service over local IPC.
10. Verify package and execute fixed adapter.
11. Verify installed software/version.
12. Report result.
13. Refresh policy and rotate credentials as required.

### 11.2 Device inventory

Collect only: - Device UUID generated for the agent installation. -
Hostname/device display name. - OS family, version and build. - CPU
architecture and core count. - Total memory and available disk space on
installation target. - Agent version and service health. - Installed
software identifiers needed to determine already-installed state.

Do not collect: - Personal documents. - Browser history. - Keystrokes. -
Screenshots. - Personal account passwords. - Arbitrary process command
lines. - Network packet contents.

### 11.3 Platform adapter interface

Use a closed typed interface:

``` rust
pub trait PackageInstaller {
    fn preflight(&self, package: &VerifiedPackage, device: &DeviceFacts)
        -> Result<PreflightResult, InstallError>;

    fn install(&self, package: &VerifiedPackage, job: &VerifiedJob)
        -> Result<InstallExecution, InstallError>;

    fn verify(&self, package: &VerifiedPackage)
        -> Result<VerificationResult, InstallError>;
}
```

The `VerifiedPackage` must only be constructible after catalogue, digest
and signature validation. Adapter methods must not accept arbitrary
shell strings.

### 11.4 Package adapter strategy

**Windows** - Prefer a managed package source such as an
organisation-controlled WinGet source or a vetted signed installer. -
Validate package identifier, exact version, source and installer
digest. - Verify Authenticode publisher/signature where applicable. -
Use a fixed adapter with fixed arguments. - Do not use user-supplied
`winget` package IDs or arbitrary URLs. - Account for per-user vs
machine-wide install scope. - Use Windows service ACLs and named-pipe
ACLs.

**macOS** - Support signed/notarized `.pkg` or approved `.dmg` workflows
with strict metadata. - Verify Developer ID signature/notarization where
applicable. - Use fixed `installer` adapter arguments. - Do not bypass
Gatekeeper or disable SIP. - Use LaunchDaemon for privileged service and
LaunchAgent only for user UI where needed. - Use XPC or protected IPC.

**Linux** - Prefer configured organisation repositories and signed
packages (`apt`, `dnf`, `zypper`, etc.) rather than arbitrary downloaded
`.deb`/`.rpm`. - Validate repository origin, package identity, exact
version and repository signature. - Run package manager with a
controlled environment and fixed argument templates. - Use systemd
service and Unix socket permissions. - Avoid `curl | bash`, arbitrary
PPA/repository addition or unsigned packages.

For the 48-hour MVP, implement one real host-OS adapter and make
unsupported OS adapters return `PLATFORM_ADAPTER_NOT_AVAILABLE` safely.
Do not fake a successful install.

### 11.5 Download and package handling

If a package must be downloaded: - Backend selects a
catalogue-controlled source. - Agent downloads over TLS to a private
temporary directory. - Enforce size limit and content-length limit. -
Verify SHA-256 and signature before install. - Use atomic file creation
and restrictive permissions. - Reject archive path traversal and symlink
entries if archives are unpacked. - Delete temporary package after
completion according to retention policy. - Never execute before
verification.

### 11.6 Installation verification

Success requires: - Installer reports success, and - OS/package database
or a trusted application metadata check confirms installed state, and -
Detected version matches requested catalogue version or allowed version
rule.

If installer exits 0 but verification fails, status is
`FAILED_VERIFICATION`, not success.

### 11.7 Retry and recovery

-   Network failure before job claim: retry with exponential backoff and
    jitter.
-   Job claim: atomic one-time claim.
-   Failure before installation starts: retry only if job remains valid
    and policy allows.
-   Failure during installation: do not blindly retry if package manager
    may be mid-transaction; inspect OS package state first.
-   Failure after install but before result upload: next heartbeat
    reconciles actual installed state and submits idempotent result.
-   Duplicate job: reject or return existing result.
-   Expired job: reject.
-   Endpoint offline: retain queued job until expiry; never extend
    approval silently.
-   Do not promise rollback. If package manager supports safe
    uninstall/rollback and policy explicitly allows it, implement as a
    separate reviewed operation.

------------------------------------------------------------------------

## 12. API contract

Prefix all routes with `/api/v1`. Use JSON. Validate request/response
schemas. Return a consistent error format. Use pagination for lists. Add
correlation IDs.

### 12.1 Employee and request endpoints

  Method   Endpoint                           Purpose
  -------- ---------------------------------- ---------------------------------
  GET      `/me`                              Current user and roles
  GET      `/devices`                         Devices visible to current user
  POST     `/software/requests`               Submit natural-language request
  GET      `/software/requests`               List own requests
  GET      `/software/requests/{id}`          Request detail/status
  POST     `/software/requests/{id}/cancel`   Cancel if state allows
  GET      `/catalogue/search?q=`             Search approved catalogue

Example request:

``` json
{
  "device_id": "uuid",
  "user_prompt": "Please install Visual Studio Code",
  "idempotency_key": "client-generated-unique-value"
}
```

### 12.2 Admin endpoints

  Method   Endpoint                           Purpose
  -------- ---------------------------------- ---------------------------
  GET      `/admin/approvals`                 Pending approvals
  POST     `/admin/approvals/{id}/decision`   Approve/reject
  GET      `/admin/catalogue/software`        List catalogue
  POST     `/admin/catalogue/software`        Create software record
  POST     `/admin/catalogue/versions`        Create package version
  PATCH    `/admin/catalogue/versions/{id}`   Update lifecycle/metadata
  GET      `/admin/security/banned`           List banned rules
  POST     `/admin/security/banned`           Add banned rule
  GET      `/admin/audit`                     Search audit events

Admin mutations require explicit permissions and audit events.

### 12.3 Endpoint endpoints

  ----------------------------------------------------------------------------
  Method                  Endpoint                     Purpose
  ----------------------- ---------------------------- -----------------------
  POST                    `/agent/enroll`              Exchange one-time
                                                       enrollment token

  POST                    `/agent/heartbeat`           Report heartbeat and
                                                       bounded device facts

  GET                     `/agent/jobs/next`           Claim next job for
                                                       authenticated device

  POST                    `/agent/jobs/{id}/started`   Report execution start

  POST                    `/agent/jobs/{id}/result`    Submit structured
                                                       result

  POST                    `/agent/credential/rotate`   Rotate device
                                                       credential
  ----------------------------------------------------------------------------

Endpoint routes require device authentication, not employee cookies.
Bind every request to the authenticated device. Rate-limit and reject
oversized payloads.

### 12.4 Standard error format

``` json
{
  "error": {
    "code": "SECURITY_CHECK_UNAVAILABLE",
    "message": "Security verification is temporarily unavailable. Installation has been paused.",
    "correlation_id": "uuid"
  }
}
```

Never return stack traces, SQL errors, secrets or raw provider messages.

### 12.5 API security

-   HTTPS only outside local development.
-   Authentication middleware and authorization dependencies.
-   Strict CORS allowlist.
-   Request size limits.
-   Rate limits by user, IP and device.
-   Idempotency keys for request creation and state-changing operations.
-   CSRF protection for cookie sessions.
-   Secure, HttpOnly, SameSite cookies if cookie auth is used.
-   Short-lived access tokens and secure refresh rotation if token auth
    is used.
-   No long-lived tokens in localStorage.
-   Validate ownership on every object ID to prevent IDOR.
-   OpenAPI docs disabled or access-controlled in production.
-   Audit admin mutations and endpoint lifecycle actions.

------------------------------------------------------------------------

## 13. Identity and authentication

### 13.1 Identity provider abstraction

Define an interface that supports: - Local development provider. -
Microsoft Entra ID OIDC provider.

Entra ID flow: - Authorization Code flow with PKCE for browser
clients. - Validate issuer, audience, signature, nonce, state and
expiry. - Map stable Entra subject/object ID to internal user. - Do not
use email alone as a stable identity key. - Enforce tenant allowlist
where required. - Use Microsoft Graph delegated/application permissions
only as necessary. - Keep client secrets/certificates server-side in a
secret manager.

### 13.2 Local development auth

-   Disabled in production unless explicitly configured.
-   Seed only synthetic accounts and random development passwords.
-   Force password change or use disposable credentials.
-   Use a modern password hashing algorithm (Argon2id preferred).
-   Apply login rate limiting and lockout/backoff.
-   Never seed a known default production admin password.

### 13.3 Entra and Outlook configuration

The operator supplies: - Tenant ID. - Client ID. - Client secret or
certificate reference. - Redirect URI. - Approved Graph scopes. - Admin
mailbox/sender configuration.

The product must validate configuration and show a safe "integration not
configured" state when absent. Do not pretend an email was sent if Graph
is not configured.

------------------------------------------------------------------------

## 14. Frontend UX specification

### 14.1 Design direction

Create a polished, calm enterprise-security product. Avoid a generic
admin template. Use: - Clear information hierarchy. - Neutral dark/navy
or light enterprise theme with restrained accent color. - Accessible
contrast and keyboard navigation. - Responsive desktop-first layout. -
Consistent spacing, typography, empty states and loading states. - Clear
status labels and reason explanations. - No fake charts or fabricated
activity.

### 14.2 Employee screens

**Employee home** - Welcome and selected device. - Device online/offline
state and last-seen time. - Natural-language request input. - Suggested
common software from approved catalogue. - Recent requests and outcomes.

**Request review** - Canonical software identity. - Exact version and
publisher. - Device compatibility. - Package source trust summary. -
Policy outcome: auto-approved / approval required / blocked. -
Plain-language reasons. - Confirm request action.

**Request progress** - Timeline: received, policy checked, approval,
queued, installing, verifying, completed. - Live/polled status. - Safe
error explanation and next step.

### 14.3 Admin screens

**Overview** - Enrolled devices, online devices, pending approvals,
recent installs and blocked requests. - Only show metrics calculated
from actual database records.

**Approvals** - Filters by age, software, requester, device and risk. -
Detail panel with exact approval binding and security checks. -
Approve/reject with comment and confirmation.

**Catalogue** - Software identity and aliases. -
Versions/platform/architecture. - Publisher, source, digest and
signature. - Approval policy and lifecycle. - Validation warnings for
incomplete metadata.

**Security** - Banned software rules. - Threat-provider health. - Recent
blocked requests. - Device quarantine status.

**Devices** - OS/architecture/agent version/last seen. - Enrollment and
credential status. - Installation history. - Revoke/quarantine action
with confirmation.

**Audit** - Search by actor, device, request, action, time and
correlation ID. - Read-only UI.

### 14.4 UX behavior

-   No optimistic success for installations.
-   Disable duplicate submit while request is pending.
-   Show request correlation ID for support.
-   Explain blocks without disclosing bypass-sensitive details.
-   Use confirmation for irreversible/admin actions.
-   Handle empty, loading, error, stale and offline states.
-   All controls must work; no decorative buttons pretending to perform
    actions.

------------------------------------------------------------------------

## 15. Observability, audit and operations

### 15.1 Structured logging

Use JSON logs with: - Timestamp, severity, service, environment. -
Correlation ID, request ID, job ID, device ID (internal UUID). - Event
name and stable error code. - Duration and provider status where useful.

Never log: - Access tokens, refresh tokens, API keys, client secrets. -
Passwords, enrollment tokens or device credentials. - Full raw package
URLs containing credentials. - Full prompts if they may contain
personal/confidential information. - Unbounded installer output.

### 15.2 Metrics

Track: - Request count and outcome. - Policy block/allow/approval
counts. - Approval wait time. - Job queue age and depth. - Installation
success/failure/verification failure. - Endpoint heartbeat age. - Gemini
latency/error rate. - Threat provider availability. - Notification
delivery failures.

Do not build an elaborate monitoring stack during the 48-hour MVP.
Expose health endpoints and structured logs first.

### 15.3 Health endpoints

-   `/health/live`: process alive.
-   `/health/ready`: database and required dependencies available.
-   Integration status endpoint restricted to admins; never expose
    secret values.

### 15.4 Audit integrity

-   Append-only application behavior.
-   Database role cannot update/delete audit rows.
-   Hash-chain events for tamper evidence.
-   Periodically export to protected external storage in production.
-   Audit policy changes, role changes, approvals, blocks, enrollment,
    credential rotation, job issuance, installation and security
    failures.

------------------------------------------------------------------------

## 16. Reliability and performance

### 16.1 Backend

-   Async I/O for network-bound operations.
-   Database connection pool limits.
-   Bounded worker concurrency.
-   Timeouts for all external calls.
-   Retry only transient failures; exponential backoff with jitter.
-   Circuit breaker or cooldown for failing external providers.
-   Outbox pattern for notification/job events.
-   Transactional state changes.
-   Pagination and bounded result sizes.
-   Avoid N+1 database queries.
-   Cache catalogue reads only with explicit invalidation/versioning.
-   Do not cache security verdicts beyond policy-defined TTL.

### 16.2 Endpoint

-   Low-frequency heartbeat with jitter.
-   Bounded memory and CPU use.
-   Bounded network retries.
-   Job polling backoff when idle.
-   No busy loops.
-   Graceful shutdown.
-   Persist only minimum state needed for recovery.
-   Never store a reusable approval token locally.

### 16.3 Scalability path

Start modular monolith. If scale requires it: 1. Separate background
workers and queue. 2. Add Redis or a durable message broker. 3.
Partition audit storage by time. 4. Add read replicas and cache. 5.
Split identity, catalogue, orchestration or notifications only when
operational evidence justifies it. 6. Support tenant isolation and
per-tenant policy namespaces before multi-tenant SaaS.

Do not introduce Kubernetes, Kafka or microservices solely to look
enterprise-grade in a 48-hour hackathon.

------------------------------------------------------------------------

## 17. Testing and acceptance criteria

A requirement is complete only when code, tests and a reproducible
demonstration exist.

### 17.1 Backend tests

-   Request validation and length limits.
-   Authentication and RBAC.
-   IDOR/ownership denial.
-   Exact catalogue matching.
-   Compatibility matrix.
-   Banned rule takes precedence.
-   Threat provider `MALICIOUS` blocks.
-   Threat provider `INDETERMINATE` blocks when mandatory.
-   Auto-approval only for explicitly eligible package/policy.
-   Requester cannot approve own request.
-   Approval binding invalidated by version/hash/policy changes.
-   Concurrent approvals produce one terminal decision.
-   Duplicate idempotency key creates one request.
-   Expired approval/job cannot dispatch.
-   Endpoint A cannot claim endpoint B's job.
-   Invalid/expired/replayed signature rejected.
-   Endpoint success without verification is not marked successful.
-   Notification failure does not corrupt approval state.

### 17.2 Endpoint tests

-   Invalid job signature rejected.
-   Wrong device ID rejected.
-   Expired job rejected.
-   Replayed nonce rejected.
-   Unknown installer type rejected.
-   Unknown package source rejected.
-   Hash mismatch rejected.
-   Signature mismatch rejected.
-   Unsafe path rejected.
-   Oversized package rejected.
-   Installer timeout handled.
-   Existing version detected.
-   Successful install verified.
-   Installer exit 0 but app missing =\> failure.
-   Service rejects arbitrary command fields.
-   IPC access denied to unauthorized local process.

### 17.3 Frontend tests

-   Employee cannot see other employee's requests.
-   Admin approval screen shows exact package version/hash.
-   Blocked request has no approval action.
-   Expired/decided request cannot be approved.
-   Errors and loading states render correctly.
-   XSS payload is rendered as text, not executable markup.
-   Keyboard navigation and form labels work.

### 17.4 End-to-end acceptance tests

**Scenario A --- catalogue software, auto-approved** - Employee requests
approved low-risk software. - Correct device selected. - Catalogue
version and compatibility are shown. - Policy auto-approves. - Endpoint
receives signed job. - Real host installation occurs. - Installed
version is independently verified. - Audit timeline shows all stages.

**Scenario B --- approval-required software** - Employee requests
controlled software. - No install job exists before approval. - Admin
sees request in dashboard. - Outlook notification sent if configured. -
Authorized admin approves. - Job is dispatched and installation
verified.

**Scenario C --- banned software** - Employee requests banned item. -
Request is blocked immediately. - Employee sees policy message. - No
approver notification is created. - No job is created. - Audit event
records the block.

**Scenario D --- security provider unavailable** - Mandatory threat
check returns indeterminate. - Request is paused/blocked according to
policy. - No auto-approval, notification for ordinary approval, or
install job is created. - Safe explanation is displayed.

**Scenario E --- offline endpoint** - Request remains queued only while
approval/job validity permits. - Device reconnects before expiry and
receives job. - If expired, job is rejected and a new request is
required.

### 17.5 Definition of Done

-   All critical security tests pass.
-   No known critical/high exploitable issue is knowingly left
    unresolved.
-   No secrets in repository or frontend bundle.
-   Database migrations work from an empty database.
-   One actual installation is demonstrated on the host OS.
-   Unsupported OS path fails safely.
-   Banned software never generates an approval or installation job.
-   Audit timeline is complete for the demo.
-   Setup instructions work on a clean environment.
-   Claims in presentation match verified implementation.

------------------------------------------------------------------------

## 18. 48-hour solo implementation plan

The goal is a complete vertical slice, not broad unfinished features.

### Phase 0 --- Guard the scope (Hour 0--1)

-   Confirm host OS and architecture.
-   Select one safe application already available in a trusted package
    source.
-   Create repository and architecture decision record.
-   Pin toolchains/dependencies.
-   Define demo flow and test fixtures.
-   Do not begin with UI polish.

**Exit:** repo, scope, selected host installer path and threat model
exist.

### Phase 1 --- Backend foundation (Hours 1--7)

-   FastAPI app, settings, structured errors and logging.
-   PostgreSQL + migrations.
-   User/role/device/catalogue/request/approval/job/audit models.
-   Local development auth and RBAC.
-   Seed synthetic employee/admin, device and catalogue entries.
-   Health endpoints.

**Exit:** database migrations and API smoke tests pass.

### Phase 2 --- Deterministic policy and request workflow (Hours 7--13)

-   Catalogue exact lookup.
-   Compatibility evaluator.
-   Banned software matcher.
-   Threat provider interface with a deterministic mock provider for
    tests.
-   Approval policy and state machine.
-   Idempotency.
-   Audit events.
-   Tests for banned, incompatible and approval-required cases.

**Exit:** backend correctly decides allow/approval/block without Gemini.

### Phase 3 --- Gemini integration (Hours 13--16)

-   Server-side Gemini client.
-   Strict structured intent schema.
-   Prompt-injection-resistant prompt.
-   Timeouts and bounded retry.
-   Exact catalogue alias matching after model extraction.
-   Deterministic fallback for exact demo names.

**Exit:** "Install VS Code" resolves to a catalogue identity; model
cannot issue commands or override policy.

### Phase 4 --- Rust endpoint and real host install (Hours 16--25)

-   Enrollment and device credential.
-   Heartbeat and device facts.
-   Authenticated job polling.
-   Signed job verification.
-   Typed job protocol.
-   User-mode agent.
-   Privileged service/adapter for the host OS.
-   Hash/signature verification.
-   Install and independent verification.
-   Result reporting and duplicate/replay protection.

**Exit:** real end-to-end install on host OS, or a clearly documented
safe blocker if host privileges/package source prevent it. Do not fake
success.

### Phase 5 --- Web dashboard (Hours 25--33)

-   Login.
-   Employee request page.
-   Device status.
-   Request timeline.
-   Admin approval queue.
-   Catalogue view.
-   Banned software screen.
-   Audit history.
-   Responsive, polished UX.

**Exit:** complete demo can be performed without API clients.

### Phase 6 --- Outlook, hardening and integration (Hours 33--39)

-   Microsoft Graph adapter if credentials available.
-   Outbox/retry and visible adapter status.
-   Entra ID adapter if tenant details available; otherwise tested local
    provider and documented Entra setup.
-   Rate limits, CORS, CSRF/session controls as applicable.
-   Secret scan, dependency scan, formatting and lint.
-   Review all privileged code paths.

**Exit:** optional integrations either work or show honest "not
configured" status; core web approval works.

### Phase 7 --- Test, fix and rehearse (Hours 39--46)

-   Run backend, frontend and Rust tests.
-   Run the five E2E scenarios.
-   Test offline, expired, duplicate, malicious and tampered job.
-   Verify no banned request triggers notification.
-   Test clean startup.
-   Fix critical/high defects before adding features.
-   Record a backup demo video.

**Exit:** repeatable demo and acceptance checklist.

### Phase 8 --- Presentation freeze (Hours 46--48)

-   Freeze features.
-   Seed realistic but synthetic data.
-   Reset demo environment.
-   Rehearse 3-minute and 5-minute pitches.
-   Prepare architecture and security explanation.
-   Prepare fallback recording and screenshots.
-   Do not introduce risky last-minute features.

### Time allocation rule

If behind schedule: 1. Keep policy and endpoint security. 2. Keep one
genuine installation. 3. Keep approval and banned-software path. 4. Keep
audit evidence. 5. Reduce visual polish and optional integrations. 6.
Never remove signature/hash verification, RBAC, or fail-closed checks to
recover time.

------------------------------------------------------------------------

## 19. Demo catalogue and seed data

Use synthetic seed records. The actual package must be verified for the
host platform before demo.

Suggested records:

  -----------------------------------------------------------------------
  Software                Demo policy             Notes
  ----------------------- ----------------------- -----------------------
  Visual Studio Code      Auto-approve only if    Exact approved version,
                          configured as approved  trusted source,
                          low-risk                verified
                                                  digest/signature

  Git                     Approval required or    Useful second catalogue
                          auto-approved by        example
                          explicit policy         

  Restricted              Block                   Demonstrates
  remote-access tool                              organisation ban

  Unknown editor          Not in catalogue        Must not install

  Approved app for        Incompatible            Demonstrates platform
  another OS                                      decision
  -----------------------------------------------------------------------

Do not label a real application "malware" merely for the demo. Use a
clearly synthetic banned test record, e.g. `demo-malware-sample`, and
explain it is a policy test fixture. Never download or execute malware.

------------------------------------------------------------------------

## 20. Environment configuration

Create `.env.example` with placeholders only:

``` dotenv
APP_ENV=development
APP_NAME=SentinelDesk
API_BASE_URL=http://localhost:8000
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel_dev_only@localhost:5432/sentinel
SESSION_SECRET=replace-with-random-development-secret
JOB_SIGNING_PRIVATE_KEY_PATH=
JOB_SIGNING_PUBLIC_KEY_PATH=
GEMINI_API_KEY=
GEMINI_MODEL=
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_CLIENT_SECRET=
ENTRA_REDIRECT_URI=http://localhost:8000/api/v1/auth/callback
GRAPH_SENDER=
GRAPH_SCOPES=
THREAT_INTEL_PROVIDER=
THREAT_INTEL_API_KEY=
CORS_ALLOWED_ORIGINS=http://localhost:5173
DEVICE_ENROLLMENT_TTL_MINUTES=10
JOB_TTL_MINUTES=15
HEARTBEAT_INTERVAL_SECONDS=60
```

Rules: - Generate random development secrets; never use the example
values in production. - Validate required settings at startup. - Never
print secret values. - Use secret manager/KMS in production. - Keep
`.env` out of Git. - Do not put backend secrets in `VITE_*` variables or
frontend source.

------------------------------------------------------------------------

## 21. Error codes and user messaging

  -----------------------------------------------------------------------
  Code                                User-facing message
  ----------------------------------- -----------------------------------
  `SOFTWARE_BLOCKED_BY_POLICY`        This software is blocked by your
                                      organisation's security policy. No
                                      installation was attempted.

  `SOFTWARE_NOT_IN_CATALOGUE`         This software is not currently
                                      available in your organisation's
                                      catalogue.

  `DEVICE_NOT_COMPATIBLE`             This software version is not
                                      compatible with this device.

  `APPROVAL_REQUIRED`                 Your request is waiting for
                                      administrator approval.

  `REQUEST_REJECTED`                  Your software request was not
                                      approved.

  `SECURITY_CHECK_UNAVAILABLE`        Security verification is
                                      temporarily unavailable.
                                      Installation has been paused.

  `DEVICE_OFFLINE`                    This device is currently offline.
                                      The request may continue when it
                                      reconnects, provided it has not
                                      expired.

  `INSTALLATION_FAILED`               Installation could not be
                                      completed. No success has been
                                      recorded.

  `FAILED_VERIFICATION`               The installer finished, but
                                      SentinelDesk could not verify the
                                      requested version.

  `ALREADY_INSTALLED`                 The requested version is already
                                      installed on this device.
  -----------------------------------------------------------------------

Keep internal error codes separate from sanitized public messages.

------------------------------------------------------------------------

## 22. Risk register and edge cases

  -----------------------------------------------------------------------
  Risk / edge case                    Required behavior
  ----------------------------------- -----------------------------------
  User asks for ambiguous product     Ask clarification; do not guess
  name                                

  Prompt injection says "ignore       Treat as untrusted user text;
  policy"                             policy remains authoritative

  Software is banned                  Block before approval; no approval
                                      email

  Malware hash match                  Hard block and audit

  Threat API unavailable              Fail closed

  Catalogue package has no digest     Not installable

  Signature publisher mismatch        Reject package

  OS/architecture mismatch            Explain incompatibility

  Insufficient disk                   Block before dispatch

  Software already installed          Report already installed; do not
                                      reinstall

  Two identical requests              Idempotency returns same request

  Two admins approve at once          One decision wins transactionally

  Requester attempts self-approval    Deny and audit

  Approval arrives after expiry       Reject

  Package hash changes after approval Invalidate approval

  Device credential stolen            Revoke, quarantine, reject jobs

  Device claims another device ID     Reject binding

  Job replay                          Reject nonce/job reuse

  Backend sends unknown action        Endpoint rejects

  Agent receives arbitrary command    Schema rejects; no execution path
  field                               exists

  Endpoint goes offline               Wait only until job expiry

  Agent crashes mid-install           Reconcile package state before
                                      retry

  Installer exit code is zero but app Verification failure
  absent                              

  User cancels after dispatch         Cancellation only if safe; never
                                      claim stopped unless confirmed

  Outlook API fails                   Keep approval in dashboard; retry
                                      outbox

  Gemini unavailable                  Exact deterministic catalogue
                                      lookup or clarification

  Entra unavailable                   Do not silently downgrade an
                                      enterprise session to local auth

  Clock skew                          Use bounded tolerance;
                                      server-issued expiry and monotonic
                                      local elapsed time

  OS package manager locked           Retry with bounded backoff; do not
                                      kill unrelated package operation

  Malformed device facts              Reject/mark stale; never assume
                                      compatibility

  Admin edits catalogue during        Policy/version binding invalidates
  approval                            approval

  Database unavailable                No new install job; endpoint cannot
                                      invent authorization

  Audit write fails                   Fail closed for security-sensitive
                                      transitions

  Malicious catalogue metadata        Treat as data; never as
                                      instructions; require admin
                                      validation

  Symlink/path traversal in package   Reject before execution

  Huge installer output               Truncate and sanitize

  Repeated enrollment attempts        Rate-limit; one-time token; revoke
                                      after use

  Agent downgrade                     Enforce minimum supported agent
                                      version and signed updates in
                                      future release

  Local user tampers with agent       Signature verification and service
                                      ACLs; report integrity failure
                                      where supported
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 23. Future enterprise roadmap

### Release 1 --- Hackathon

-   One real host-OS installation.
-   Cross-platform agent architecture and build path.
-   Internal catalogue.
-   Gemini intent extraction.
-   Deterministic guardrails.
-   Web approvals.
-   Optional Outlook/Entra adapters.
-   Audit and verification.

### Release 2 --- Pilot

-   Real Windows, macOS and Linux validation matrix.
-   Enterprise signing/notarization for agent installers.
-   Production Entra and Graph setup.
-   Durable queue/outbox.
-   Secret manager/KMS.
-   External threat-intelligence provider.
-   Agent update mechanism with signed releases and staged rollout.
-   Device groups, policy scopes and administrator delegation.
-   Security assessment and penetration testing.

### Release 3 --- Enterprise

-   Intune/Jamf/SCCM/MDM integration.
-   Multi-tenant isolation if product becomes SaaS.
-   Fleet-scale job scheduling and concurrency limits.
-   Package lifecycle and vulnerability intelligence.
-   Software license governance.
-   Cost and usage analytics.
-   HA/DR, backup restore tests and operational SLOs.
-   Compliance evidence and retention controls.

### Release 4 --- Advanced intelligence

-   Predictive compatibility.
-   Approved software recommendations by job role.
-   Software usage/license optimization where lawful and
    privacy-approved.
-   Dependency and update planning.
-   Policy simulation and impact analysis.
-   Human-reviewed risk scoring.

------------------------------------------------------------------------

## 24. Hackathon differentiation and judging strategy

The product should stand out through **trustworthy autonomy**, not by
claiming "AI can install anything."

### Strong differentiators

1.  **Policy-first AI:** AI understands the request, deterministic
    policy decides what is allowed.
2.  **Closed-loop execution:** request → compatibility → approval →
    install → independent verification.
3.  **Zero-notification hard block:** banned software is blocked
    immediately without creating an admin approval task.
4.  **Cross-platform agent architecture:** same job protocol,
    platform-specific trusted adapters.
5.  **Proof of execution:** show package identity, digest verification,
    signed job, endpoint identity and installed-version evidence.
6.  **Human-in-the-loop governance:** automatic approval only within
    explicit policy boundaries.
7.  **Explainable decisions:** show why a version was selected, blocked
    or sent for approval.

### Suggested 3-minute demo

**0:00--0:20 --- Problem** "Employees wait for IT to install approved
software. IT teams manually check compatibility, catalogue, security and
approvals. SentinelDesk automates the workflow while keeping privilege
and policy under control."

**0:20--1:10 --- Happy path** - Employee types: "Install Visual Studio
Code." - Dashboard identifies the enrolled machine. - Catalogue returns
exact compatible version. - Policy auto-approves only if seed policy
allows. - Endpoint receives a signed job. - Show actual installation and
verification.

**1:10--1:45 --- Approval path** - Request a controlled application. -
Show admin approval queue. - Approve in web dashboard. - Show Outlook
notification if Graph is configured. - Show job dispatch after approval
only.

**1:45--2:15 --- Security path** - Request synthetic banned test
software. - Show immediate block. - Show no approval notification and no
job. - Open audit evidence.

**2:15--2:40 --- Tampering path** - Demonstrate a test job with wrong
digest, expired timestamp or invalid signature. - Endpoint rejects it. -
Show safe failure.

**2:40--3:00 --- Close** "SentinelDesk is not an AI shell-command
generator. It is a policy-governed enterprise provisioning system with
verified endpoint execution."

### Judge questions to prepare for

**"Why use AI? Why not a normal catalogue?"**\
AI translates natural language and handles ambiguity. Catalogue
matching, security and authorization remain deterministic.

**"What if Gemini is compromised or hallucinates?"**\
Its output is schema-validated and treated as untrusted intent. It
cannot authorize or execute anything.

**"What if an admin approves malware?"**\
Ordinary approval cannot override hard security blocks. The endpoint
rechecks the signed job and package integrity.

**"How do you prevent a compromised endpoint from installing arbitrary
software?"**\
Device-bound credentials, signed short-lived jobs, closed action
protocol, local verification, fixed adapters and no remote shell.

**"Does it really work on all three operating systems?"**\
Show exactly which OS has been physically tested. Explain the shared
Rust architecture and platform-specific adapters. Never claim untested
platform validation.

**"Can it scale?"**\
The MVP is a modular monolith with clear boundaries; queue workers,
partitioning and service separation are planned when load justifies
them.

------------------------------------------------------------------------

## 25. Coding-agent execution instructions

This document is the source of truth. Any coding model (Claude, Codex,
Cursor, Gemini or another agent) must follow these rules.

### 25.1 Before coding

1.  Read this entire document.
2.  Inspect the existing repository before changing it.
3.  Identify host OS, architecture and available toolchains.
4.  Produce a concise implementation checklist mapped to sections and
    acceptance tests.
5.  Record assumptions and blockers. Do not invent credentials, API
    responses or integrations.
6.  Preserve working code. Do not rewrite the project unnecessarily.

### 25.2 During coding

-   Implement vertical slices in the order in Section 18.
-   Keep backend policy independent from Gemini.
-   Keep endpoint privileged service separate from user UI.
-   Use typed schemas at every process/network boundary.
-   Add tests with each feature.
-   Use migrations for database changes.
-   Keep secrets in environment/secret manager.
-   Avoid giant files and circular imports.
-   Use dependency injection for external services.
-   Use clear naming, small functions and explicit error handling.
-   Do not add features not required for the MVP unless they directly
    improve security or demo reliability.
-   Never replace a failing real integration with a fake success
    response.
-   Never suppress failing tests to make the build green.
-   Never weaken security controls for convenience.

### 25.3 After each phase

Report: - Files created/modified. - Requirements completed. - Tests run
and results. - Known defects. - Security implications. - Exact next
step.

Do not mark a requirement complete without evidence.

### 25.4 Completion report

At project completion, produce: - Feature-to-requirement traceability
matrix. - Test report with commands and results. - Supported OS/platform
matrix with actual validation status. - Security controls implemented
and limitations. - Environment variables required. - Setup/deployment
guide. - Demo script. - Known issues and deferred items.

### 25.5 Stop conditions

Stop and ask the human operator when: - A real credential, tenant ID,
package source or signing key is required but absent. - Package
publisher/hash/signature cannot be verified. - A requested action is
outside the typed allowlist. - A security control would need to be
disabled. - A destructive operation is proposed. - The host OS does not
support the required privileged workflow. - Requirements conflict or a
material assumption changes.

Do not ask for secrets in chat or commit them to source control. Provide
secure setup instructions instead.

------------------------------------------------------------------------

## 26. Final product acceptance checklist

### Product

-   [ ] Employee can submit a natural-language software request.
-   [ ] Device inventory is visible and current.
-   [ ] Catalogue lookup returns exact approved versions.
-   [ ] Compatibility decision is deterministic and explainable.
-   [ ] Banned software is blocked immediately.
-   [ ] Approval-required software reaches the admin queue.
-   [ ] Web approval is authenticated and audited.
-   [ ] Outlook notification works when configured, otherwise reports
    unconfigured honestly.
-   [ ] Endpoint receives only authorized typed jobs.
-   [ ] Real installation succeeds on the tested host OS.
-   [ ] Installed version is independently verified.
-   [ ] User sees accurate final status.

### Security

-   [ ] Gemini cannot authorize or execute.
-   [ ] No model-generated shell commands exist in the execution path.
-   [ ] Input/action/output guardrails are tested.
-   [ ] Banned rules take precedence over approval.
-   [ ] Mandatory security check failure blocks installation.
-   [ ] Package digest and publisher signature are verified.
-   [ ] Job signature, expiry, nonce and device binding are verified.
-   [ ] Privileged service has a closed command surface.
-   [ ] RBAC and ownership checks are tested.
-   [ ] Secrets are absent from source and frontend bundles.
-   [ ] Audit events exist for all security-sensitive transitions.

### Engineering

-   [ ] Clean startup works from documented instructions.
-   [ ] Migrations work on an empty database.
-   [ ] Formatting, lint and tests pass.
-   [ ] No critical/high known vulnerability is knowingly ignored.
-   [ ] Errors are bounded, sanitized and traceable.
-   [ ] Unsupported platform reports a truthful safe result.
-   [ ] Demo is repeatable from a clean state.

------------------------------------------------------------------------

## 27. Final engineering directive

Build SentinelDesk as a **secure software-provisioning control plane
with a narrowly privileged endpoint executor**.

The winning story is not "Gemini installs applications." The winning
story is:

> "An employee can request software naturally. SentinelDesk understands
> the intent, checks the organisation's approved catalogue, validates
> device compatibility, applies deterministic security policy, routes
> only eligible requests for approval, and executes a signed, verified
> installation on the correct device---with complete evidence."

**Prioritize in this order:** 1. Security correctness. 2. Real
end-to-end installation. 3. Deterministic policy and approval. 4.
Verification and audit evidence. 5. Reliability and recovery. 6.
Cross-platform architecture and honest validation. 7. Visual polish and
optional integrations.

A smaller product that securely completes one real installation is
stronger than a broad demo that simulates everything. Do not claim "100%
bug-free." Demonstrate measurable correctness, transparent limitations
and a defensible security design.
