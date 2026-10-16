# DevOps AI Auditor — Phase 5 Report

**Phase:** 5 — Continuous Security Operations & Intelligent Incident Response
**Core principles upheld:**
- **Deterministic rules remain authoritative.** Correlation, risk prioritization,
  and verification are all deterministic and explainable. AI investigates and
  explains; it never sets severity, risk, or incident state.
- **Read-only / plan-only by default.** Event sources are read-only or signed
  webhooks. Containment is plan-first and approval-gated; execution never mutates
  infrastructure in this build (the AWS connector is read-only) — it records the
  intended action and current state honestly.
- **Evidence-grounded, redaction-safe.** Every external payload is treated as
  untrusted, secret-redacted and size-bounded before storage. Notifications and
  AI tools expose metadata only — never credentials, tokens, or raw payloads.
- **Phases 1–4 unchanged.** The repo scanner, cloud intelligence, policy/risk, and
  the Phase 3 agentic layer are reused as-is. Security-ops is a new, additive
  layer that *reads* their outputs.

---

## 1. Features implemented

- **Continuous security-event ingestion** from internal (verified) sources — new
  repository-scan findings, cloud-scan findings, and risk-significant cloud
  changes — and external (reported) sources — AWS GuardDuty, Security Hub,
  CloudTrail, AWS Config, plus signed CI/CD, Falco, and Alertmanager webhooks.
- **Unified normalized event schema** with content-based deduplication (repeated
  deliveries fold onto one row), out-of-order handling, provenance, and a
  `verified` flag separating independently-verified findings from reported alerts.
- **Deterministic incident correlation** that groups events sharing an explainable
  linkage (same resource, cloud-graph-related resource, shared IAM principal, or
  shared source IP) within a bounded time window — every link carries a rationale.
- **Incident lifecycle** with server-validated transitions, ownership, notes, and
  a full audit timeline.
- **AI-assisted incident investigation** reusing the Phase 3 LangGraph agent with
  new read-only, scope-enforced incident tools; answers are evidence-grounded with
  citations and a hallucination guard.
- **Attack timeline + relationship graph** distinguishing confirmed facts from
  deterministically-inferred links (AI hypotheses are kept separate).
- **Deterministic, explainable risk prioritization** (0–100) with a per-factor
  rationale and double-counting protection.
- **Containment / remediation planning + approval workflow** — non-destructive
  recommendations, approval gating, idempotent gated execution, and independent
  verification by re-running deterministic checks.
- **Background processing** via Celery (event-driven ingestion + a scheduled
  poll/correlate/prune sweep) and **redaction-safe notifications/escalation**.
- **Incident Operations Center UI** — dashboard, incident list, and a tabbed
  incident detail (overview/events/timeline/graph/plans/investigate/notes).

## 2. Architecture and data-flow changes

```
 Sources ──► Ingestion ──► Normalized SecurityEvent (deduped) ──► Correlation ──► Incident
 (verified: repo/cloud scans, cloud changes;        │                 │              │
  reported: GuardDuty/SecurityHub/CloudTrail/        │                 │       Prioritization
  Config, CI-CD/Falco/Alertmanager webhooks)         │                 │       (deterministic)
                                                     ▼                 ▼              │
                                             secret-redacted    explainable      ┌───┴─────────────┐
                                             + size-bounded      rationale       │ AI investigation │ (read-only,
                                                                                 │ Containment plan │  approval-gated,
                                                                                 │ + verification   │  evidence-grounded)
                                                                                 └─────────────────┘
```

A new, self-contained layer lives under `backend/services/security/` (pure
ingestion/correlation/prioritization primitives + adapters) with two orchestration
services (`SecurityService`, `IncidentService`) and a `ContainmentService`. The
AI layer reuses the Phase 3 engine with an incident-scoped tool registry. Workers
and notifications reuse the existing Celery and notification infrastructure.

## 3. New and modified files

**New (backend):**
- `models/security.py` (SecurityEvent, SecurityEventSource),
  `models/incident.py` (Incident, IncidentEvent, IncidentResource,
  IncidentTimelineEntry, IncidentNote, IncidentInvestigation, ContainmentPlan,
  ContainmentApproval, ContainmentExecution).
- `services/security/{normalize,ingest,correlation,prioritization,notify,
  webhook_auth}.py` and `services/security/adapters/{internal,aws,webhook}.py`.
- `services/security_service.py`, `services/incident_service.py`,
  `services/containment_service.py`.
- `agents/investigation/tools/incident_tools.py`.
- `api/v1/endpoints/{security,incidents,containment}.py`.
- `workers/security_tasks.py`.
- Tests: `tests/test_security_ingest.py`, `test_security_correlation.py`,
  `test_incident_lifecycle.py`, `test_incident_ai.py`, `test_incident_graph.py`,
  `test_incident_prioritization.py`, `test_containment.py`,
  `test_incident_verification.py`, `test_security_tasks_notify.py`,
  `test_incident_api.py`.

**New (frontend):** `hooks/useIncidents.ts`,
`pages/IncidentDashboard.tsx`, `pages/IncidentList.tsx`, `pages/IncidentDetail.tsx`.

**Modified (backend):** `models/__init__.py`, `models/enums.py`,
`models/schemas.py`, `core/config.py`, `core/database.py`, `core/exceptions.py`,
`api/dependencies.py`, `api/v1/router.py`, `agents/investigation/engine.py`,
`agents/investigation/tools/base.py`, `agents/investigation/tools/registry.py`,
`services/investigation_service.py`, `services/notifications/base.py`,
`workers/celery_app.py`, `workers/cloud_tasks.py`, `tests/conftest.py`.

**Modified (frontend):** `types/api.ts`, `lib/api.ts`, `App.tsx`,
`components/layout/AppShell.tsx`.

## 4. Database migrations

Eleven new tables are created idempotently via SQLAlchemy `create_all`
(registered in `models/__init__.py` and `core/database.py`): `security_events`,
`security_event_sources`, `incidents`, `incident_events`, `incident_resources`,
`incident_timeline_entries`, `incident_notes`, `incident_investigations`,
`containment_plans`, `containment_approvals`, `containment_executions`. No
existing table is altered, so there is no destructive migration. Two UNIQUE
constraints enforce core invariants: `security_events.fingerprint` (dedup) and
`containment_executions.idempotency_key` (no duplicate execution). On an existing
database the new tables appear automatically on startup.

## 5. New API endpoints

Security (prefix `/api/v1/security`):
- `GET /events`, `GET /events/{id}` — list/get normalized events.
- `GET /sources`, `GET /integrations/health` — source registry + ingestion health.
- `POST /correlate` — run deterministic correlation on demand.
- `POST /webhooks/{source}` — signed inbound webhook (`cicd`|`falco`|`alertmanager`),
  HMAC + replay authenticated (not the API key).

Incidents (prefix `/api/v1/incidents`):
- `GET /` (filters), `POST /` (manual create from events), `GET /{id}` (detail),
  `PATCH /{id}` (owner/root-cause/resolution), `POST /{id}/transition` (validated).
- `GET /{id}/timeline`, `GET /{id}/relationships`, `GET /{id}/events`,
  `GET`/`POST /{id}/notes`.
- `POST`/`GET /{id}/remediation-plans`, `POST`/`GET /{id}/investigations`.

Containment (prefix `/api/v1/remediation-plans`):
- `GET /{id}`, `POST /{id}/approve`, `POST /{id}/reject`, `POST /{id}/execute`,
  `POST /{id}/verify`.

## 6. Frontend pages and workflows

- **Incident Dashboard** (`/incidents`): open-by-severity, new/unassigned counts,
  open-by-account, event-ingestion health, a "run correlation" action, and the
  highest-priority open incidents.
- **Incident List** (`/incidents/list`): search/filter by status, severity, and
  unassigned; sortable table linking to detail.
- **Incident Detail** (`/incidents/:id`): tabbed —
  *Overview* (assignment + deterministic risk rationale + affected resources),
  *Events* (member events with correlation rationale + verified/reported badges),
  *Timeline* (evidence-class-colored entries), *Graph* (relationship nodes/edges
  with confirmed vs inferred), *Plans* (generate/approve/reject/execute/verify),
  *Investigate* (evidence-grounded AI workspace reusing the Phase 3 result view),
  and *Notes*. Lifecycle transitions are driven from the header.

## 7. AWS and external integration setup

- **Internal sources (no setup):** repo-scan and cloud-scan findings and cloud
  changes are ingested automatically — repo scans via the ingestion task, cloud
  syncs via a worker hook that enqueues ingestion after each sync.
- **AWS native sources (read-only):** reuse the Phase 4 read-only AssumeRole role.
  Grant additional read-only permissions as needed: `guardduty:ListDetectors`,
  `guardduty:ListFindings`, `guardduty:GetFindings`, `securityhub:GetFindings`,
  `cloudtrail:LookupEvents`, and `config:Describe*`/`config:Get*`. The polling
  adapters are defensive — missing permissions surface via source health, never a
  crash. (In this build the normalizers are exercised with recorded fixtures; live
  polling requires the assumed-role access above.)
- **Webhook sources (CI/CD, Falco, Alertmanager):** register a source with a
  shared secret, then have the sender POST to `/api/v1/security/webhooks/{source}`
  with `X-Timestamp` (unix seconds) and `X-Signature: sha256=<hex>` where the hex
  is `HMAC-SHA256(secret, "<timestamp>.<raw-body>")`. Requests outside the replay
  window or with a bad signature are rejected with HTTP 401.

## 8. Environment variables and configuration

Added to `core/config.py`, `.env.example`, and both `backend`/`worker` services in
`docker-compose.yml` (all optional; defaults production-safe):

| Variable | Default | Purpose |
|---|---|---|
| `SECURITY_OPS_ENABLED` | `true` | Master toggle for the security-ops subsystem |
| `INCIDENT_AUTO_CREATE` | `true` | Auto-create incidents from correlated events |
| `INCIDENT_CORRELATION_WINDOW_MINUTES` | `1440` | Max window to fold events into one incident |
| `SECURITY_POLL_INTERVAL_MINUTES` | `15` | Scheduled poll/correlate/prune cadence (0 disables) |
| `SECURITY_EVENT_RETENTION_DAYS` | `90` | Retention for uncorrelated events (0 disables prune) |
| `SECURITY_WEBHOOK_MAX_BODY_BYTES` | `1000000` | Max inbound webhook payload size |
| `SECURITY_WEBHOOK_REPLAY_WINDOW_SECONDS` | `300` | Accepted webhook timestamp skew |

Containment write execution is additionally gated by the existing
`CLOUD_WRITE_ENABLED` (default `false`). The worker runs embedded Celery beat
(`--beat`) which now also schedules the security poll sweep.

## 9. Security controls and approval behavior

- **Webhook authentication:** HMAC-SHA256 over `"<timestamp>.<body>"`, constant-time
  compared, with a replay window. A source without a configured secret rejects all
  inbound webhooks (never fails open).
- **Untrusted input:** every event payload is secret-redacted and size-bounded
  before storage; AI tools additionally neutralize text (prompt-injection defense
  reused from Phase 3) and enforce incident/account scope.
- **Approval gating:** containment plans start `proposed`; execution requires an
  authorized `approved` state. Duplicate execution is blocked by a UNIQUE
  idempotency key. WRITE-class actions require `CLOUD_WRITE_ENABLED` and are still
  never auto-performed (read-only connector) — recorded honestly as `not_enabled`;
  advisory PLAN actions are recorded `skipped`.
- **Verification before closure:** a plan is only marked `verified` when a
  deterministic re-check confirms the issue is fixed. A successful execution record
  never implies resolution.
- **AI boundaries:** investigation tools are read-only and scope-enforced; AI never
  sets severity/risk/state; the risk score is computed deterministically.
- **Notifications:** carry only title/severity/priority/status/account/resource
  ids (+ an optional link). Principals, IPs, provenance, and raw payloads are never
  included; delivery is best-effort and never breaks processing.

## 10. Tests executed and results

**55 new Phase-5 tests** across 10 files (service-level on a fast shared in-memory
SQLite, plus HTTP tests on a file-backed app):

| File | Tests | Covers |
|---|---|---|
| `test_security_ingest.py` | 10 | Normalization, dedup, redaction, AWS fixtures, webhook auth (bad sig/replay/missing secret) |
| `test_security_correlation.py` | 6 | Resource/related-resource/principal grouping, isolation, idempotency, rationale |
| `test_incident_lifecycle.py` | 8 | Valid + illegal transitions, manual create, notes, filters |
| `test_incident_ai.py` | 5 | AI fallback+persist, grounded citations, hallucination guard, incident + account scope |
| `test_incident_graph.py` | 2 | Confirmed vs inferred edges; hypotheses excluded |
| `test_incident_prioritization.py` | 6 | Deterministic score + rationale, no double-counting, compensating controls |
| `test_containment.py` | 7 | Plan generation, approval required, write gating, duplicate-exec, advisory skip |
| `test_incident_verification.py` | 3 | Unresolved→fixed, verify-requires-execute, inconclusive |
| `test_security_tasks_notify.py` | 3 | Notification + redaction, no-channel no-op, event pruning |
| `test_incident_api.py` | 5 | HTTP ingest/correlate/list/detail/lifecycle, containment, webhook replay (401), 404 |

Per-milestone gate (all green): `ruff check --fix`, `mypy .` (225 source files, no
issues), and the milestone's `pytest` file. Frontend `npm run build` (tsc + vite)
and `npm run lint` (`eslint --max-warnings 0`) both pass. `docker-compose.yml`
validated as well-formed YAML. The full backend regression result (Phases 1–5)
accompanies this change in the verification summary; the 55 new tests pass and no
Phase 1–4 test regressed.

> Note on the test environment: this host's filesystem makes per-test SQLite
> `create_all` very slow, so Phase-5 service tests use a shared in-memory SQLite
> (StaticPool) via the `mem_db` fixture for speed and reliability; HTTP tests use
> a module-scoped file DB like the Phase-3 API tests.

## 11. Deployment and upgrade instructions

1. Pull the changes; no destructive migration — new tables are created on startup
   via `create_all` (Postgres and SQLite alike).
2. Set the optional Phase-5 env vars (section 8) if you want non-default behavior.
   For scheduled polling/pruning, keep the worker running with embedded beat
   (compose already uses `--beat`).
3. To enable AWS native sources, extend the Phase-4 read-only role with the
   permissions in section 7. To enable webhook sources, register a source with a
   secret and configure the sender's HMAC headers.
4. Containment execution stays plan-only unless `CLOUD_WRITE_ENABLED=true`; even
   then this build does not perform AWS mutations (read-only connector).
5. Rebuild the frontend (`npm run build`) to pick up the Incident Operations Center.

## 12. Known limitations and unimplemented features

- **No real containment writes.** Because the AWS connector is strictly read-only,
  approved WRITE plans are not executed automatically — the workflow is planning +
  approval + honest `not_enabled`/`skipped` recording + verification. This is a
  deliberate safety choice, consistent with the spec's fallback.
- **AWS native polling is fixture-tested.** The GuardDuty/Security Hub/CloudTrail/
  Config normalizers are fully implemented and unit-tested with recorded fixtures;
  live polling requires the assumed-role permissions and is a no-op (surfaced via
  health) where unavailable. Config change ingestion is normalized but not yet
  wired to a live subscription.
- **Single-tenant authorization.** Consistent with Phases 1–4, there is no
  per-user/org model; scoping is enforced by cloud account and incident/account
  tool scope. Multi-tenant RBAC is future work.
- **Verification is cloud-rule-based.** Deterministic verification re-runs cloud
  rules for cloud-scan-sourced incidents; incidents whose signals have no
  deterministic rule return `inconclusive` and require human confirmation.
- **Relationship graph is tabular** in the UI (nodes + evidence-classed edge
  table), not a force-directed canvas.
- **AI quality depends on the configured LLM;** with none configured the engine
  returns deterministic, tool-grounded fallbacks.

## 13. Recommended Phase 6

- Live AWS event delivery (EventBridge → ingestion) instead of polling, plus
  GuardDuty/Security Hub subscription management from the UI.
- Safe, audited containment *execution* behind an explicit opt-in with real
  rollback, change previews, and post-change verification.
- Multi-tenant RBAC (org/project/user) with per-tenant isolation tests.
- SOAR-style playbooks: deterministic, approval-gated response runbooks per
  incident class.
- A force-directed incident graph with drill-down and attack-path highlighting.
- MTTR/MTTA analytics and an on-call escalation policy engine.
- Expand verification beyond cloud rules (repo re-scan, K8s re-check) and add a
  golden incident-response evaluation harness.
