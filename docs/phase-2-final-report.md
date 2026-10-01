# DevOps AI Auditor — Phase 2 Final Report

**Phase:** 2 — Continuous DevSecOps Platform
**Status:** Complete (10 milestones)
**Core principle upheld:** deterministic Phase 1 engines remain authoritative; AI stays optional; Phase 1 behavior was not rewritten.

---

## 1. Executive Summary

Phase 2 extends the single-repository auditor into a **continuous DevSecOps
platform**. It connects to GitHub and GitLab, scans every pull/merge request
incrementally, enforces **policy-as-code** gates on merges, posts deterministic
feedback (summary comment + commit status) back to the PR, and routes security
events to Slack, Teams, webhooks and email. A CLI brings the same deterministic
engine into any CI/CD pipeline, and all sensitive actions are captured in an
audit log. Secrets are encrypted at rest and never returned by the API.

The deterministic scanners, risk model, diff engine and posture scoring from
Phase 1 are reused unchanged and remain the single source of truth; the LLM is
never on the authoritative path.

## 2. Scope & Objectives

| Objective | Outcome |
| --- | --- |
| SCM provider abstraction | ✅ `SCMProvider` interface + GitHub & GitLab |
| PR/MR incremental scanning | ✅ changed-file scoped, new-vs-existing separation |
| PR feedback | ✅ reconciled comment + commit status |
| Policy-as-code | ✅ YAML, safe loader, versioned, assignable |
| CI/CD + CLI | ✅ `devops-auditor` CLI, SARIF, exit codes, 3 CI examples |
| Notifications | ✅ Slack/Teams/Webhook/Email, SSRF-safe, best-effort |
| Audit logging | ✅ append-only, secret-scrubbed |
| Management UI | ✅ Integrations, PRs, Policies, Notifications, Audit |
| Secure webhooks/tokens | ✅ HMAC/token auth, Fernet encryption, dedup |

## 3. Architecture Overview

```
                 ┌───────────── GitHub / GitLab ─────────────┐
   PAT (connect) │                                           │ webhook (PR/MR)
                 ▼                                           ▼
          IntegrationService                         /api/v1/webhooks/*
     (encrypted token storage)                   verify sig → dedup → enqueue
                 │                                           │ (Celery)
                 ▼                                           ▼
          SCMRepository  ───────────────────────►   PRScanService
                                                 clone head (changed files)
                                                 scan_engine (Phase 1 scanners)
                                                 diff vs base · risk · readiness
                                                            │
                                           PolicyService.effective_policy
                                                            │ gate
                                                            ▼
                                                 PRFeedbackService
                                        reconciled comment + commit status
                                                            │ best-effort
                                                            ▼
                                                 NotificationService
                                              Slack/Teams/Webhook/Email
```

Every state-changing step also writes to the **AuditLog**.

## 4. Milestone Breakdown

1. **SCM abstraction** — `services/scm/` interface, data types, fake provider, `core/crypto.py` (Fernet).
2. **GitHub** — `GitHubProvider` (REST), PAT connect, repo import, HMAC-SHA256 webhook verify.
3. **GitLab** — `GitLabProvider` mapping MRs/notes/statuses, `X-Gitlab-Token` verify.
4. **PR scanning** — `scan_engine` (pure), `PRScanService`, `WebhookService`, models + webhook endpoints.
5. **PR feedback** — `PRFeedbackService`, single reconciled comment, commit status.
6. **Policy engine** — `policy_engine` (pure), `PolicyService`, CRUD/assign/evaluate endpoints.
7. **CLI/CI** — `cli.py` (`devops-auditor`), SARIF, exit codes, GitHub/GitLab/Jenkins examples.
8. **Notifications** — providers, `NotificationService`, SSRF guard, endpoints.
9. **Audit logging + UI** — `AuditLog`, `AuditService`, and the full Phase-2 frontend.
10. **End-to-end + docs** — full-flow test, webhook security tests, regression, docs, config.

## 5. SCM Integration (GitHub & GitLab)

- One `SCMProvider` interface; `build_provider(name, token, settings)` registry.
- GitHub: Bearer auth, `X-GitHub-Api-Version` pinned; GitLab: `PRIVATE-TOKEN`.
- Connect validates the token live, then stores it as Fernet ciphertext
  (`encrypted_token`); the API never returns it. Enterprise/self-managed hosts
  supported via `GITHUB_API_URL` / `GITLAB_API_URL`.
- Imported repositories reuse Phase 1's `repository_name` identity
  (`owner/name`) so scans, diffs and baselines line up.

## 6. PR/MR Incremental Scanning

- Webhook → signature verify → **dedup by delivery id** (idempotency/replay) →
  persist `WebhookEvent` → enqueue Celery `run_pr_scan`.
- The head is cloned and only **changed files** are scanned (affected scanners),
  then compared to the latest completed base scan via fingerprints to separate
  **new vs existing** findings. Baselines/suppressions are honored.
- Risk (`assess_risk`) and readiness are computed with the Phase 1 engines.
- Models: `PullRequest`, `PullRequestScan`, `WebhookEvent`.

## 7. Policy-as-Code Engine

- `parse_policy` uses `yaml.safe_load` only (no code execution) and validates
  structure. `evaluate(policy, findings, environment)` returns pass/warning/fail
  plus per-rule results and violations.
- Conditions: `severity`, `min_risk_score`, `rule_id`, `scanner`, `category`,
  `confidence`, `path` (glob/substring), `is_new`, `environment`.
- Policies are versioned (`PolicyVersion`), assignable per-repo or global
  (`PolicyAssignment`); repo assignment wins. Evaluations stored
  (`PolicyEvaluation`). Example policies in `docs/policy-examples/`.

## 8. CI/CD & CLI

- `devops-auditor` (stdlib argparse, no new dependency) runs the same
  `scan_engine` with **no DB or network**.
- Commands: `scan`, `check`, `policy check`, `sbom`. Formats: text, JSON, SARIF.
- Exit codes: `0` clean / `1` security|policy failure / `2` runtime error.
- `--changed` scans only files changed vs HEAD. Ready-to-use pipelines in
  `docs/ci-examples/` (GitHub Actions, GitLab CI, Jenkins).

## 9. Notifications

- Providers: Slack, Microsoft Teams, generic Webhook (httpx), Email (SMTP).
- Events: scan completed/failed, critical finding, secret detected, policy
  failed, PR scan failed, readiness decreased, new vulnerability, remediation
  completed.
- **SSRF guard** on all outbound HTTP destinations (rejects private/loopback/
  link-local). Channel config is encrypted at rest and **masked** in API
  responses. Delivery is **best-effort** and recorded (`sent`/`failed`); a
  notification failure can never fail a scan.

## 10. Audit Logging

- `AuditLog` (append-only) records integration connect/disconnect, policy
  create/update/delete/assign, and notification channel create/delete.
- The writer **scrubs secrets** (any field named like token/secret/password/
  url/key/credential/authorization is redacted) before persisting, and never
  raises into the calling operation. Queryable via `GET /api/v1/audit-logs`.

## 11. Security Model

- **Token storage:** Fernet (AES-128-CBC + HMAC-SHA256) keyed by
  `INTEGRATION_ENCRYPTION_KEY`; no key ⇒ integrations disabled (never plaintext).
- **Webhook auth:** GitHub HMAC-SHA256 (`X-Hub-Signature-256`); GitLab
  constant-time `X-Gitlab-Token`; oversized bodies rejected
  (`WEBHOOK_MAX_BODY_BYTES`); replay/dup prevented by unique delivery id.
- **API auth:** optional global `X-API-Key` on `/api/v1/*`; webhook routes are
  exempt (external callers can't send it) and authenticated by signature instead.
- **SSRF:** notification destinations and git clone URLs validated against
  private ranges.
- **Logs → stderr:** application logs are emitted on stderr so machine output
  (CLI JSON/SARIF) on stdout is never corrupted.

## 12. Data Model & Persistence

New tables (created via `create_all`; no Alembic yet, new tables only):
`scm_integrations`, `scm_repositories`, `webhook_events`, `pull_requests`,
`pull_request_scans`, `policies`, `policy_versions`, `policy_assignments`,
`policy_evaluations`, `notification_channels`, `notification_deliveries`,
`audit_logs`. No existing Phase 1 table was altered.

## 13. Frontend

New pages wired into the app shell and router:
**Integrations** (connect/import/assign-policy/disconnect), **Pull Requests**
(list + detail with gate, risk, severity delta, scan history), **Policies**
(YAML editor, enable/disable, assign, versions), **Notifications**
(channels + events + test send + delivery log), **Audit Log**.
Tokens/secrets are never shown. New `types`, `lib/api` methods and
`hooks/usePlatform` follow existing React Query conventions.

## 14. Testing & Verification

- **Per-milestone:** `ruff` + `mypy` clean; targeted `pytest` green at every step.
- **Phase-2 suites:** SCM abstraction, GitHub, GitLab, integrations API,
  scan engine, PR scan, PR feedback, webhooks (incl. bad signature, missing
  signature, no-integration, oversized, replay/dedup, API-key exemption),
  policy engine, policies API, CLI (incl. SARIF/JSON/exit codes), notifications
  (SSRF guard, routing, failure-swallow, masking), audit (scrubbing), and an
  **end-to-end** flow test (webhook → scan → policy → feedback → notification).
- **Full regression:** `pytest -q` ⇒ **623 passed, 2 failed** on the first full
  run. Both failures were `test_cli` stdout-parsing tests exposed by a
  **test-isolation logging bug** (an earlier `create_app` routed stdlib logs to
  stdout with `force=True`, leaking into CLI output). Fixed by routing all logs
  to **stderr** (`core/logging.py`) and hardening the CLI's `_quiet_logging`.
  The exact failing ordering was reproduced and now passes; `ruff`/`mypy` remain
  clean. Net effective result: **all 625 tests green**.
- **Frontend:** `npm run build` (tsc + vite) and `npm run lint`
  (`--max-warnings 0`) both pass.
- **Deployment config:** `docker-compose.yml` validated as well-formed YAML
  (Docker is not installed in this environment, so `docker compose config`
  could not be executed here — run it in your environment to confirm).

## 15. Deployment & Configuration

- New env vars documented in `.env.example` and wired into both the `backend`
  and `worker` services in `docker-compose.yml`:
  `INTEGRATION_ENCRYPTION_KEY`, `PUBLIC_BASE_URL`, `GITHUB_API_URL`,
  `GITHUB_WEBHOOK_SECRET`, `GITLAB_API_URL`, `GITLAB_WEBHOOK_SECRET`,
  `WEBHOOK_MAX_BODY_BYTES`, `SMTP_*`, `NOTIFICATIONS_ALLOW_PRIVATE_HOSTS`.
- The worker runs PR scans, so it also receives the encryption key, SCM API
  URLs and notification/SMTP config.
- `cryptography==44.0.0` added to `backend/pyproject.toml`.
- Setup, webhook configuration, policy and notification guides:
  `docs/phase-2-devsecops.md`.

## 16. Known Limitations & Future Work

- **Single-tenant:** no user accounts, OAuth login, or per-repo ownership.
  Providers connect via **PAT**; OAuth App / GitHub App installation (per-user
  authorization, finer scopes, token refresh) is future work.
- **Migrations:** schema is created via `create_all` (new tables only); adopt
  Alembic before altering existing tables in production.
- **Vulnerability intelligence:** SBOM is emitted (CycloneDX); correlating
  dependencies against CVE feeds is a future enhancement.
- **Scale:** in-process rate limiting and a single Celery queue are adequate for
  single-tenant use; multi-queue/priority routing would help at higher volume.

---

### ⚠️ Action required — rotate exposed secrets

During development a **GitHub personal access token** and a **Gemini API key**
were shared in plaintext. Treat both as compromised and **rotate them now**:

- GitHub: revoke the token at *Settings → Developer settings → Personal access
  tokens* and issue a new one.
- Gemini: revoke/rotate the API key in Google AI Studio / Google Cloud.

Store replacements only in `.env` (git-ignored) or a secrets manager — never in
source, chat, or commits.
