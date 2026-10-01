# Phase 2 — Continuous DevSecOps Platform

Phase 2 turns the repository auditor into a continuous DevSecOps platform:
connect GitHub/GitLab, scan every pull/merge request incrementally, gate merges
with policy-as-code, and route security events to Slack, Teams, webhooks or
email. The deterministic Phase 1 engines (scanners, risk, diff, posture) remain
the authoritative core; AI stays optional.

> **Deployment model.** This is a **single-tenant** platform. There is no user
> account or OAuth login system. Integrations, policies and notification
> channels are workspace-global and protected by the optional `X-API-Key`
> (see `API_KEY`). Providers are connected with a **personal access token
> (PAT)**, stored encrypted. OAuth App / GitHub App flows are a future
> enhancement (see "Known limitations").

---

## 1. Prerequisites

Set an encryption key so access tokens and webhook secrets are stored encrypted
at rest. Without it, integrations are disabled (tokens are never stored in
plaintext).

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the result in `.env`:

```ini
INTEGRATION_ENCRYPTION_KEY=<generated-key>
PUBLIC_BASE_URL=https://auditor.example.com   # used for PR links + status target_url
```

See `.env.example` for the full Phase 2 variable surface.

---

## 2. Connecting GitHub

1. Create a PAT with `repo` scope (and `admin:repo_hook` if you want the
   platform to register webhooks for you). A fine-grained token needs
   **Contents: read**, **Pull requests: read/write**, **Commit statuses:
   read/write**, and **Webhooks: read/write**.
2. In the UI go to **Integrations → Connect a provider**, choose **GitHub**,
   paste the token, and connect. The token is validated against the API, then
   stored encrypted. It is never returned by the API again.
3. **Import repositories**: enter `owner/repo` under the integration to track it
   for PR scanning. The imported `full_name` is the same identity Phase 1 uses
   for scans/diffs/baselines, so history lines up.

### Webhook (GitHub)

Point a repository (or org) webhook at:

```
POST  {PUBLIC_BASE_URL}/api/v1/webhooks/github
Content type: application/json
Secret: <your GITHUB_WEBHOOK_SECRET, or the per-integration secret>
Events: Pull requests
```

Inbound deliveries are verified with HMAC-SHA256 against
`X-Hub-Signature-256`. The webhook route is exempt from `X-API-Key` (external
callers cannot send it) but is authenticated by the signature.

GitHub Enterprise Server: set `GITHUB_API_URL=https://<host>/api/v3`.

---

## 3. Connecting GitLab

1. Create a Personal (or Project) Access Token with `api` scope.
2. **Integrations → Connect a provider → GitLab**, paste the token.
3. Import projects by `namespace/project`.

### Webhook (GitLab)

Add a project webhook:

```
URL:   {PUBLIC_BASE_URL}/api/v1/webhooks/gitlab
Secret token: <your GITLAB_WEBHOOK_SECRET, or the per-integration secret>
Trigger: Merge request events
```

GitLab deliveries are authenticated by a constant-time comparison of the
`X-Gitlab-Token` header to the configured secret. Self-managed GitLab: set
`GITLAB_API_URL=https://<host>/api/v4`.

---

## 4. What happens on a pull/merge request

```
webhook → verify signature → dedup by delivery id → persist WebhookEvent
        → enqueue PR scan (Celery)
        → clone head @ changed files → run only affected scanners (incremental)
        → compare vs the latest completed base scan (new vs existing)
        → risk + readiness (Phase 1 engines), honoring baselines/suppressions
        → policy evaluation → gate (pass | warning | fail)
        → PR feedback: one reconciled summary comment + commit status
        → notification dispatch (best-effort)
```

- Only **new** findings (not already present on the base branch) drive the gate.
- Baselines/suppressions are honored, exactly as in Phase 1.
- The summary comment is **reconciled**: it is updated in place on each new
  commit, never duplicated.
- PR feedback and notifications are **best-effort** — a provider/API error there
  never changes the fact that the scan completed.

---

## 5. Policy-as-code

Policies are YAML, parsed with a safe loader (no code execution). Each rule
matches findings by condition and declares an action.

```yaml
version: 1
name: production-gate
description: Block merges that introduce critical/high risk.
rules:
  - id: no-critical
    condition:
      severity: critical
    action: fail
  - id: no-new-high
    condition:
      severity: high
      is_new: true          # only findings not already on the base branch
    action: fail
  - id: warn-secrets
    condition:
      scanner: gitleaks
    action: warn
```

### Supported conditions

| Key             | Meaning                                                        |
| --------------- | -------------------------------------------------------------- |
| `severity`      | One value or a list: `critical`, `high`, `medium`, `low`.      |
| `min_risk_score`| Minimum deterministic risk score (0–100).                      |
| `rule_id`       | Match a specific rule id (or list).                            |
| `scanner`       | Match a scanner (e.g. `gitleaks`, `docker-rules`).             |
| `category`      | Finding category.                                              |
| `confidence`    | `low` / `medium` / `high`.                                     |
| `path`          | Glob (`*.tf`) or substring match on the file path.             |
| `is_new`        | `true` to match only findings new in this PR.                  |
| `environment`   | Restrict the rule to named environments.                       |

### Actions and the gate

- `fail` + at least one match → overall **fail** (blocking commit status).
- `warn` + at least one match → **warning** (visible, non-blocking).
- otherwise → **pass**.

### Assigning policies

- **Global**: applies to every repository (Policies → *Set global*).
- **Per-repository**: pick a policy in the Integrations repositories table.
- Repository assignment wins over the global one. With no policy assigned, a
  built-in default gate applies (new critical/high → fail, new medium → warning).

Policies are versioned: every edit creates a new immutable version.

---

## 6. CLI & CI/CD

The same deterministic engine runs locally and in CI via the `devops-auditor`
CLI (no DB or network required). See `docs/ci-examples/` for ready-to-use
GitHub Actions, GitLab CI, and Jenkins pipelines.

```bash
devops-auditor scan .                      # human-readable
devops-auditor scan . --format sarif -o out.sarif
devops-auditor policy check . --policy production-gate.yaml
devops-auditor sbom . --output sbom.json   # CycloneDX
devops-auditor check --changed             # only files changed vs HEAD
```

Exit codes: `0` clean, `1` security/policy failure (fail the build), `2`
runtime/config error.

---

## 7. Notifications

Create channels in **Notifications**. Supported types: **Slack**, **Microsoft
Teams**, **Webhook**, **Email**. Each channel subscribes to one or more events:

`scan_completed`, `scan_failed`, `critical_finding`, `secret_detected`,
`policy_failed`, `pr_scan_failed`, `readiness_decreased`, `new_vulnerability`,
`remediation_completed`.

- Channel config (webhook URLs, SMTP recipients) is stored **encrypted** and
  returned **masked** by the API.
- Outbound webhook/Slack/Teams URLs pass an **SSRF guard**: private/loopback/
  link-local destinations are refused (unless
  `NOTIFICATIONS_ALLOW_PRIVATE_HOSTS=true`, intended for tests only).
- Delivery is best-effort and recorded (`sent` / `failed`) under
  **Notifications → Recent deliveries**. A delivery failure never fails a scan.

Email requires SMTP settings (`SMTP_HOST`, …). See `.env.example`.

---

## 8. Audit log

Sensitive, state-changing actions are recorded in an append-only audit log
(**Audit Log** page / `GET /api/v1/audit-logs`): integration connect/disconnect,
policy create/update/delete/assign, notification channel create/delete.

Secrets are **never** recorded — the audit writer redacts any field whose name
looks like a secret (token, secret, password, url, key, credential,
authorization) before persisting.

---

## 9. Security model summary

- **Token storage**: Fernet (AES-128-CBC + HMAC) via `INTEGRATION_ENCRYPTION_KEY`;
  tokens never returned by the API.
- **Webhook auth**: GitHub HMAC-SHA256 signature; GitLab constant-time token
  compare; oversized bodies rejected (`WEBHOOK_MAX_BODY_BYTES`); deliveries
  de-duplicated by delivery id (replay protection).
- **SSRF**: notification destinations and git clone URLs are validated against
  private/loopback ranges.
- **API auth**: optional global `X-API-Key` on `/api/v1/*` (webhooks exempt,
  authenticated by signature instead).

### Known limitations

- Single-tenant: no per-user accounts, no OAuth login, no per-repo ownership.
  Token (PAT) connect only; OAuth App / GitHub App installation is future work.
- New tables are created via `create_all` (no Alembic migrations yet).
