# DevOps AI Auditor — Phase 4 Report

**Phase:** 4 — Cloud Runtime Intelligence, IaC Drift & Compliance
**Core principles upheld:**
- **Read-only by default.** Every cloud interaction is a `Describe*`/`List*`/`Get*`
  call. Write/remediation is gated behind `CLOUD_WRITE_ENABLED` (default `false`)
  and still requires per-action human approval — nothing in Phase 4 mutates AWS.
- **No stored AWS keys.** Accounts are connected via STS `AssumeRole`. The platform
  never persists long-lived access keys; it holds only short-lived assumed
  credentials in memory for the duration of a sync.
- **No secrets to the LLM.** Cloud tools return metadata only, secret-redacted at the
  tool boundary. Access keys, session tokens, SSM/Secrets Manager values, and the
  account external id are never sent to the model.
- **Phases 1–3 unchanged.** The deterministic repo scanner/risk/posture/policy engine
  and the Phase 3 agentic layer are reused, not modified. Cloud is a new, additive
  subject (an *account*) alongside the existing subject (a *scan*).

---

## 1. Features implemented

Cloud (AWS) runtime intelligence across discovery, security posture, network exposure,
IaC drift, Kubernetes correlation, compliance, change monitoring, and AI investigation:

- **AWS account onboarding (STS AssumeRole)** — connect/validate/disconnect read-only
  accounts; external id stored Fernet-encrypted; account id derived from AWS, not trusted
  from the request.
- **Multi-service asset discovery** — EC2, S3, RDS, ELB/ELBv2, VPC (incl. subnets, route
  tables, internet gateways, security groups), EKS, Lambda, ECR, IAM. Regional + global
  services, bounded concurrency.
- **Deterministic cloud security rules** — 13 checks across SG/EC2/S3/RDS/IAM/EKS,
  producing cloud findings with severity, evidence, recommendation, and compliance tags.
- **Cloud security posture** — reuses the Phase 1 scoring engine over cloud/network/iam
  domains; account-scoped so repo posture is never perturbed.
- **Network exposure graph + attack surface** — evidence-backed directed edges only
  (route-table→IGW, instance→subnet/SG, public IP, internet-facing LB, public RDS, public
  EKS endpoint); internet-facing attack-surface summary.
- **IaC drift (Terraform ↔ live AWS)** — correlate a repo scan's Terraform against the
  account's discovered state: `IN_SYNC` / `DRIFTED` / `NOT_MANAGED` / `UNKNOWN`, with
  attribute-level differences.
- **EKS ↔ Kubernetes correlation** — end-to-end path Terraform → AWS EKS → K8s workloads
  → services → internet, reusing the repo scan's `correlation_index`.
- **Compliance engine** — CIS AWS Foundations controls assessed from deterministic cloud
  findings (`PASS`/`FAIL`/`NOT_APPLICABLE`/`NOT_ASSESSED`), with time-limited exceptions.
- **Change detection** — diffs successive syncs; flags risk-significant changes
  (exposure→public, new world-open admin/db port, RDS public flip). First sync = baseline.
- **Cloud AI investigation** — account-scoped agentic investigation reusing the Phase 3
  engine with 9 new read-only, secret-redacted cloud tools.
- **Scheduled synchronization** — optional Celery-beat periodic sync of all accounts.
- **Cloud UI** — a full "Cloud" section (accounts, overview/posture, assets, findings,
  network, drift, compliance, changes, EKS, investigate).

## 2. Architecture changes

A new cloud layer is added **alongside** the existing engine, reusing its primitives:

- `backend/services/aws/` — low-level AWS access and intelligence: `client.py` (STS
  AssumeRole factory + role-arn validation), `resources.py` (DTOs + tag helpers),
  `discovery.py` (per-service discovery + `discover_all`), and `rules/` (deterministic
  cloud rule engine + registry).
- `backend/services/cloud_*_service.py` + `services/compliance/` — orchestration services
  (account, discovery, posture, graph, drift, kubernetes, compliance) consumed by the API.
- `backend/models/cloud.py` — dedicated cloud tables (see §5).
- `backend/agents/investigation/tools/cloud_tools.py` — cloud tools registered into the
  existing Phase 3 tool registry; the investigation engine is reused unchanged.
- `backend/workers/cloud_tasks.py` — Celery tasks for sync + scheduled sync-all.

The deterministic finding **architecture** is reused (RuleFinding-style DTOs, enums,
`services.posture.assess_posture`, finding fingerprints) but cloud findings live in a
dedicated table (see Decision in §17), because the repo `Finding` table is tied to a
`scan_id`/file and cannot be account-scoped without altering a Phase 1 model.

## 3. Cloud security model (how access works)

```
Platform identity (ECS task role / EC2 instance profile / local AWS creds)
    -- sts:AssumeRole (role_arn + optional external_id) -->
Short-lived assumed credentials (in memory only, 900-3600s)
    -- Describe*/List*/Get* only -->
Discovered metadata -> deterministic rules/posture/graph/drift/compliance
```

- `verify()` derives the AWS account id from the AssumeRole response's
  `AssumedRoleUser.Arn` (no second `get_caller_identity` call needed).
- `external_id` is stored Fernet-encrypted (`encrypted_external_id`); `role_arn` is stored
  in plaintext (it is not a secret and is shown in the UI).
- Role ARNs are validated (`validate_role_arn`) before any STS call.

## 4. Deterministic cloud rules

All rules are pure functions over discovered metadata (no network calls at evaluation
time). Registry: `services/aws/rules/`.

| Rule | Service | Title | Default severity area |
|---|---|---|---|
| `AWS-SG-001` | ec2 | Security group exposes an admin port to the internet | network |
| `AWS-SG-002` | ec2 | Security group exposes a database port to the internet | network |
| `AWS-SG-003` | ec2 | Security group allows all ports from the internet | network |
| `AWS-EC2-001` | ec2 | EC2 instance does not enforce IMDSv2 | cloud |
| `AWS-S3-001` | s3 | S3 bucket is publicly accessible | cloud |
| `AWS-S3-002` | s3 | S3 bucket has no default encryption | cloud |
| `AWS-RDS-001` | rds | RDS instance is publicly accessible | cloud |
| `AWS-RDS-002` | rds | RDS storage is not encrypted | cloud |
| `AWS-RDS-003` | rds | RDS automated backups are disabled | cloud |
| `AWS-IAM-001` | iam | IAM user has no MFA device | iam |
| `AWS-IAM-002` | iam | IAM role trusts any principal (wildcard) | iam |
| `AWS-EKS-001` | eks | EKS API endpoint is public to the internet | network |

## 5. Database changes

New tables (created via `create_all`; **no existing table altered**), in
`models/cloud.py`, registered in `models/__init__.py` and `core/database.py`:

- `cloud_accounts` — connected account (provider, name, verified account_id, role_arn,
  **encrypted_external_id**, regions, status, status_detail, last_synced_at).
- `cloud_snapshots` — one row per sync (status, regions, asset/finding counts, error).
- `cloud_assets` — discovered resources (service, resource_type, resource_id, arn, name,
  region, state, **exposure**, tags, attributes, first/last-synced timestamps).
- `cloud_relationships` — derived, evidence-backed network edges.
- `cloud_findings` — deterministic cloud security findings (dedicated table — see §17).
- `cloud_drift` — Terraform↔AWS drift records (status, expected, actual, differences).
- `cloud_changes` — detected changes between syncs (change_type, detail, risk_significant).
- `compliance_exceptions` — time-limited exceptions (framework, control_id, resource_id,
  reason, owner, approved_by, expires_at).

## 6. API changes

New router `api/v1/endpoints/cloud.py` (prefix `/api/v1/cloud`):

| Method & path | Purpose |
|---|---|
| `POST /cloud/accounts` | Connect an AWS account (STS AssumeRole, read-only) |
| `GET /cloud/accounts` | List connected accounts |
| `GET /cloud/accounts/{id}` | Get one account |
| `POST /cloud/accounts/{id}/validate` | Re-validate role access |
| `DELETE /cloud/accounts/{id}` | Disconnect |
| `POST /cloud/accounts/{id}/sync` | Discover resources (snapshot) |
| `GET /cloud/accounts/{id}/assets` | List assets (filter: service/region/exposure) |
| `GET /cloud/assets/{asset_id}` | Get one asset |
| `GET /cloud/accounts/{id}/findings` | List cloud findings |
| `GET /cloud/accounts/{id}/posture` | Cloud posture (cloud/network/iam) |
| `GET /cloud/accounts/{id}/network` | Network exposure graph |
| `GET /cloud/accounts/{id}/attack-surface` | Internet-facing attack surface |
| `GET /cloud/accounts/{id}/assets/{rid}/relationships` | Relationships for a resource |
| `POST /cloud/accounts/{id}/drift` | Correlate a scan's Terraform vs live AWS |
| `GET /cloud/accounts/{id}/drift` | List stored drift |
| `GET /cloud/accounts/{id}/changes` | List detected changes (`risk_only` filter) |
| `GET /cloud/compliance/frameworks` | List supported frameworks |
| `GET /cloud/accounts/{id}/compliance/{framework}` | Assess against a framework |
| `POST /cloud/accounts/{id}/compliance/exceptions` | Create an exception |
| `GET /cloud/accounts/{id}/compliance/exceptions` | List exceptions |
| `DELETE /cloud/compliance/exceptions/{id}` | Delete an exception |
| `GET /cloud/accounts/{id}/eks-correlation` | EKS↔Terraform↔K8s correlation |

Plus the cloud AI entrypoint in the Phase 3 router:
- `POST /api/v1/ai/cloud/accounts/{account_id}/investigate`

## 7. Frontend changes

- `types/api.ts`: cloud account/asset/finding/posture/network/drift/compliance/change/EKS types.
- `lib/api.ts`: cloud accounts (CRUD + validate + sync), assets, findings, posture, network,
  attack-surface, drift (list + correlate), compliance (frameworks/assess/exceptions),
  changes, EKS correlation, and `investigateCloud`.
- `hooks/useCloud.ts`: React Query hooks for all of the above.
- New pages under `pages/Cloud*.tsx`:
  - `CloudAccounts` — connect form (role ARN + external id + regions) and account list.
  - `CloudLayout` — account header with "Sync now" + tabbed sub-navigation.
  - `CloudOverview` — posture score, severity/service breakdown, domains, top risks.
  - `CloudAssets` — filterable discovered-resource table (service/exposure).
  - `CloudFindings` — severity-filtered findings with evidence + compliance tags.
  - `CloudNetwork` — internet-exposure paths + relationship table + attack-surface stats.
  - `CloudDrift` — scan picker + correlate action + drift records with attribute diffs.
  - `CloudCompliance` — framework picker, control results, pass rate, exceptions.
  - `CloudChanges` — change feed with risk-significant filter.
  - `CloudEks` — EKS cluster correlation path (Terraform → AWS → K8s → internet).
  - `CloudInvestigate` — account-scoped AI investigation (answer, confidence, evidence,
    "how the agent investigated this" trace).
- Wired a **"Cloud"** item into the app shell nav and `/cloud` + `/cloud/:accountId/*` routes.

## 8. Cloud AI tools

9 read-only, bounded, secret-redacted tools (`agents/investigation/tools/cloud_tools.py`),
registered into the existing Phase 3 registry. Account scope is enforced via
`ctx.authorizes_account(account_id)`; `ToolContext.invoke()` rejects out-of-scope accounts.

| Tool | Purpose |
|---|---|
| `list_cloud_accounts` | List connected accounts (ids/provider/status), no secrets |
| `get_cloud_assets` | List discovered AWS resources (metadata), filterable |
| `get_cloud_resource` | Full metadata for one resource (secret-redacted) |
| `get_cloud_findings` | Deterministic cloud findings (severity-sorted) |
| `get_cloud_posture` | Cloud/network/iam domain scores |
| `get_network_graph` | Network exposure nodes + evidence-backed edges |
| `get_iam_analysis` | IAM findings + user/role summary (no secret values) |
| `get_drift` | Terraform-vs-AWS drift records |
| `get_compliance_status` | Compliance assessment for an account + framework |

Cloud metadata is additionally run through recursive `_redact()` + `neutralize()` before
reaching the model (defence in depth on top of the Phase 3 safeguards).

## 9. Compliance engine

- Framework: **CIS AWS Foundations** (`CIS_AWS`, 11 controls) assessed from deterministic
  cloud findings. (`NIST`, `SOC2`, `PCI_DSS` labels are reserved as future mappings.)
- Statuses: `PASS` (applicable, assessed, no non-excepted findings), `FAIL` (has findings),
  `NOT_APPLICABLE` (no assets of the control's services), `NOT_ASSESSED` (account never
  synced — we never claim compliance from absence of data).
- Exceptions: stored with reason (`accept_risk` / `false_positive` / `not_applicable` /
  `compensating_control`), owner, and optional `expires_at` (expired exceptions ignored).
- Every assessment carries a disclaimer: it is evidence-based, **not a certification**.

## 10. Change detection & monitoring

- Diffs the current sync's assets against the previous snapshot. The **first sync is a
  baseline** (no changes emitted).
- Records added/removed/modified resources; marks `risk_significant` only on genuinely
  elevated transitions (exposure→public, a newly world-open admin/DB port, an RDS
  public-accessibility flip) to avoid alert fatigue.
- Optional scheduled re-sync via Celery beat (`AWS_SYNC_INTERVAL_HOURS`, 0 disables),
  which also feeds a `cloud_change` notification event into the existing Phase 2
  notification layer.

## 11. Security protections

- Read-only AWS access; write path gated by `CLOUD_WRITE_ENABLED` (default off) **and**
  per-action approval. No Phase 4 code path mutates AWS.
- STS AssumeRole only; no long-lived keys stored. Short-lived creds held in memory.
- External id stored Fernet-encrypted; never returned by the API.
- Account-scope authorization on every cloud tool call (`authorizes_account`).
- Cloud tools return metadata only, secret-redacted at the boundary; no SSM/Secrets
  Manager/parameter values are fetched or exposed.
- Account id is AWS-verified (from the AssumeRole response), not trusted from the client.
- Role ARN validated before use. All reused Phase 3 safeguards (argument validation,
  result bounding, prompt-injection neutralization, citation verification) still apply.

## 12. Prompt-injection & secret-redaction

Reuses the Phase 3 hardened guardrail prompt, untrusted-content wrapping, and
`neutralize()` over all tool output. Cloud tool output is additionally passed through a
recursive `_redact()` that masks any secret-looking strings in nested metadata. The
citation verifier remains the structural backstop: a hijacked model still cannot fabricate
findings/resources that were not genuinely retrieved.

## 13. Database migration note

New tables are created idempotently via SQLAlchemy `create_all`. No existing table is
altered, so there is no destructive migration. On an existing SQLite dev DB the new tables
appear automatically on startup; on Postgres the same `create_all` path applies.

## 14. Tests

New Phase-4 test files (9), using `botocore.stub.Stubber` (no live AWS, no `moto`):

| File | Tests | Covers |
|---|---|---|
| `test_cloud_accounts.py` | 8 | STS AssumeRole, verify, connect/validate/delete, encryption |
| `test_cloud_discovery.py` | 6 | Multi-service discovery + asset persistence |
| `test_cloud_rules.py` | 12 | All 13 deterministic rules + posture |
| `test_cloud_graph.py` | 5 | Network edge derivation + attack surface |
| `test_cloud_drift.py` | 6 | Terraform↔AWS correlation statuses |
| `test_cloud_kubernetes.py` | 2 | EKS↔K8s correlation |
| `test_cloud_compliance.py` | 6 | CIS assessment + exceptions |
| `test_cloud_ai.py` | 6 | Cloud AI tools + account-scope enforcement |
| `test_cloud_changes.py` | 6 | Change detection + risk-significance |

**Total: 57 new Phase-4 tests.**

## 15. Test results

- Per-milestone gate (all green): `ruff check --fix`, `mypy .` (204 source files, no
  issues), and the milestone's `pytest` file.
- Full regression (Phase 1 + 2 + 3 + 4): see the "Verification" summary accompanying this
  change. The 57 new Phase-4 tests pass and no Phase 1/2/3 test regressed.
- Frontend: `npm run build` (tsc + vite) and `npm run lint` (`eslint --max-warnings 0`)
  both pass.
- `docker-compose.yml`: validated as well-formed YAML (Docker not installed in this
  environment; run `docker compose config` in yours to confirm).

## 16. Environment variables

New Phase-4 settings (all optional; defaults are production-safe). Added to `.env.example`
and wired into the `backend` and `worker` services in `docker-compose.yml`:

| Variable | Default | Purpose |
|---|---|---|
| `AWS_STS_REGION` | `us-east-1` | Region used for the STS AssumeRole handshake |
| `AWS_ROLE_SESSION_NAME` | `devops-ai-auditor` | Session name (appears in CloudTrail) |
| `AWS_ASSUME_ROLE_DURATION` | `3600` | Lifetime (s) of assumed credentials |
| `AWS_DEFAULT_REGIONS` | `us-east-1` | Default regions when an account specifies none |
| `AWS_MAX_CONCURRENCY` | `4` | Max concurrent AWS calls per sync |
| `AWS_SYNC_INTERVAL_HOURS` | `6` | Scheduled sync interval (0 disables) |
| `CLOUD_WRITE_ENABLED` | `false` | Enable cloud write/remediation (still needs approval) |

The platform's own base identity for `sts:AssumeRole` comes from the task role / instance
profile in AWS; for local Docker, standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` / `AWS_REGION` are passed through. **No per-account keys are ever
stored** — only short-lived assumed credentials.

## 17. Known limitations & key decisions

Limitations:
- Compliance report is JSON only (via the assessment endpoint). HTML/PDF export is deferred.
- One framework (CIS AWS) is implemented; NIST/SOC2/PCI are reserved labels.
- Network graph is rendered as exposure paths + a relationship table (no force-directed
  canvas yet).
- AWS coverage is the core services listed in §1; additional services are additive future work.
- Single-tenant authorization (consistent with Phases 1–3): account-scope enforced, no
  per-user ownership.

Key decisions:
- **Dedicated `CloudFinding` table** (not the repo `Finding` table): repo findings require
  a non-nullable `scan_id` tied to a file, and `create_all` cannot add account-scope columns
  to an existing table. We reuse the finding *architecture*, not the table.
- **Account-scoped posture** reusing `assess_posture`: cloud domains are applicable only
  when cloud findings exist, so repo scans are unaffected.
- **`verify()` derives account id from the AssumeRole response** rather than a second
  `get_caller_identity` call (which would need a real STS client on the assumed session and
  be un-stubbable in tests).
- **Change detection skips the first sync** (baseline) and flags only risk-significant
  transitions, rather than every diff.

## 18. Manual testing / AWS setup instructions

### A. Create a read-only IAM role in the target AWS account

1. In the target account, create an IAM **role** (e.g. `DevOpsAuditorReadOnly`).
2. **Trust policy** — allow the platform's identity to assume it, with an external id:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "AWS": "arn:aws:iam::<PLATFORM_ACCOUNT_ID>:root" },
       "Action": "sts:AssumeRole",
       "Condition": { "StringEquals": { "sts:ExternalId": "<YOUR_EXTERNAL_ID>" } }
     }]
   }
   ```
   (Scope the `Principal` down to the exact task/instance role ARN in production.)
3. **Permissions** — attach the AWS managed `ReadOnlyAccess` policy, or a minimal
   read-only policy covering the discovered services:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "ec2:Describe*",
         "s3:GetBucket*", "s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration",
         "rds:Describe*",
         "elasticloadbalancing:Describe*",
         "eks:Describe*", "eks:List*",
         "lambda:List*", "lambda:GetFunction*",
         "ecr:Describe*",
         "iam:List*", "iam:GetAccountSummary", "iam:GetRole", "iam:GetLoginProfile"
       ],
       "Resource": "*"
     }]
   }
   ```
   All of these are read-only. No write/delete permissions are needed or requested.

### B. Ensure the platform can assume the role

- In AWS: the platform's task role / instance profile must allow `sts:AssumeRole` on the
  target role ARN.
- Locally: export `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN`
  if using temporary creds) for an identity allowed to assume the role.

### C. Connect, sync, and explore in the UI

1. Open **Cloud** in the left nav → **Connect an AWS account**. Enter the role ARN, the
   external id, and (optionally) regions. Submit — the account id is verified via AssumeRole.
2. On the account page, click **Sync now**. The first sync establishes a baseline.
3. **Overview** — review the posture score, severity/service breakdown, and top risk areas.
4. **Assets** — filter discovered resources by service/exposure.
5. **Findings** — review deterministic cloud findings with evidence + fixes.
6. **Network** — inspect internet-exposure paths and the relationship table.
7. **IaC Drift** — pick a completed scan containing Terraform and click **Correlate**;
   review `DRIFTED` / `NOT_MANAGED` records and attribute-level diffs.
8. **Compliance** — pick CIS AWS; review control pass/fail; add a time-limited exception
   on a failing control if accepted.
9. **Changes** — sync again after a change in AWS; verify the change (and any
   risk-significant flag) appears.
10. **EKS** — review the Terraform→AWS→Kubernetes→internet correlation path.
11. **Investigate** — ask e.g. "What is exposed to the internet?"; verify the answer cites
    real findings/resources and the trace lists the tools used.

Negative checks: with no base AWS identity, connect fails cleanly (502
`CloudConnectionError`); with `CLOUD_WRITE_ENABLED=false`, no write path is reachable;
cloud tools reject out-of-scope account ids.

## 19. Recommended Phase 5

- HTML/PDF compliance reports and scheduled compliance digests.
- Additional frameworks (NIST 800-53, SOC 2, PCI DSS) with explicit control mappings.
- Broader AWS coverage (CloudTrail, KMS, Secrets Manager config, GuardDuty findings import)
  and multi-cloud (Azure/GCP) via the same read-only, assume-identity pattern.
- A force-directed network graph canvas with drill-down from attack-surface to resource.
- Approved, auditable cloud remediation flows (guarded by `CLOUD_WRITE_ENABLED` + approval).
- Continuous drift monitoring with alerting on new drift between scheduled syncs.
- Per-account/project RBAC and multi-tenant ownership.
