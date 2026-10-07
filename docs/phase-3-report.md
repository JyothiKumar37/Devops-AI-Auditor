# DevOps AI Auditor — Phase 3 Report

**Phase:** 3 — Advanced Agentic AI & Intelligent Investigation
**Core principle upheld:** the deterministic scanner/policy/risk engine remains the
single source of truth. Every AI output is optional, read-only, evidence-grounded,
clearly labeled as AI analysis, and never overrides a deterministic finding,
severity, score, policy result, or gate.

---

## 1. Features implemented

- **Controlled tool framework** — a read-only tool registry the LLM must go through (no DB/shell/code access).
- **Agentic investigation engine** — a bounded LangGraph ReAct loop (plan → select tool → gather evidence → synthesize).
- **Evidence + confidence + hallucination safeguards** — citations verified against genuinely-retrieved data; deterministic confidence; insufficient-evidence path.
- **Root-cause / cross-finding / historical reasoning** — deterministic clustering tool + scan diff/history tools.
- **Natural-language investigation** — scan-, finding-, and repository-scoped entrypoints via structured tool calls (no NL-to-SQL).
- **AI remediation planner** — proposed, estimate-labeled plan grounded in real findings; requires approval; never mutates.
- **AI-assisted PR review** — optional, advisory PR notes; never affects the gate.
- **AI security review agent** — targeted, non-authoritative security second-opinion.
- **Investigation sessions** — persisted investigations with evidence + safe execution trace; history + reopen.
- **Investigation UI** — scan-scoped "Investigate" tab (answer, confidence, evidence citations, "how the agent investigated this" trace, remediation plan, security review, history).
- **AI evaluation framework** — repeatable golden-case + security test harness.

## 2. Architecture changes

A new, self-contained AI layer under `backend/agents/investigation/` sits ALONGSIDE
the deterministic engine. It never writes domain data. New services
(`investigation_service`, `remediation_plan_service`, `ai_pr_review_service`,
`ai_security_review_service`) wrap it and are exposed under `/api/v1/ai/*`. The
existing Phase 1/2 code (scanners, risk, posture, diff, PR scan, policy) is reused
unchanged as the authoritative data source and is only ever *read* by tools.

## 3. AI agent architecture

```
User question
   -> InvestigationService (scope: scan | finding | repository)
   -> InvestigationEngine (LangGraph)
        understand_intent -> agent_decide --(call_tool)--> execute_tool --+
                                   |  (final)                             |
                                   v              <-----------------------+
                              synthesize -> verify citations -> confidence -> result
   -> AIInvestigation (persisted: answer, citations, evidence, trace)
```

- The model only chooses *which registered tool to call next* (structured JSON); it never receives DB/shell access.
- The loop is hard-bounded (max 8 tool calls, recursion limit 40, evidence char budget).
- With no LLM configured, the engine returns a deterministic, tool-only result.

## 4. Tools created

All tools are **READ-only**, validate arguments (Pydantic, extra fields forbidden),
enforce scan-scope authorization, bound/paginate results, neutralize untrusted text,
and redact secrets. Registry: `agents/investigation/tools/`.

| Tool | Purpose | Inputs | Outputs | Authz | Security restrictions |
|---|---|---|---|---|---|
| `get_scan_summary` | High-level scan overview | scan_id | repo, status, readiness, severity/category counts, posture, recommendations | READ + scan scope | reuses deterministic posture; bounded |
| `get_scan_history` | Repository trend over scans | scan_id, limit≤30 | readiness/severity trend points | READ + scope | bounded |
| `get_findings` | List findings (filtered, paged) | scan_id, severity?, category?, scanner?, limit≤50, offset | finding dicts + totals | READ + scope | enum-validated filters; redacted |
| `get_finding` | One finding in full | scan_id, finding_id | finding detail | READ + scope | evidence secret-redacted |
| `get_related_findings` | Deterministically related findings | scan_id, finding_id, limit≤50 | findings + relation reasons | READ + scope | bounded |
| `get_root_cause_groups` | Themed root-cause clusters | scan_id | groups (theme, finding_ids, files, severities) | READ + scope | deterministic clustering |
| `get_posture` | Authoritative posture/readiness | scan_id | overall/domain scores, weak areas | READ + scope | reuses Phase 1 engine |
| `get_risk_summary` | Per-finding risk ranking | scan_id, limit≤50 | risk score + priority + signals | READ + scope | deterministic risk |
| `get_scan_diff` | New vs fixed vs unchanged | scan_id, base_scan_id? | summary, severity deltas, readiness delta | READ + scope (both scans) | trimmed/neutralized |
| `get_file` | Bounded file slice | scan_id, path, start_line?, end_line? | numbered, secret-redacted lines | READ + scope | ≤400 lines, per-line redaction |
| `search_repository` | Substring search over stored files | scan_id, query, limit≤50 | path/line/text matches | READ + scope | bounded + redacted |

Write/remediation capabilities are modeled as a separate `REMEDIATION` permission
that is **never granted** to the autonomous loop (reserved for human-approved flows).

## 5. Database changes

One new table (created via `create_all`, no existing table altered):
- `ai_investigations` — persisted investigation sessions (scope, scan_id, finding_id, repository_name, question, answer, root_cause, impact, confidence, label, recommendations/citations/evidence/trace JSON, ai_used, tool_calls, hallucination_guard_triggered, created_at). Indexed by (scan_id, created_at) and (repository_name, created_at).

## 6. API changes

New router `api/v1/endpoints/investigations.py` (prefix `/api/v1/ai`):
- `POST /ai/scans/{scan_id}/investigate`
- `POST /ai/scans/{scan_id}/findings/{finding_id}/investigate`
- `POST /ai/repository/investigate`
- `GET  /ai/investigations` (history list; filter by scan_id/repository)
- `GET  /ai/investigations/{id}` (reopen with full evidence + trace)
- `POST /ai/scans/{scan_id}/remediation-plan`
- `POST /ai/pull-requests/{pr_id}/review`
- `POST /ai/scans/{scan_id}/security-review`

Existing Phase 1/2 AI endpoints (`/scans/.../explain|fix-suggestion|triage|ask|chat`,
`/health/llm`, `/settings/llm`) are unchanged and reused.

## 7. Frontend changes

- `types/api.ts`: investigation/remediation/review types.
- `lib/api.ts`: investigate (scan/finding/repo), list/get investigations, remediation plan, PR review, security review.
- `hooks/useInvestigation.ts`: React Query hooks.
- `pages/AIInvestigation.tsx`: scan-scoped investigation UI — question box + suggestions, answer with confidence badge, root cause, recommendations, clickable evidence citations, "How the agent investigated this" trace panel (safe, high-level — no chain-of-thought), remediation-plan generator, AI security review, and investigation history.
- Wired as an **"Investigate"** tab in the scan layout + route `/scans/:scanId/investigate`.

## 8. LangGraph changes

New `agents/investigation/engine.py` builds a dedicated `StateGraph`
(`InvestigationState`) separate from the existing linear reasoning graph. Unlike the
reasoning graph, it has a **conditional edge** forming a bounded agentic loop
(`agent_decide` → `execute_tool` → `agent_decide`), compiled and run with `ainvoke`
and an explicit recursion limit. The synchronous LLM provider is called via
`asyncio.to_thread`.

## 9. Security protections

- Tools are read-only; no `execute_sql`, shell, or code-execution tool exists.
- Scan-scope authorization: a tool call for a scan outside the investigation's authorized set is rejected (`unauthorized`).
- Argument validation (Pydantic, `extra=forbid`) rejects malformed/unknown args.
- Result bounding/pagination prevents unbounded data egress.
- Remediation requires explicit approval; AI never applies changes.
- AI review items are `source=AI_REVIEW`, `authoritative=False` — they never fail CI/policy/gates.
- AI failures are swallowed/degraded; they never break deterministic scanning.

## 10. Prompt-injection protections

Repository content is treated as untrusted DATA. Reused `agents/reasoning/sanitize.py`:
a hardened `guardrail_system` prompt (declares tool output untrusted, instructs the
model to ignore embedded directives, never reveal the system prompt), `wrap_untrusted`
sentinel delimiters around all tool-provided content, and `neutralize` (strips control/
zero-width chars, defuses delimiter spoofing, truncates). The structural backstop is the
citation verifier (§3) — even a fully hijacked model cannot introduce fabricated findings
or files into the result.

## 11. Secret-redaction implementation

`agents/investigation/redaction.py` `redact_secrets()` runs at the **tool boundary**
before any content reaches the LLM. It masks AWS keys, GitHub/GitLab/Slack/OpenAI/Google
tokens, JWTs, PEM private-key blocks, `key=value` secrets, and URL-embedded credentials
→ `[REDACTED]`. Applied in `get_file`, `search_repository`, and finding evidence
projection. Tests assert no secret appears in the evidence corpus the model sees.

## 12. AI evaluation framework

`tests/test_ai_eval.py` is a repeatable, network-free harness over a golden scenario
(k8s deployment missing limits + an injected/secret file). It evaluates behaviourally
(not "sounds good"):
- finding/file citation correctness (cited refs must be genuinely retrieved);
- hallucination rate (fabricated citations dropped);
- tool selection (the correct tool was actually invoked);
- secret redaction (no secret in the evidence corpus);
plus security assertions: prompt injection neutralized, compromised model cannot
leak/fabricate, unauthorized scan access blocked, arbitrary tool abuse blocked.

## 13. Tests

New Phase-3 test files: `test_investigation_tools.py` (15), `test_investigation_engine.py`
(4), `test_investigation_safeguards.py` (5), `test_investigation_correlation.py` (4),
`test_investigation_api.py` (8), `test_remediation_planner.py` (3), `test_ai_pr_review.py`
(3), `test_ai_security_review.py` (3), `test_ai_eval.py` (7). Total: **52 new tests**.

## 14. Test results

- Phase-3 suites: all green (per-milestone ruff + mypy clean; 181 source files type-checked).
- Full regression (Phase 1 + 2 + 3): **677 passed, 0 failed** (`pytest -q`, ~41.5 min). The 52 new Phase-3 tests pass and no Phase 1/2 test regressed.
- Frontend: `npm run build` (tsc + vite) and `npm run lint` (`--max-warnings 0`) both pass.
- `docker-compose.yml`: validated as well-formed YAML (Docker not installed in this environment; run `docker compose config` in yours to confirm).

## 15. Environment variables

Reuses existing `LLM_PROVIDER` / `LLM_API_KEY` / `LLM_MODEL` / `LLM_BASE_URL` /
`LLM_TEMPERATURE` / `LLM_TIMEOUT`. New Phase-3 flags (both optional, default off/safe):
- `AI_PR_REVIEW_ENABLED` (default `false`) — append advisory AI review to PR comments.
- `AI_REVIEW_MAX_ITEMS` (default `8`) — cap on AI review items.
Added to `.env.example` and wired into the `backend` and `worker` services in
`docker-compose.yml`.

## 16. Performance considerations

- The agent never sends the whole repository to the LLM; it retrieves only bounded, needed evidence.
- Hard caps: ≤8 tool calls, recursion limit 40, ≤7000-char evidence budget, bounded tool outputs.
- Synchronous LLM calls run via `asyncio.to_thread` so they don't block the event loop.
- With AI disabled the engine does deterministic tool-only work (no model calls).

## 17. Known limitations

- Investigations run in-request (bounded); offloading long investigations to Celery is future work.
- Single-tenant authorization (consistent with Phase 1/2): scan-scope enforced, but no per-user ownership.
- Multi-turn "continue this investigation" memory is not yet implemented (each investigation is standalone, though persisted).
- AI review/security-review quality depends on the configured model; items are advisory by design.
- Golden evaluation uses seeded scenarios rather than full on-disk sample repositories.

## 18. Manual testing instructions

1. Run a scan (upload a ZIP or connect a repo) and open it.
2. Open the **Investigate** tab. With no LLM configured you still get deterministic,
   tool-grounded answers; set `LLM_PROVIDER` + `LLM_API_KEY` to enable full agentic answers.
3. Ask e.g. "Why is the production readiness score low?" — verify the answer cites real
   findings/files, shows a confidence badge, and the trace lists the tools used.
4. Click **Propose remediation plan** — verify it lists real findings, an estimated score
   delta (labeled an estimate), and "requires approval".
5. Click **AI security review** — verify advisory, file-grounded items.
6. `GET /api/v1/ai/investigations?scan_id=<id>` — verify history; reopen one by id.
7. Negative checks: a question that forces no evidence returns the explicit
   "insufficient evidence" message; investigations never alter findings/scores.

## 19. Recommended Phase 4

- Multi-turn investigation memory + follow-up questions with retained scoped context.
- Celery-offloaded long investigations with streamed progress (reuse the SSE pattern).
- Vulnerability intelligence: correlate SBOM/dependencies against live CVE feeds.
- AI usage dashboard + per-user/project cost controls and token accounting.
- Optional, explicit "AI review gate" (opt-in, clearly probabilistic) for teams that want it.
- Expand the golden evaluation to on-disk sample repositories with regression thresholds.
