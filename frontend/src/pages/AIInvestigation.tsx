import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import {
  useInvestigateScan,
  useInvestigations,
  useRemediationPlan,
  useSecurityReview,
} from "@/hooks/useInvestigation";
import { ApiError } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type { InvestigationResult, RemediationPlan } from "@/types/api";

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    high: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
    medium: "bg-amber-50 text-amber-700 ring-amber-600/20",
    low: "bg-slate-100 text-slate-600 ring-slate-300",
  };
  return <Badge className={map[confidence] ?? map.low}>confidence: {confidence}</Badge>;
}

function TracePanel({ result }: { result: InvestigationResult }) {
  const [open, setOpen] = useState(false);
  if (!result.trace.length) return null;
  return (
    <div className="mt-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-xs font-medium text-slate-500 hover:text-brand"
      >
        {open ? "▾" : "▸"} How the agent investigated this ({result.tool_calls} tool call
        {result.tool_calls === 1 ? "" : "s"})
      </button>
      {open ? (
        <ul className="mt-2 space-y-1 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs">
          {result.trace.map((step, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-slate-400">{step.kind === "tool" ? "✓" : "•"}</span>
              <span className="text-slate-600">
                {step.label}
                {step.tool ? <span className="ml-1 font-mono text-slate-400">[{step.tool}]</span> : null}
                {step.status && step.status !== "ok" ? (
                  <span className="ml-1 text-rose-500">({step.status})</span>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function ResultCard({ result }: { result: InvestigationResult }) {
  return (
    <Card className="p-5">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Badge className="bg-brand-50 text-brand-deep ring-brand-200">{result.label}</Badge>
        <ConfidenceBadge confidence={result.confidence} />
        {!result.ai_used ? (
          <Badge className="bg-slate-100 text-slate-500 ring-slate-300">AI disabled - deterministic</Badge>
        ) : null}
        {result.hallucination_guard_triggered ? (
          <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">unverifiable claims removed</Badge>
        ) : null}
      </div>

      <div className="prose prose-sm max-w-none whitespace-pre-wrap text-slate-700">{result.answer}</div>

      {result.root_cause ? (
        <div className="mt-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Root cause</h4>
          <p className="text-sm text-slate-700">{result.root_cause}</p>
        </div>
      ) : null}

      {result.recommendations.length ? (
        <div className="mt-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Recommended actions</h4>
          <ol className="mt-1 list-decimal space-y-0.5 pl-5 text-sm text-slate-700">
            {result.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ol>
        </div>
      ) : null}

      {result.citations.length ? (
        <div className="mt-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</h4>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {result.citations.map((c, i) => (
              <span key={i} className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600">
                {c.type === "finding" ? `finding ${(c.finding_id ?? "").slice(0, 8)}` : c.path}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <TracePanel result={result} />
    </Card>
  );
}

function RemediationPlanCard({ plan }: { plan: RemediationPlan }) {
  return (
    <Card className="p-5">
      <div className="mb-2 flex items-center gap-2">
        <Badge className="bg-violet-50 text-violet-700 ring-violet-600/20">{plan.label}</Badge>
        <Badge className="bg-slate-100 text-slate-600 ring-slate-300">risk: {plan.risk_level}</Badge>
        <Badge className="bg-amber-50 text-amber-700 ring-amber-600/20">requires approval</Badge>
      </div>
      <p className="text-sm font-medium text-slate-800">{plan.problem}</p>
      <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-700">
        {plan.steps.map((s) => (
          <li key={s.order}>
            {s.action}
            {s.file ? <span className="ml-1 font-mono text-[11px] text-slate-400">{s.file}</span> : null}
          </li>
        ))}
      </ol>
      <p className="mt-3 rounded-lg bg-amber-50 p-2 text-xs text-amber-800">
        Estimated readiness: {plan.estimated_score_before} → {plan.estimated_score_after} (
        {plan.estimated_score_delta >= 0 ? "+" : ""}
        {plan.estimated_score_delta}). {plan.estimate_note}
      </p>
    </Card>
  );
}

export default function AIInvestigation() {
  const { scanId } = useParams<{ scanId: string }>();
  const sid = scanId ?? "";
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);

  const investigate = useInvestigateScan(sid);
  const remediation = useRemediationPlan(sid);
  const security = useSecurityReview(sid);
  const { data: history } = useInvestigations(sid);

  const suggestions = [
    "What are the biggest risks?",
    "Why is the production readiness score low?",
    "What should I fix first?",
    "Are multiple findings caused by one root issue?",
  ];

  const run = (q: string) => {
    const text = q.trim();
    if (!text) return;
    setPlan(null);
    investigate.mutate(text, { onSuccess: setResult });
  };

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <h2 className="mb-1 text-sm font-semibold text-slate-900">AI Investigation</h2>
        <p className="mb-3 text-xs text-slate-500">
          Ask a question about this scan. The agent gathers evidence through controlled, read-only
          tools and answers with citations. Deterministic findings and scores remain authoritative.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run(question);
          }}
          className="flex gap-2"
        >
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. Why is the production readiness score low?"
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
          <button
            type="submit"
            disabled={investigate.isPending || !question.trim()}
            className="btn-primary px-4 py-2 text-xs disabled:opacity-50"
          >
            {investigate.isPending ? "Investigating…" : "Investigate"}
          </button>
        </form>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {suggestions.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                setQuestion(s);
                run(s);
              }}
              className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-slate-600 hover:border-brand hover:text-brand"
            >
              {s}
            </button>
          ))}
        </div>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            onClick={() => remediation.mutate({}, { onSuccess: (p) => { setResult(null); setPlan(p); } })}
            disabled={remediation.isPending}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {remediation.isPending ? "Planning…" : "Propose remediation plan"}
          </button>
          <button
            type="button"
            onClick={() => security.mutate()}
            disabled={security.isPending}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {security.isPending ? "Reviewing…" : "AI security review"}
          </button>
        </div>
        {investigate.isError ? (
          <p className="mt-2 text-xs text-rose-600">
            {investigate.error instanceof ApiError ? investigate.error.message : "Investigation failed."}
          </p>
        ) : null}
      </Card>

      {investigate.isPending ? <Spinner label="Gathering evidence…" /> : null}
      {result ? <ResultCard result={result} /> : null}
      {plan ? <RemediationPlanCard plan={plan} /> : null}

      {security.data && security.data.items.length ? (
        <Card className="p-5">
          <div className="mb-2 flex items-center gap-2">
            <Badge className="bg-brand-50 text-brand-deep ring-brand-200">AI Security Review</Badge>
            <Badge className="bg-slate-100 text-slate-500 ring-slate-300">advisory - non-authoritative</Badge>
          </div>
          <ul className="space-y-2">
            {security.data.items.map((item, i) => (
              <li key={i} className="text-sm text-slate-700">
                <span className="font-medium">{item.title}</span> ({item.confidence}) — {item.concern}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      {history && history.items.length ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-900">Previous investigations</h3>
          <div className="space-y-1.5">
            {history.items.slice(0, 10).map((inv) => (
              <div
                key={inv.id}
                className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs"
              >
                <span className="truncate text-slate-700">{inv.question}</span>
                <span className="ml-2 flex shrink-0 items-center gap-2 text-slate-400">
                  <ConfidenceBadge confidence={inv.confidence} />
                  {relativeTime(inv.created_at)}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <EmptyState title="No investigations yet" description="Ask a question above to start." />
      )}
    </div>
  );
}
