import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, Spinner } from "@/components/ui";
import { useInvestigateCloud } from "@/hooks/useCloud";
import { ApiError } from "@/lib/api";
import type { InvestigationResult } from "@/types/api";

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
                {step.tool ? (
                  <span className="ml-1 font-mono text-slate-400">[{step.tool}]</span>
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
          <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
            AI disabled - deterministic
          </Badge>
        ) : null}
        {result.hallucination_guard_triggered ? (
          <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">
            unverifiable claims removed
          </Badge>
        ) : null}
      </div>

      <div className="prose prose-sm max-w-none whitespace-pre-wrap text-slate-700">
        {result.answer}
      </div>

      {result.root_cause ? (
        <div className="mt-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Root cause
          </h4>
          <p className="text-sm text-slate-700">{result.root_cause}</p>
        </div>
      ) : null}

      {result.recommendations.length ? (
        <div className="mt-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Recommended actions
          </h4>
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
              <span
                key={i}
                className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600"
              >
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

export default function CloudInvestigate() {
  const { accountId } = useParams();
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const investigate = useInvestigateCloud(accountId ?? "");

  const suggestions = [
    "What is exposed to the internet?",
    "What are the biggest cloud security risks?",
    "Which resources are not managed by Terraform?",
    "What should I fix first?",
  ];

  const run = (q: string) => {
    const text = q.trim();
    if (!text) return;
    investigate.mutate(text, { onSuccess: setResult });
  };

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <h2 className="mb-1 text-sm font-semibold text-slate-900">Cloud AI Investigation</h2>
        <p className="mb-3 text-xs text-slate-500">
          Ask about this account's cloud posture. The agent gathers evidence through read-only
          tools scoped to this account and answers with citations. No secrets are ever sent to the
          model.
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
            placeholder="e.g. What is exposed to the internet?"
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
        {investigate.isError ? (
          <p className="mt-2 text-xs text-rose-600">
            {investigate.error instanceof ApiError
              ? investigate.error.message
              : "Investigation failed."}
          </p>
        ) : null}
      </Card>

      {investigate.isPending ? <Spinner label="Gathering evidence…" /> : null}
      {result ? <ResultCard result={result} /> : null}
    </div>
  );
}
