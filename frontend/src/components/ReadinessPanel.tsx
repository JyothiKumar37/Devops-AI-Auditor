import { useReport } from "@/hooks/useScans";
import type { CategoryScore } from "@/types/api";

function scoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-rose-400";
}

function barColor(score: number): string {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 60) return "bg-amber-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-rose-500";
}

function ScoreGauge({ score, ready }: { score: number; ready: boolean }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);
  return (
    <div className="relative grid h-36 w-36 place-items-center">
      <svg className="h-36 w-36 -rotate-90" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={radius} className="fill-none stroke-white/10" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={radius}
          strokeWidth="10"
          strokeLinecap="round"
          className={`fill-none transition-all ${scoreColor(score)}`}
          stroke="currentColor"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-3xl font-bold ${scoreColor(score)}`}>{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
        <span className={`mt-1 text-xs font-medium ${ready ? "text-emerald-400" : "text-rose-400"}`}>
          {ready ? "Ready" : "Not ready"}
        </span>
      </div>
    </div>
  );
}

function CategoryBar({ category }: { category: CategoryScore }) {
  return (
    <div className={category.applicable ? "" : "opacity-40"}>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="capitalize text-slate-300" title={category.explanation}>
          {category.category}
          {!category.applicable ? " (n/a)" : ""}
        </span>
        <span className="text-slate-400">{category.score}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-white/10">
        <div
          className={`h-full rounded-full ${barColor(category.score)}`}
          style={{ width: `${category.score}%` }}
        />
      </div>
    </div>
  );
}

export function ReadinessPanel({ scanId }: { scanId: string | null }) {
  const { data, isLoading, isError } = useReport(scanId);

  if (!scanId) {
    return (
      <section className="flex min-h-[12rem] items-center justify-center rounded-xl border border-white/10 bg-surface-soft/60 p-5">
        <p className="text-sm text-slate-500">Select a scan to view production readiness.</p>
      </section>
    );
  }

  return (
    <section className="rounded-xl border border-white/10 bg-surface-soft/60 p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Production Readiness
        </h2>
        {data ? (
          <span className="text-xs text-slate-500">
            {data.llm_used ? "AI + rules" : "deterministic"}
          </span>
        ) : null}
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-400">Computing readiness…</p>
      ) : isError ? (
        <p className="text-sm text-rose-300">Could not load the report.</p>
      ) : data ? (
        <div className="space-y-6">
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
            <ScoreGauge
              score={data.production_readiness.score}
              ready={data.production_readiness.ready}
            />
            <div className="flex-1 space-y-2">
              {data.production_readiness.category_scores.map((c) => (
                <CategoryBar key={c.category} category={c} />
              ))}
            </div>
          </div>

          {data.production_readiness.blockers.length > 0 ? (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-rose-300">
                Critical blockers
              </h3>
              <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-300">
                {data.production_readiness.blockers.map((b) => (
                  <li key={b}>{b}</li>
                ))}
              </ol>
            </div>
          ) : null}

          {data.production_readiness.top_risks.length > 0 ? (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-amber-300">
                High priority
              </h3>
              <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-300">
                {data.production_readiness.top_risks.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ol>
            </div>
          ) : null}

          {data.production_readiness.next_actions.length > 0 ? (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Recommended next actions
              </h3>
              <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">
                {data.production_readiness.next_actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
            </div>
          ) : null}

          <p className="border-t border-white/10 pt-3 text-xs text-slate-500">
            {data.production_readiness.explanation}
          </p>
        </div>
      ) : null}
    </section>
  );
}
