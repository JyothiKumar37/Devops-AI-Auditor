import { Link, useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Meter, ScoreRing, SeverityPill, Spinner } from "@/components/ui";
import {
  useContainerSecurity,
  useKubernetesScore,
  usePosture,
  useRemediationHistory,
  useScan,
} from "@/hooks/useScans";

interface Dimension {
  key: string;
  label: string;
  score: number;
  findings: number;
}

function ScoreDimensionsCard({
  title,
  overall,
  totalFindings,
  unit,
  dimensions,
}: {
  title: string;
  overall: number;
  totalFindings: number;
  unit: string;
  dimensions: Dimension[];
}) {
  return (
    <Card className="p-5">
      <p className="section-title mb-3">{title}</p>
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center">
        <div className="flex items-center gap-4 lg:w-56 lg:border-r lg:border-slate-200 lg:pr-6">
          <ScoreRing score={overall} caption={unit} size={104} />
          <p className="text-xs text-slate-500">
            {totalFindings} {totalFindings === 1 ? "issue" : "issues"}
          </p>
        </div>
        <div className="flex-1 space-y-1.5">
          {dimensions.map((c) => (
            <div key={c.key} className="flex items-center gap-3 py-1">
              <span className="w-40 shrink-0 text-sm font-medium text-slate-700">{c.label}</span>
              <span className="flex-1">
                <Meter value={c.score} />
              </span>
              <span
                className="w-10 text-right text-sm font-bold tabular-nums"
                style={{ color: scoreColor(c.score) }}
              >
                {c.score}
              </span>
              <span className="w-16 text-right text-xs text-slate-400">
                {c.findings} {c.findings === 1 ? "issue" : "issues"}
              </span>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}
import { SEVERITY_ORDER, prettyLabel, relativeTime, scoreColor } from "@/lib/format";
import type { PostureCategory } from "@/types/api";

function DomainRow({ scanId, cat }: { scanId: string; cat: PostureCategory }) {
  if (!cat.applicable) {
    return (
      <div className="flex items-center gap-3 py-2 opacity-60">
        <span className="w-32 shrink-0 text-sm font-medium text-slate-600">{cat.label}</span>
        <span className="flex-1 text-xs text-slate-400">Not applicable</span>
        <span className="w-10 text-right text-xs text-slate-400">N/A</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-3 py-2" title={cat.explanation}>
      <span className="w-32 shrink-0 text-sm font-medium text-slate-700">{cat.label}</span>
      <span className="flex-1">
        <Meter value={cat.score} />
      </span>
      <span
        className="w-10 text-right text-sm font-bold tabular-nums"
        style={{ color: scoreColor(cat.score) }}
      >
        {cat.score}
      </span>
      <Link
        to={`/scans/${scanId}/findings`}
        className="w-16 shrink-0 text-right text-xs text-slate-400 hover:text-brand hover:underline"
      >
        {cat.findings} {cat.findings === 1 ? "issue" : "issues"}
      </Link>
    </div>
  );
}

export default function Posture() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data: scan } = useScan(id);
  const isDone = scan?.status === "completed";
  const { data, isLoading } = usePosture(isDone ? id : null);
  const { data: history } = useRemediationHistory(isDone ? id : null);
  const { data: k8s } = useKubernetesScore(isDone ? id : null);
  const { data: container } = useContainerSecurity(isDone ? id : null);

  if (scan && !isDone) {
    return (
      <Card className="p-6">
        <Spinner label={`Scan ${scan.status}…`} />
      </Card>
    );
  }
  if (isLoading || !data) return <Spinner />;

  const total = data.total_findings || 0;

  return (
    <div className="space-y-4">
      {/* Overall posture + diff deltas */}
      <Card className="relative overflow-hidden p-5">
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-brand-50/60 via-white to-violet-50/40" />
        <div className="relative flex flex-col gap-6 lg:flex-row lg:items-center">
          <div className="flex items-center gap-4 lg:w-72 lg:border-r lg:border-slate-200 lg:pr-6">
            <ScoreRing score={data.overall} caption="posture" />
            <div>
              <p className="section-title">Overall posture</p>
              <span
                className={`chip mt-2 ring-1 ${
                  data.ready
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                    : "bg-rose-50 text-rose-700 ring-rose-600/20"
                }`}
              >
                {data.ready ? "Production ready" : "Not production ready"}
              </span>
              <p className="mt-2 text-xs text-slate-500">{total} active findings</p>
            </div>
          </div>

          <div className="flex-1">
            <p className="section-title mb-2">Severity distribution</p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {SEVERITY_ORDER.map((sev) => {
                const c = data.severity_counts[sev] ?? 0;
                return (
                  <Link
                    key={sev}
                    to={`/scans/${id}/findings?severity=${sev}`}
                    className="rounded-lg border border-slate-200/70 bg-white/70 px-2.5 py-2 transition hover:border-slate-300 hover:shadow-card-hover"
                  >
                    <span className="block text-lg font-bold tabular-nums text-slate-900">{c}</span>
                    <span className="block text-[11px] capitalize text-slate-500">{sev}</span>
                  </Link>
                );
              })}
            </div>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <span className="chip bg-rose-50 text-rose-700 ring-1 ring-rose-600/20">
                {data.new_findings} new
              </span>
              <span className="chip bg-emerald-50 text-emerald-700 ring-1 ring-emerald-600/20">
                {data.fixed_findings} fixed
              </span>
              <span className="chip bg-slate-50 text-slate-600 ring-1 ring-slate-300">
                {data.unchanged_findings} unchanged
              </span>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Per-domain scores */}
        <Card className="p-5">
          <p className="section-title mb-1">Domain scores</p>
          <p className="mb-2 text-xs text-slate-500">
            Each domain is scored 0-100 from this scan's findings. Overlapping lenses:
            a Kubernetes security issue counts toward both.
          </p>
          <div className="divide-y divide-slate-100">
            {data.categories.map((cat) => (
              <DomainRow key={cat.key} scanId={id as string} cat={cat} />
            ))}
          </div>
        </Card>

        <div className="space-y-4">
          {/* Top risk areas */}
          <Card className="p-5">
            <p className="section-title mb-2">Top risk areas</p>
            {data.top_risk_areas.length === 0 ? (
              <p className="text-sm text-slate-500">No weak domains — every applicable area scores full.</p>
            ) : (
              <ul className="space-y-2">
                {data.top_risk_areas.map((area) => (
                  <li key={area.key} className="flex items-center gap-3 text-sm">
                    <span
                      className="w-9 text-right font-bold tabular-nums"
                      style={{ color: scoreColor(area.score) }}
                    >
                      {area.score}
                    </span>
                    <span className="font-medium text-slate-700">{area.label}</span>
                    <span className="ml-auto text-xs text-slate-400">{area.findings} issues</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Most affected files */}
          <Card className="p-5">
            <p className="section-title mb-2">Most affected files</p>
            {data.most_affected_files.length === 0 ? (
              <p className="text-sm text-slate-500">No file-scoped findings.</p>
            ) : (
              <ul className="space-y-1.5">
                {data.most_affected_files.map((f) => (
                  <li key={f.file} className="flex items-center gap-2 text-sm">
                    <SeverityPill severity={f.max_severity} />
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-600" title={f.file}>
                      {f.file}
                    </span>
                    <span className="text-xs font-semibold tabular-nums text-slate-500">
                      {f.findings}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      {/* Recommendations */}
      <Card className="p-5">
        <p className="section-title mb-2">Priority recommendations</p>
        {data.recommendations.length === 0 ? (
          <EmptyState title="Nothing critical" description="No high-priority actions were derived from this scan." />
        ) : (
          <ol className="space-y-1.5">
            {data.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-slate-700">
                <span className="mt-0.5 w-5 shrink-0 text-right font-mono text-xs text-slate-400">
                  {i + 1}
                </span>
                <span>{rec}</span>
              </li>
            ))}
          </ol>
        )}
      </Card>

      {/* Container-security score (only when Docker/Compose files exist). */}
      {container && container.applicable ? (
        <ScoreDimensionsCard
          title="Container security"
          overall={container.overall}
          totalFindings={container.total_findings}
          unit="containers"
          dimensions={container.categories}
        />
      ) : null}

      {/* Kubernetes production-readiness score (only when manifests exist). */}
      {k8s && k8s.applicable ? (
        <ScoreDimensionsCard
          title="Kubernetes production readiness"
          overall={k8s.overall}
          totalFindings={k8s.total_findings}
          unit="k8s"
          dimensions={k8s.categories}
        />
      ) : null}

      {/* Remediation history: the audit trail of applied fixes for this scan. */}
      {history && history.total > 0 ? (
        <Card className="p-5">
          <div className="mb-2 flex items-center justify-between">
            <p className="section-title">Remediation history</p>
            <span className="text-xs text-slate-500">
              {history.resolved_count} of {history.total} verified resolved
            </span>
          </div>
          <ul className="divide-y divide-slate-100">
            {history.items.map((h) => (
              <li key={h.id} className="flex items-center gap-2.5 py-2 text-sm">
                <SeverityPill severity={h.severity} />
                <span className="font-mono text-xs text-slate-500">{h.rule_id}</span>
                <span className="min-w-0 flex-1 truncate text-xs text-slate-500" title={h.file_path ?? ""}>
                  {h.file_path ?? "—"}
                </span>
                {h.resolved ? (
                  <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">Resolved</Badge>
                ) : (
                  <Badge className="bg-amber-50 text-amber-700 ring-amber-600/20">
                    {prettyLabel(h.applied ? "not resolved" : "manual")}
                  </Badge>
                )}
                <span className="w-16 text-right text-xs text-slate-400">
                  {relativeTime(h.created_at)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}
