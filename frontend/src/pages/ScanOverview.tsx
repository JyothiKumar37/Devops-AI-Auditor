import { Link, useParams } from "react-router-dom";

import { Badge, Card, SeverityPill, Spinner } from "@/components/ui";
import { useDiscovery, useReport, useScan } from "@/hooks/useScans";
import { CATEGORY_META, SEVERITY_ORDER, severityMeta } from "@/lib/format";
import type { DiscoveryCategory } from "@/types/api";

function readinessColor(score: number): string {
  if (score >= 80) return "text-emerald-600";
  if (score >= 60) return "text-amber-600";
  return "text-rose-600";
}

export default function ScanOverview() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data: scan } = useScan(id);
  const isDone = scan?.status === "completed";
  const { data: discovery } = useDiscovery(isDone ? id : null);
  const { data: report } = useReport(isDone ? id : null);

  if (scan && !isDone) {
    return (
      <Card className="p-8">
        <div className="flex flex-col items-center gap-3 text-center">
          <Spinner label={`Scan ${scan.status}…`} />
          <p className="max-w-md text-sm text-slate-500">
            Discovering files, running deterministic scanners, detecting secrets and correlating
            findings. This view will update automatically.
          </p>
        </div>
      </Card>
    );
  }

  if (!report || !discovery) {
    return <Spinner />;
  }

  const pr = report.production_readiness;
  const activeCats = (Object.keys(discovery.counts) as DiscoveryCategory[]).filter(
    (c) => (discovery.counts[c] ?? 0) > 0,
  );

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="flex flex-col items-center justify-center p-6">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Production readiness
          </p>
          <p className={`mt-2 text-5xl font-bold ${readinessColor(pr.score)}`}>{pr.score}</p>
          <p className="text-xs text-slate-500">/ 100</p>
          <Link
            to={`/scans/${id}/readiness`}
            className="mt-3 text-xs font-medium text-brand hover:underline"
          >
            View breakdown →
          </Link>
        </Card>

        <Card className="p-6 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Findings by severity
            </p>
            <Link to={`/scans/${id}/findings`} className="text-xs text-brand hover:underline">
              All findings →
            </Link>
          </div>
          <div className="grid grid-cols-5 gap-3">
            {SEVERITY_ORDER.map((sev) => (
              <div key={sev} className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-center">
                <p className={`text-2xl font-semibold ${severityMeta(sev).text}`}>
                  {report.severity_counts[sev] ?? 0}
                </p>
                <p className="mt-1 text-[11px] uppercase tracking-wide text-slate-500">{sev}</p>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            {report.total_findings} findings · {report.reviewed_false_positives} reviewed as likely
            false positives
          </p>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <p className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-500">
            Detected stack
          </p>
          <div className="flex flex-wrap gap-2">
            {report.understanding.technologies.length ? (
              report.understanding.technologies.map((t) => (
                <Badge key={t} className="bg-slate-50 text-slate-700 ring-slate-200">
                  {t}
                </Badge>
              ))
            ) : (
              <span className="text-sm text-slate-500">No known technologies detected.</span>
            )}
          </div>
          <p className="mb-2 mt-5 text-xs font-medium uppercase tracking-wide text-slate-500">
            Discovered artifacts
          </p>
          <div className="flex flex-wrap gap-2">
            {activeCats.map((c) => {
              const meta = CATEGORY_META[c];
              return (
                <span key={c} className="text-xs text-slate-500">
                  <span className={`rounded px-1.5 py-0.5 ring-1 ring-inset ${meta?.accent ?? ""}`}>
                    {meta?.label ?? c}
                  </span>{" "}
                  {discovery.counts[c] ?? 0}
                </span>
              );
            })}
          </div>
        </Card>

        <Card className="p-5">
          <p className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-500">
            Root-cause correlations
          </p>
          {report.finding_groups.length === 0 ? (
            <p className="text-sm text-slate-500">No cross-file root causes identified.</p>
          ) : (
            <ul className="space-y-2">
              {report.finding_groups.slice(0, 5).map((g) => (
                <li key={g.root_cause} className="flex items-start gap-2 text-sm">
                  <SeverityPill severity={g.severity} />
                  <span className="text-slate-700">{g.root_cause}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
