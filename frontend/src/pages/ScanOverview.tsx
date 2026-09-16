import { Link, useParams } from "react-router-dom";

import { Card, SeverityPill, Spinner } from "@/components/ui";
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
      <Card className="p-6">
        <Spinner label={`Scan ${scan.status}…`} />
        <p className="mt-2 max-w-xl text-sm text-slate-500">
          Discovering files, running deterministic scanners, detecting secrets and correlating
          findings. This view updates automatically.
        </p>
      </Card>
    );
  }

  if (!report || !discovery) {
    return <Spinner />;
  }

  const pr = report.production_readiness;
  const total = report.total_findings || 1;
  const activeCats = (Object.keys(discovery.counts) as DiscoveryCategory[]).filter(
    (c) => (discovery.counts[c] ?? 0) > 0,
  );

  return (
    <div className="space-y-4">
      {/* Summary bar: readiness + severity distribution */}
      <Card className="p-5">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center">
          <div className="lg:w-56 lg:border-r lg:border-slate-200 lg:pr-6">
            <p className="section-title">Production readiness</p>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className={`text-4xl font-semibold tabular-nums ${readinessColor(pr.score)}`}>
                {pr.score}
              </span>
              <span className="text-sm text-slate-400">/ 100</span>
            </div>
            <span
              className={`chip mt-2 ${
                pr.ready
                  ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                  : "bg-rose-50 text-rose-700 ring-rose-600/20"
              }`}
            >
              {pr.ready ? "Production ready" : "Not production ready"}
            </span>
          </div>

          <div className="flex-1">
            <div className="mb-2 flex items-center justify-between">
              <p className="section-title">Findings · {report.total_findings}</p>
              <Link to={`/scans/${id}/findings`} className="text-xs font-medium text-brand hover:underline">
                All findings →
              </Link>
            </div>
            <div className="flex h-2 w-full overflow-hidden rounded-full bg-slate-100">
              {SEVERITY_ORDER.map((sev) => {
                const c = report.severity_counts[sev] ?? 0;
                if (!c) return null;
                return (
                  <span
                    key={sev}
                    className={severityMeta(sev).dot}
                    style={{ width: `${(c / total) * 100}%` }}
                    title={`${sev}: ${c}`}
                  />
                );
              })}
            </div>
            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
              {SEVERITY_ORDER.map((sev) => (
                <span key={sev} className="inline-flex items-center gap-1.5 text-xs">
                  <span className={`h-2 w-2 rounded-full ${severityMeta(sev).dot}`} aria-hidden />
                  <span className="capitalize text-slate-500">{sev}</span>
                  <span className="font-medium tabular-nums text-slate-800">
                    {report.severity_counts[sev] ?? 0}
                  </span>
                </span>
              ))}
            </div>
            <p className="mt-3 text-xs text-slate-500">
              {report.reviewed_false_positives} reviewed as likely false positives
            </p>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Detected stack + artifacts */}
        <Card className="p-5">
          <p className="section-title">Detected stack</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {report.understanding.technologies.length ? (
              report.understanding.technologies.map((t) => (
                <span key={t} className="chip bg-slate-50 text-slate-700 ring-slate-200">
                  {t}
                </span>
              ))
            ) : (
              <span className="text-sm text-slate-500">No known technologies detected.</span>
            )}
          </div>
          <p className="section-title mt-5">Discovered artifacts</p>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {activeCats.map((c) => {
                const meta = CATEGORY_META[c];
                return (
                  <tr key={c} className="border-b border-slate-100 last:border-0">
                    <td className="py-1.5">
                      <span className={`rounded px-1.5 py-0.5 text-xs ring-1 ring-inset ${meta?.accent ?? ""}`}>
                        {meta?.label ?? c}
                      </span>
                    </td>
                    <td className="py-1.5 text-right font-mono text-xs tabular-nums text-slate-600">
                      {discovery.counts[c] ?? 0}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>

        {/* Root-cause correlations */}
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">Root-cause correlations</p>
            {report.finding_groups.length > 5 ? (
              <span className="text-xs text-slate-400">
                showing 5 of {report.finding_groups.length}
              </span>
            ) : null}
          </div>
          {report.finding_groups.length === 0 ? (
            <p className="mt-2 text-sm text-slate-500">No cross-file root causes identified.</p>
          ) : (
            <ul className="mt-2 divide-y divide-slate-100">
              {report.finding_groups.slice(0, 5).map((g) => (
                <li key={g.root_cause} className="flex items-start gap-2.5 py-2 text-sm">
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
