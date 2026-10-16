import { useParams } from "react-router-dom";

import { Card, EmptyState, Meter, ScoreRing, SeverityPill, Spinner, StatCard } from "@/components/ui";
import { useCloudAttackSurface, useCloudPosture } from "@/hooks/useCloud";
import { SEVERITY_ORDER, prettyLabel, scoreColor } from "@/lib/format";

export default function CloudOverview() {
  const { accountId } = useParams();
  const { data: posture, isLoading } = useCloudPosture(accountId ?? null);
  const { data: surface } = useCloudAttackSurface(accountId ?? null);

  if (isLoading && !posture) return <Spinner label="Loading posture…" />;
  if (!posture) return <EmptyState title="No posture data" description="Sync the account to compute posture." />;

  if (posture.total_findings === 0) {
    return (
      <EmptyState
        title="No findings yet"
        description="Sync this account to discover assets and evaluate cloud security posture."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="flex items-center gap-5 p-5">
          <ScoreRing score={posture.overall} caption="posture" />
          <div>
            <p className="text-sm font-semibold text-slate-900">Cloud security posture</p>
            <p className="mt-1 text-xs text-slate-500">
              Deterministic score across cloud, network and IAM domains.
            </p>
          </div>
        </Card>
        <StatCard
          label="Total findings"
          value={posture.total_findings}
          hint="deterministic cloud rules"
        />
        <StatCard
          label="Internet-facing"
          value={surface?.internet_facing ?? "—"}
          hint="publicly reachable assets"
          accent={surface && surface.internet_facing > 0 ? "text-rose-600" : "text-slate-900"}
        />
      </div>

      <div className="flex flex-wrap gap-2">
        {SEVERITY_ORDER.map((sev) =>
          posture.severity_counts[sev] ? (
            <SeverityPill key={sev} severity={sev} count={posture.severity_counts[sev]} />
          ) : null,
        )}
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-900">Domains</h2>
        <div className="space-y-3">
          {posture.domains.map((d) => (
            <Card key={d.key} className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-800">{d.label}</p>
                  <p className="text-xs text-slate-500">
                    {d.applicable ? `${d.findings} finding(s)` : "not applicable"}
                  </p>
                </div>
                <span
                  className="text-lg font-bold tabular-nums"
                  style={{ color: d.applicable ? scoreColor(d.score) : "#94a3b8" }}
                >
                  {d.applicable ? d.score : "—"}
                </span>
              </div>
              {d.applicable ? (
                <div className="mt-2">
                  <Meter value={d.score} />
                  {d.explanation ? (
                    <p className="mt-1.5 text-xs text-slate-500">{d.explanation}</p>
                  ) : null}
                </div>
              ) : null}
            </Card>
          ))}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card className="p-4">
          <h3 className="mb-2 text-sm font-semibold text-slate-900">Findings by service</h3>
          {Object.keys(posture.by_service).length === 0 ? (
            <p className="text-xs text-slate-500">No findings.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {Object.entries(posture.by_service)
                .sort((a, b) => b[1] - a[1])
                .map(([svc, count]) => (
                  <li key={svc} className="flex items-center justify-between">
                    <span className="uppercase text-slate-600">{svc}</span>
                    <span className="font-mono text-xs tabular-nums text-slate-500">{count}</span>
                  </li>
                ))}
            </ul>
          )}
        </Card>
        <Card className="p-4">
          <h3 className="mb-2 text-sm font-semibold text-slate-900">Top risk areas</h3>
          {posture.top_risk_areas.length === 0 ? (
            <p className="text-xs text-slate-500">No elevated risk domains.</p>
          ) : (
            <ul className="space-y-1.5 text-sm">
              {posture.top_risk_areas.map((area) => (
                <li key={area.key} className="flex items-center justify-between">
                  <span className="text-slate-600">{prettyLabel(area.label)}</span>
                  <span
                    className="font-mono text-xs tabular-nums"
                    style={{ color: scoreColor(area.score) }}
                  >
                    {area.score}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
