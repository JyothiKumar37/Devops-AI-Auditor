import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, PageHeader, Spinner, StatCard } from "@/components/ui";
import { useCorrelate, useIncidents, useSecurityHealth } from "@/hooks/useIncidents";
import { relativeTime } from "@/lib/format";
import type { Incident } from "@/types/api";

const OPEN_STATUSES = new Set([
  "new", "triaging", "investigating", "containment_planned", "containment_approved",
]);

function sevColor(sev: string): string {
  return (
    { critical: "text-rose-600", high: "text-orange-600", medium: "text-amber-600" }[sev] ??
    "text-slate-900"
  );
}

export default function IncidentDashboard() {
  const { data, isLoading } = useIncidents();
  const { data: health } = useSecurityHealth();
  const correlate = useCorrelate();

  const incidents = data?.items ?? [];
  const open = incidents.filter((i) => OPEN_STATUSES.has(i.status));
  const bySeverity = (sev: string) => open.filter((i) => i.severity === sev).length;
  const unassigned = open.filter((i) => !i.owner).length;
  const newCount = incidents.filter((i) => i.status === "new").length;

  const byAccount = new Map<string, number>();
  for (const i of open) {
    const key = i.account_ref || "(none)";
    byAccount.set(key, (byAccount.get(key) ?? 0) + 1);
  }

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Incident Operations Center"
        subtitle="Continuous security operations: ingestion, correlation, and response."
        actions={
          <button
            type="button"
            onClick={() => correlate.mutate()}
            disabled={correlate.isPending}
            className="btn-primary px-3.5 py-2 text-xs disabled:opacity-50"
          >
            {correlate.isPending ? "Correlating…" : "Run correlation"}
          </button>
        }
      />

      {isLoading && !data ? (
        <Spinner label="Loading incidents…" />
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Open incidents" value={open.length} hint="not yet resolved" />
            <StatCard
              label="Critical / High"
              value={bySeverity("critical") + bySeverity("high")}
              hint="open, elevated severity"
              accent={bySeverity("critical") + bySeverity("high") > 0 ? "text-rose-600" : undefined}
            />
            <StatCard label="New (untriaged)" value={newCount} hint="awaiting triage" />
            <StatCard
              label="Unassigned"
              value={unassigned}
              hint="open without an owner"
              accent={unassigned > 0 ? "text-amber-600" : undefined}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="p-4">
              <h3 className="mb-2 text-sm font-semibold text-slate-900">Open by account</h3>
              {byAccount.size === 0 ? (
                <p className="text-xs text-slate-500">No open incidents.</p>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {[...byAccount.entries()].sort((a, b) => b[1] - a[1]).map(([acct, count]) => (
                    <li key={acct} className="flex items-center justify-between">
                      <span className="font-mono text-xs text-slate-600">{acct}</span>
                      <span className="tabular-nums text-slate-500">{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card className="p-4">
              <h3 className="mb-2 text-sm font-semibold text-slate-900">
                Event ingestion health
              </h3>
              {!health || health.total_sources === 0 ? (
                <p className="text-xs text-slate-500">
                  No security event sources registered yet. Sources auto-register as events are
                  ingested from scans, cloud syncs, and webhooks.
                </p>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {health.sources.map((s) => (
                    <li key={s.source_type} className="flex items-center justify-between gap-2">
                      <span className="text-slate-600">{s.source_type}</span>
                      <span className="flex items-center gap-2 text-xs text-slate-500">
                        <Badge
                          className={
                            s.status === "ok"
                              ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                              : "bg-amber-50 text-amber-700 ring-amber-600/20"
                          }
                        >
                          {s.status}
                        </Badge>
                        {s.events_ingested} events
                        {s.last_event_at ? ` · ${relativeTime(s.last_event_at)}` : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900">Highest-priority open incidents</h3>
              <Link to="/incidents/list" className="text-xs font-medium text-slate-500 hover:text-brand">
                View all →
              </Link>
            </div>
            {open.length === 0 ? (
              <EmptyState
                title="No open incidents"
                description="Correlated security events become incidents here."
              />
            ) : (
              <div className="space-y-2">
                {open.slice(0, 8).map((inc) => (
                  <IncidentRow key={inc.id} incident={inc} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function IncidentRow({ incident }: { incident: Incident }) {
  return (
    <Link
      to={`/incidents/${incident.id}`}
      className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-2.5 shadow-soft hover:border-brand"
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-sm font-semibold ${sevColor(incident.severity)}`}>
            {incident.severity.toUpperCase()}
          </span>
          <span className="truncate font-medium text-slate-800">{incident.title}</span>
        </div>
        <p className="mt-0.5 text-xs text-slate-500">
          priority {incident.priority} · {incident.event_count} event(s) ·{" "}
          {incident.owner || "unassigned"} · {incident.status}
        </p>
      </div>
      <span className="ml-3 shrink-0 text-xs text-slate-400">
        {relativeTime(incident.updated_at)}
      </span>
    </Link>
  );
}
