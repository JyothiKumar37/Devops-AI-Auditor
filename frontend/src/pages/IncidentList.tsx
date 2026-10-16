import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import { useIncidents } from "@/hooks/useIncidents";
import { SEVERITY_ORDER, relativeTime } from "@/lib/format";

const STATUSES = [
  "new", "triaging", "investigating", "containment_planned",
  "containment_approved", "contained", "resolved", "false_positive", "accepted_risk",
];

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "resolved"
      ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
      : status === "false_positive" || status === "accepted_risk"
        ? "bg-slate-100 text-slate-500 ring-slate-300"
        : "bg-indigo-50 text-indigo-700 ring-indigo-600/20";
  return <Badge className={cls}>{status.replace(/_/g, " ")}</Badge>;
}

function SevBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "bg-rose-50 text-rose-700 ring-rose-600/20"
      : severity === "high"
        ? "bg-orange-50 text-orange-700 ring-orange-600/20"
        : severity === "medium"
          ? "bg-amber-50 text-amber-700 ring-amber-600/20"
          : "bg-slate-100 text-slate-500 ring-slate-300";
  return <Badge className={cls}>{severity}</Badge>;
}

export default function IncidentList() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [unassigned, setUnassigned] = useState(false);
  const { data, isLoading } = useIncidents({
    incident_status: status || undefined,
    severity: severity || undefined,
    unassigned: unassigned ? "true" : undefined,
  });

  const incidents = data?.items ?? [];

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader title="Incidents" subtitle="Search, filter, and triage security incidents." />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-slate-600">
          <input
            type="checkbox"
            checked={unassigned}
            onChange={(e) => setUnassigned(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-slate-300"
          />
          Unassigned only
        </label>
        {data ? <span className="text-xs text-slate-500">{data.total} incident(s)</span> : null}
      </div>

      {isLoading && !data ? (
        <Spinner label="Loading incidents…" />
      ) : incidents.length === 0 ? (
        <EmptyState title="No incidents" description="No incidents match the current filters." />
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2.5">Incident</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5">Priority</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Owner</th>
                  <th className="px-4 py-2.5">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-50/60">
                    <td className="px-4 py-2.5">
                      <Link to={`/incidents/${inc.id}`} className="font-medium text-slate-800 hover:text-brand">
                        {inc.title}
                      </Link>
                      <span className="block text-[11px] text-slate-400">
                        {inc.event_count} event(s) · {inc.account_ref || "no account"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5"><SevBadge severity={inc.severity} /></td>
                    <td className="px-4 py-2.5 font-mono text-xs tabular-nums text-slate-600">
                      {inc.priority}
                    </td>
                    <td className="px-4 py-2.5"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">{inc.owner || "—"}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">
                      {relativeTime(inc.updated_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
