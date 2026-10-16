import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import { useCloudDrift, useCorrelateDrift } from "@/hooks/useCloud";
import { useScans } from "@/hooks/useScans";

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    IN_SYNC: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
    DRIFTED: "bg-rose-50 text-rose-700 ring-rose-600/20",
    NOT_MANAGED: "bg-amber-50 text-amber-700 ring-amber-600/20",
    UNKNOWN: "bg-slate-100 text-slate-500 ring-slate-300",
  };
  return <Badge className={map[status] ?? map.UNKNOWN}>{status.replace(/_/g, " ")}</Badge>;
}

export default function CloudDrift() {
  const { accountId } = useParams();
  const [scanId, setScanId] = useState("");
  const { data: scans } = useScans();
  const { data, isLoading } = useCloudDrift(accountId ?? null);
  const correlate = useCorrelateDrift(accountId ?? "");

  const rows = data?.items ?? [];
  const summary = data?.summary ?? {};
  const completedScans = (scans?.items ?? []).filter((s) => s.status === "completed");

  return (
    <div className="space-y-5">
      <Card className="p-4">
        <h2 className="mb-1 text-sm font-semibold text-slate-900">Correlate Terraform ↔ AWS</h2>
        <p className="mb-3 text-xs text-slate-500">
          Compare a repository scan's Terraform against this account's live AWS state to detect
          drift and unmanaged resources.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="min-w-[16rem] rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
          >
            <option value="">Select a scan…</option>
            {completedScans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.repository_name} · {s.id.slice(0, 8)}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={!scanId || correlate.isPending}
            onClick={() => correlate.mutate(scanId)}
            className="btn-primary px-3.5 py-1.5 text-xs disabled:opacity-50"
          >
            {correlate.isPending ? "Correlating…" : "Correlate"}
          </button>
        </div>
        {correlate.isError ? (
          <p className="mt-2 text-xs text-rose-600">
            Correlation failed. Ensure the scan contains Terraform and the account is synced.
          </p>
        ) : null}
      </Card>

      {Object.keys(summary).length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {Object.entries(summary).map(([status, count]) => (
            <span key={status} className="inline-flex items-center gap-2">
              <StatusBadge status={status} />
              <span className="font-mono text-xs tabular-nums text-slate-500">{count}</span>
            </span>
          ))}
        </div>
      ) : null}

      {isLoading && !data ? (
        <Spinner label="Loading drift…" />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No drift recorded"
          description="Run a correlation above to compare Terraform against live state."
        />
      ) : (
        <div className="space-y-3">
          {rows.map((d) => (
            <Card key={d.id} className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge status={d.status} />
                <span className="font-medium text-slate-800">
                  {d.resource_id || d.terraform_address || "resource"}
                </span>
                {d.service ? (
                  <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                    {d.service.toUpperCase()}
                  </Badge>
                ) : null}
                {d.terraform_address ? (
                  <span className="font-mono text-[11px] text-slate-400">{d.terraform_address}</span>
                ) : null}
              </div>
              {d.differences.length > 0 ? (
                <div className="mt-2 overflow-x-auto rounded-lg bg-slate-50 p-2.5">
                  <table className="min-w-full text-xs">
                    <thead className="text-left text-slate-400">
                      <tr>
                        <th className="pr-4 py-1">Attribute</th>
                        <th className="pr-4 py-1">Expected (Terraform)</th>
                        <th className="py-1">Actual (AWS)</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono text-slate-600">
                      {d.differences.map((diff, i) => (
                        <tr key={i}>
                          <td className="pr-4 py-1">{String(diff.attribute ?? diff.key ?? "")}</td>
                          <td className="pr-4 py-1">{JSON.stringify(diff.expected ?? "")}</td>
                          <td className="py-1">{JSON.stringify(diff.actual ?? "")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
