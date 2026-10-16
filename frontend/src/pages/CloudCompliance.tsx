import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Meter, Spinner } from "@/components/ui";
import {
  useComplianceAssessment,
  useComplianceExceptions,
  useComplianceFrameworks,
  useCreateComplianceException,
  useDeleteComplianceException,
} from "@/hooks/useCloud";
import { formatDateTime } from "@/lib/format";

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    PASS: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
    FAIL: "bg-rose-50 text-rose-700 ring-rose-600/20",
    NOT_APPLICABLE: "bg-slate-100 text-slate-500 ring-slate-300",
    NOT_ASSESSED: "bg-amber-50 text-amber-700 ring-amber-600/20",
  };
  return <Badge className={map[status] ?? map.NOT_ASSESSED}>{status.replace(/_/g, " ")}</Badge>;
}

export default function CloudCompliance() {
  const { accountId } = useParams();
  const { data: frameworks } = useComplianceFrameworks();
  const [framework, setFramework] = useState("");

  useEffect(() => {
    const first = frameworks?.frameworks[0];
    if (!framework && first) {
      setFramework(first.framework);
    }
  }, [frameworks, framework]);

  const { data: assessment, isLoading } = useComplianceAssessment(
    accountId ?? null,
    framework || null,
  );
  const { data: exceptions } = useComplianceExceptions(accountId ?? null);
  const createException = useCreateComplianceException(accountId ?? "");
  const deleteException = useDeleteComplianceException(accountId ?? "");

  const onExcept = (controlId: string) => {
    const reason = prompt(
      "Exception reason (accept_risk | false_positive | not_applicable | compensating_control):",
      "accept_risk",
    );
    if (!reason) return;
    const owner = prompt("Owner (who accepts this risk):", "");
    if (!owner) return;
    createException.mutate({
      framework,
      control_id: controlId,
      reason: reason.trim(),
      owner: owner.trim(),
    });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          {frameworks?.frameworks.map((f) => (
            <option key={f.framework} value={f.framework}>
              {f.label} ({f.controls} controls)
            </option>
          ))}
        </select>
      </div>

      {isLoading && !assessment ? (
        <Spinner label="Assessing compliance…" />
      ) : !assessment ? (
        <EmptyState title="No assessment" description="Select a framework to assess compliance." />
      ) : (
        <>
          <Card className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">{assessment.label}</h2>
                <p className="mt-0.5 text-xs text-slate-500">{assessment.disclaimer}</p>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold tabular-nums text-slate-900">
                  {assessment.pass_rate}%
                </p>
                <p className="text-[11px] uppercase tracking-widest text-slate-400">pass rate</p>
              </div>
            </div>
            <div className="mt-3">
              <Meter value={assessment.pass_rate} />
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(assessment.summary).map(([status, count]) => (
                <span key={status} className="inline-flex items-center gap-1.5">
                  <StatusBadge status={status} />
                  <span className="font-mono text-xs tabular-nums text-slate-500">{count}</span>
                </span>
              ))}
            </div>
          </Card>

          <div className="space-y-3">
            {assessment.controls.map((c) => (
              <Card key={c.control_id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge status={c.status} />
                      <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                        {c.control_id}
                      </Badge>
                      <span className="font-medium text-slate-800">{c.title}</span>
                    </div>
                    {c.description ? (
                      <p className="mt-1 text-xs text-slate-500">{c.description}</p>
                    ) : null}
                    <p className="mt-1 text-xs text-slate-500">{c.evidence}</p>
                    {c.affected_resources.length > 0 ? (
                      <ul className="mt-2 space-y-0.5 font-mono text-[11px] text-slate-500">
                        {c.affected_resources.map((r, i) => (
                          <li key={i}>
                            {r.resource_id} · {r.service} · {r.severity}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                    {c.status === "FAIL" && c.remediation ? (
                      <p className="mt-2 text-xs text-slate-500">
                        <span className="font-semibold text-slate-600">Fix:</span> {c.remediation}
                      </p>
                    ) : null}
                  </div>
                  {c.status === "FAIL" ? (
                    <button
                      type="button"
                      onClick={() => onExcept(c.control_id)}
                      disabled={createException.isPending}
                      className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                    >
                      Add exception
                    </button>
                  ) : null}
                </div>
              </Card>
            ))}
          </div>
        </>
      )}

      {exceptions && exceptions.items.length > 0 ? (
        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-900">Exceptions</h2>
          <div className="space-y-2">
            {exceptions.items.map((e) => (
              <Card key={e.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                      {e.framework}/{e.control_id}
                    </Badge>
                    <Badge className="bg-indigo-50 text-indigo-700 ring-indigo-600/20">
                      {e.reason}
                    </Badge>
                    <span className="text-xs text-slate-500">owner: {e.owner || "—"}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400">
                    {e.resource_id ? `${e.resource_id} · ` : ""}
                    {e.expires_at ? `expires ${formatDateTime(e.expires_at)}` : "no expiry"}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => deleteException.mutate(e.id)}
                  className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
                >
                  Remove
                </button>
              </Card>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
