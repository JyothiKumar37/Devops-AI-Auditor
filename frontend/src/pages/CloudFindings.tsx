import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, SeverityPill, Spinner } from "@/components/ui";
import { useCloudFindings } from "@/hooks/useCloud";
import { SEVERITY_ORDER } from "@/lib/format";

export default function CloudFindings() {
  const { accountId } = useParams();
  const [severity, setSeverity] = useState("");
  const { data, isLoading } = useCloudFindings(accountId ?? null, {
    severity: severity || undefined,
  });

  const findings = data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        {data ? (
          <span className="text-xs text-slate-500">
            {data.returned} of {data.total} findings
          </span>
        ) : null}
      </div>

      {isLoading && !data ? (
        <Spinner label="Loading findings…" />
      ) : findings.length === 0 ? (
        <EmptyState
          title="No findings"
          description="No deterministic cloud security findings for the current filter."
        />
      ) : (
        <div className="space-y-3">
          {findings.map((f) => (
            <Card key={f.id} className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityPill severity={f.severity} />
                <span className="font-medium text-slate-800">{f.title}</span>
                <Badge className="bg-slate-100 text-slate-500 ring-slate-300">{f.rule_id}</Badge>
                <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                  {f.service.toUpperCase()}
                </Badge>
              </div>
              {f.description ? (
                <p className="mt-2 text-sm text-slate-600">{f.description}</p>
              ) : null}
              {f.resource_id ? (
                <p className="mt-1 font-mono text-[11px] text-slate-400">
                  {f.resource_id}
                  {f.region ? ` · ${f.region}` : ""}
                </p>
              ) : null}
              {f.evidence ? (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-50 p-2.5 font-mono text-[11px] text-slate-600">
                  {f.evidence}
                </pre>
              ) : null}
              {f.recommendation ? (
                <p className="mt-2 text-xs text-slate-500">
                  <span className="font-semibold text-slate-600">Fix:</span> {f.recommendation}
                </p>
              ) : null}
              {f.compliance.length > 0 ? (
                <div className="mt-2 flex flex-wrap gap-1">
                  {f.compliance.map((c) => (
                    <Badge key={c} className="bg-indigo-50 text-indigo-700 ring-indigo-600/20">
                      {c}
                    </Badge>
                  ))}
                </div>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
