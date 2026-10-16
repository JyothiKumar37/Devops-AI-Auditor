import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import { useCloudChanges } from "@/hooks/useCloud";
import { prettyLabel, relativeTime } from "@/lib/format";

export default function CloudChanges() {
  const { accountId } = useParams();
  const [riskOnly, setRiskOnly] = useState(false);
  const { data, isLoading } = useCloudChanges(accountId ?? null, riskOnly);

  const changes = data?.items ?? [];

  return (
    <div className="space-y-4">
      <label className="flex items-center gap-2 text-xs text-slate-600">
        <input
          type="checkbox"
          checked={riskOnly}
          onChange={(e) => setRiskOnly(e.target.checked)}
          className="h-3.5 w-3.5 rounded border-slate-300"
        />
        Risk-significant only
      </label>

      {isLoading && !data ? (
        <Spinner label="Loading changes…" />
      ) : changes.length === 0 ? (
        <EmptyState
          title="No changes detected"
          description="Changes are recorded between synchronizations (the first sync is a baseline)."
        />
      ) : (
        <div className="space-y-2">
          {changes.map((c) => (
            <Card key={c.id} className="p-3.5">
              <div className="flex flex-wrap items-center gap-2">
                {c.risk_significant ? (
                  <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">risk</Badge>
                ) : null}
                <Badge className="bg-slate-100 text-slate-600 ring-slate-300">
                  {prettyLabel(c.change_type)}
                </Badge>
                {c.service ? (
                  <span className="text-xs uppercase text-slate-500">{c.service}</span>
                ) : null}
                <span className="font-mono text-[11px] text-slate-500">{c.resource_id}</span>
                <span className="ml-auto text-xs text-slate-400">
                  {relativeTime(c.created_at)}
                </span>
              </div>
              {Object.keys(c.detail).length > 0 ? (
                <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-50 p-2.5 font-mono text-[11px] text-slate-600">
                  {JSON.stringify(c.detail, null, 2)}
                </pre>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
