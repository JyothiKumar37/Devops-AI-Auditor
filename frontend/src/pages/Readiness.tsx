import { useParams } from "react-router-dom";

import { ReadinessPanel } from "@/components/ReadinessPanel";
import { Card, SeverityPill } from "@/components/ui";
import { useReport } from "@/hooks/useScans";

export default function Readiness() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data } = useReport(id);

  return (
    <div className="space-y-6">
      <ReadinessPanel scanId={id} />

      {data && data.finding_groups.length > 0 ? (
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Root-cause groups
          </h2>
          <div className="space-y-4">
            {data.finding_groups.map((g) => (
              <div key={g.root_cause} className="rounded-lg border border-white/5 bg-slate-950/40 p-4">
                <div className="mb-2 flex items-center gap-2">
                  <SeverityPill severity={g.severity} />
                  <h3 className="text-sm font-semibold text-slate-100">{g.root_cause}</h3>
                </div>
                <p className="text-sm text-slate-400">{g.impact}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {g.affected_files.map((f) => (
                    <span
                      key={f}
                      className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[11px] text-slate-400"
                    >
                      {f}
                    </span>
                  ))}
                </div>
                <p className="mt-2 text-xs text-slate-500">{g.recommendation}</p>
              </div>
            ))}
          </div>
        </Card>
      ) : null}
    </div>
  );
}
