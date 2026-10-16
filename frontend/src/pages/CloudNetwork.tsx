import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, SeverityPill, Spinner, StatCard } from "@/components/ui";
import { useCloudAttackSurface, useCloudNetwork } from "@/hooks/useCloud";
import { SEVERITY_ORDER } from "@/lib/format";
import type { CloudNetworkNode } from "@/types/api";

function nodeLabel(nodes: CloudNetworkNode[], id: string): string {
  const n = nodes.find((x) => x.id === id);
  return n?.label ?? id;
}

export default function CloudNetwork() {
  const { accountId } = useParams();
  const { data: graph, isLoading } = useCloudNetwork(accountId ?? null);
  const { data: surface } = useCloudAttackSurface(accountId ?? null);

  if (isLoading && !graph) return <Spinner label="Building network graph…" />;
  if (!graph || graph.nodes.length <= 1) {
    return (
      <EmptyState
        title="No network graph"
        description="Sync the account to derive evidence-backed network relationships."
      />
    );
  }

  const nodes = graph.nodes;
  // Edges that expose a resource directly to the internet are the highest signal.
  const exposures = graph.edges.filter((e) => e.source === "internet" && e.relation === "exposes");

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          label="Internet-facing"
          value={surface?.internet_facing ?? exposures.length}
          hint="publicly reachable assets"
          accent={(surface?.internet_facing ?? exposures.length) > 0 ? "text-rose-600" : undefined}
        />
        <StatCard label="Graph nodes" value={nodes.length - 1} hint="discovered resources" />
        <StatCard label="Relationships" value={graph.edges.length} hint="evidence-backed edges" />
      </div>

      {surface && surface.internet_facing > 0 ? (
        <div className="flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((sev) =>
            surface.by_severity[sev] ? (
              <SeverityPill key={sev} severity={sev} count={surface.by_severity[sev]} />
            ) : null,
          )}
        </div>
      ) : null}

      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-900">Internet exposure paths</h2>
        {exposures.length === 0 ? (
          <EmptyState title="No direct internet exposure" description="No asset is directly reachable from the internet." />
        ) : (
          <div className="space-y-2">
            {exposures.map((e, i) => {
              const node = nodes.find((n) => n.id === e.target);
              return (
                <Card key={`${e.target}-${i}`} className="flex flex-wrap items-center gap-2 p-3">
                  <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">Internet</Badge>
                  <span className="text-slate-400">→</span>
                  <span className="font-medium text-slate-800">{nodeLabel(nodes, e.target)}</span>
                  {node?.service ? (
                    <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                      {node.service.toUpperCase()}
                    </Badge>
                  ) : null}
                  {node?.max_severity ? <SeverityPill severity={node.max_severity} /> : null}
                  {Object.keys(e.detail).length > 0 ? (
                    <span className="font-mono text-[11px] text-slate-400">
                      {Object.entries(e.detail)
                        .map(([k, v]) => `${k}=${String(v)}`)
                        .join(" ")}
                    </span>
                  ) : null}
                </Card>
              );
            })}
          </div>
        )}
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-900">Relationships</h2>
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2.5">Source</th>
                  <th className="px-4 py-2.5">Relation</th>
                  <th className="px-4 py-2.5">Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {graph.edges.map((e, i) => (
                  <tr key={`${e.source}-${e.target}-${i}`} className="hover:bg-slate-50/60">
                    <td className="px-4 py-2 font-medium text-slate-700">
                      {nodeLabel(nodes, e.source)}
                    </td>
                    <td className="px-4 py-2">
                      <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                        {e.relation}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-slate-700">{nodeLabel(nodes, e.target)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
