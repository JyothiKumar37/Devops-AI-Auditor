import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import { useEksCorrelation } from "@/hooks/useCloud";

export default function CloudEks() {
  const { accountId } = useParams();
  const { data, isLoading } = useEksCorrelation(accountId ?? null);

  if (isLoading && !data) return <Spinner label="Correlating EKS clusters…" />;
  if (!data || data.clusters === 0) {
    return (
      <EmptyState
        title="No EKS clusters"
        description="No EKS clusters were discovered for this account."
      />
    );
  }

  return (
    <div className="space-y-3">
      {data.correlations.map((c) => (
        <Card key={c.cluster} className="p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-slate-800">{c.cluster}</span>
            <Badge className="bg-slate-100 text-slate-500 ring-slate-300">{c.region}</Badge>
            {c.terraform_managed ? (
              <Badge className="bg-violet-50 text-violet-700 ring-violet-600/20">
                Terraform-managed
              </Badge>
            ) : (
              <Badge className="bg-amber-50 text-amber-700 ring-amber-600/20">unmanaged</Badge>
            )}
            {c.endpoint_public_access ? (
              <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">public endpoint</Badge>
            ) : (
              <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">
                private endpoint
              </Badge>
            )}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
            {c.path.map((step, i) => (
              <span key={i} className="flex items-center gap-1.5">
                <span className="rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] text-slate-600">
                  {String(step.layer)}
                  {step.ref ? `: ${String(step.ref)}` : ""}
                  {typeof step.count === "number" ? ` (${step.count})` : ""}
                </span>
                {i < c.path.length - 1 ? <span className="text-slate-400">→</span> : null}
              </span>
            ))}
          </div>

          <p className="mt-3 text-xs text-slate-500">
            {c.kubernetes.has_scan_evidence
              ? `${c.kubernetes.workloads} workload(s), ${c.kubernetes.services.length} service(s) from scan evidence`
              : "No Kubernetes scan evidence linked"}
          </p>
          {c.kubernetes.services.length > 0 ? (
            <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-slate-500">
              {c.kubernetes.services.map((s, i) => (
                <li key={i}>
                  {s.namespace}/{s.name}
                </li>
              ))}
            </ul>
          ) : null}
        </Card>
      ))}
    </div>
  );
}
