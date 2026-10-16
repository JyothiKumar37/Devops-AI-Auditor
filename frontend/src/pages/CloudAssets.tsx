import { useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import { useCloudAssets } from "@/hooks/useCloud";
import { relativeTime } from "@/lib/format";

function ExposureBadge({ exposure }: { exposure: string }) {
  const cls =
    exposure === "public"
      ? "bg-rose-50 text-rose-700 ring-rose-600/20"
      : exposure === "private"
        ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
        : "bg-slate-100 text-slate-500 ring-slate-300";
  return <Badge className={cls}>{exposure}</Badge>;
}

export default function CloudAssets() {
  const { accountId } = useParams();
  const [svc, setSvc] = useState("");
  const [exposure, setExposure] = useState("");
  const { data, isLoading } = useCloudAssets(accountId ?? null, {
    svc: svc || undefined,
    exposure: exposure || undefined,
  });

  const assets = data?.items ?? [];
  const services = Array.from(new Set(assets.map((a) => a.service))).sort();

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={svc}
          onChange={(e) => setSvc(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">All services</option>
          {["ec2", "s3", "rds", "elb", "vpc", "eks", "lambda", "iam", "ecr", ...services]
            .filter((v, i, arr) => arr.indexOf(v) === i)
            .map((s) => (
              <option key={s} value={s}>
                {s.toUpperCase()}
              </option>
            ))}
        </select>
        <select
          value={exposure}
          onChange={(e) => setExposure(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">Any exposure</option>
          <option value="public">Public</option>
          <option value="private">Private</option>
          <option value="unknown">Unknown</option>
        </select>
        {data ? (
          <span className="text-xs text-slate-500">
            {data.returned} of {data.total} assets
          </span>
        ) : null}
      </div>

      {isLoading && !data ? (
        <Spinner label="Loading assets…" />
      ) : assets.length === 0 ? (
        <EmptyState
          title="No assets"
          description="Sync the account (or adjust filters) to discover AWS resources."
        />
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2.5">Resource</th>
                  <th className="px-4 py-2.5">Service</th>
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">Region</th>
                  <th className="px-4 py-2.5">Exposure</th>
                  <th className="px-4 py-2.5">Synced</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {assets.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50/60">
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-slate-800">{a.name || a.resource_id}</span>
                      {a.name ? (
                        <span className="block font-mono text-[11px] text-slate-400">
                          {a.resource_id}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-2.5 uppercase text-slate-600">{a.service}</td>
                    <td className="px-4 py-2.5 text-slate-600">{a.resource_type}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-500">
                      {a.region || "global"}
                    </td>
                    <td className="px-4 py-2.5">
                      <ExposureBadge exposure={a.exposure} />
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">
                      {relativeTime(a.last_synced_at)}
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
