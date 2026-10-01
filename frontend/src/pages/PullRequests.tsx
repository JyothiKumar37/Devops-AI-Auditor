import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import { usePullRequests } from "@/hooks/usePlatform";
import { relativeTime } from "@/lib/format";
import type { GateStatus } from "@/types/api";

export function GateBadge({ gate }: { gate: GateStatus | string }) {
  const map: Record<string, string> = {
    pass: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
    warning: "bg-amber-50 text-amber-700 ring-amber-600/20",
    fail: "bg-rose-50 text-rose-700 ring-rose-600/20",
  };
  const label: Record<string, string> = { pass: "Passed", warning: "Warning", fail: "Failed" };
  return <Badge className={map[gate] ?? "bg-slate-100 text-slate-600 ring-slate-300"}>{label[gate] ?? gate}</Badge>;
}

export default function PullRequests() {
  const { data, isLoading } = usePullRequests();
  const items = data?.items ?? [];

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Pull Requests"
        subtitle="Incremental security scans triggered by webhooks on each PR / MR."
      />
      {isLoading ? (
        <Spinner label="Loading pull requests…" />
      ) : items.length === 0 ? (
        <EmptyState
          title="No pull requests scanned yet"
          description="Once a connected repository opens a PR, its webhook triggers an incremental scan and it appears here."
        />
      ) : (
        <div className="space-y-2">
          {items.map((pr) => (
            <Link key={pr.id} to={`/pull-requests/${pr.id}`}>
              <Card className="p-4 transition hover:shadow-md">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium text-slate-800">
                      #{pr.number} {pr.title}
                    </p>
                    <p className="mt-0.5 truncate text-xs text-slate-500">
                      {pr.repo_full_name} · {pr.head_ref} → {pr.base_ref} · by {pr.author} · {relativeTime(pr.updated_at)}
                    </p>
                  </div>
                  <Badge className="bg-slate-100 text-slate-600 ring-slate-300">{pr.state}</Badge>
                </div>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
