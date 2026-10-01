import { Link, useParams } from "react-router-dom";

import { Badge, Card, EmptyState, PageHeader, Spinner, StatCard } from "@/components/ui";
import { usePullRequest } from "@/hooks/usePlatform";
import { formatDateTime, severityMeta } from "@/lib/format";
import type { PullRequestScan } from "@/types/api";

import { GateBadge } from "./PullRequests";

function SeverityDelta({ delta }: { delta: Record<string, number> | null }) {
  const order = ["critical", "high", "medium", "low"];
  const entries = order.filter((k) => (delta?.[k] ?? 0) > 0);
  if (entries.length === 0) return <span className="text-xs text-slate-400">no new findings</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map((k) => {
        const meta = severityMeta(k);
        return (
          <span key={k} className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${meta.badge}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
            {meta.label} · {delta?.[k]}
          </span>
        );
      })}
    </div>
  );
}

function ScanCard({ scan, latest }: { scan: PullRequestScan; latest?: boolean }) {
  const violations = Array.isArray(scan.policy_result?.violations)
    ? (scan.policy_result?.violations as unknown[]).length
    : 0;
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GateBadge gate={scan.gate_status} />
          {latest ? <Badge className="bg-brand-50 text-brand-deep ring-brand-200">latest</Badge> : null}
          <span className="font-mono text-xs text-slate-400">{scan.head_sha.slice(0, 8)}</span>
        </div>
        <span className="text-xs text-slate-400">{formatDateTime(scan.created_at)}</span>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="New findings" value={scan.new_findings} />
        <StatCard label="Fixed" value={scan.fixed_findings} />
        <StatCard label="PR risk" value={`${scan.pr_risk_score}/100`} />
        <StatCard label="Changed files" value={scan.changed_files} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-500">
        <span>Readiness: {scan.readiness_before} → {scan.readiness_after}</span>
        {violations > 0 ? <span className="text-rose-600">Policy violations: {violations}</span> : null}
      </div>
      <div className="mt-2">
        <SeverityDelta delta={scan.severity_delta} />
      </div>
    </Card>
  );
}

export default function PullRequestDetail() {
  const { prId } = useParams<{ prId: string }>();
  const { data, isLoading } = usePullRequest(prId ?? null);

  if (isLoading) return <Spinner label="Loading pull request…" />;
  if (!data) return <EmptyState title="Pull request not found" />;

  const { pull_request: pr, latest_scan, scans } = data;
  const history = scans.filter((s) => s.id !== latest_scan?.id);

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title={`#${pr.number} ${pr.title}`}
        subtitle={`${pr.repo_full_name} · ${pr.head_ref} → ${pr.base_ref} · by ${pr.author}`}
        actions={
          <a href={pr.web_url} target="_blank" rel="noreferrer" className="btn-primary px-3.5 py-2 text-xs">
            View on {pr.provider}
          </a>
        }
      />
      <Link to="/pull-requests" className="mb-4 inline-block text-xs text-slate-500 hover:text-brand">
        ← All pull requests
      </Link>

      {latest_scan ? (
        <div className="space-y-5">
          <ScanCard scan={latest_scan} latest />
          {history.length > 0 ? (
            <div>
              <h2 className="mb-2 text-sm font-semibold text-slate-900">Scan history</h2>
              <div className="space-y-3">
                {history.map((s) => (
                  <ScanCard key={s.id} scan={s} />
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : (
        <EmptyState title="No scans yet" description="This pull request has not been scanned." />
      )}
    </div>
  );
}
