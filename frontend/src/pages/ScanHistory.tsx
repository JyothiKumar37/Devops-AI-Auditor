import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import { useScans } from "@/hooks/useScans";
import { formatDateTime, prettyLabel } from "@/lib/format";

export default function ScanHistory() {
  const { data, isLoading, isError } = useScans();

  return (
    <div>
      <PageHeader
        title="Scan History"
        subtitle="Every repository audit, most recent first."
        actions={
          <Link
            to="/scan/new"
            className="rounded-lg bg-brand px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-brand-muted"
          >
            New Scan
          </Link>
        }
      />
      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load scans" />
      ) : data.items.length === 0 ? (
        <EmptyState title="No scans yet" description="Upload a repository to begin." />
      ) : (
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/5 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-5 py-2.5 font-medium">Repository</th>
                <th className="px-5 py-2.5 font-medium">Source</th>
                <th className="px-5 py-2.5 font-medium">Status</th>
                <th className="px-5 py-2.5 font-medium">Files</th>
                <th className="px-5 py-2.5 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((scan) => (
                <tr key={scan.id} className="border-b border-white/5 last:border-0 hover:bg-white/5">
                  <td className="px-5 py-3">
                    <Link
                      to={`/scans/${scan.id}`}
                      className="font-medium text-slate-100 hover:text-brand"
                    >
                      {scan.repository_name}
                    </Link>
                    {scan.error_message ? (
                      <p className="text-xs text-rose-400">{scan.error_message}</p>
                    ) : null}
                  </td>
                  <td className="px-5 py-3 text-slate-400">{prettyLabel(scan.source_type)}</td>
                  <td className="px-5 py-3">
                    <ScanStatusBadge status={scan.status} />
                  </td>
                  <td className="px-5 py-3 text-slate-400">{scan.file_count}</td>
                  <td className="px-5 py-3 text-slate-400">{formatDateTime(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
