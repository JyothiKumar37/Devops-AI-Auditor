import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import { useAuditLogs } from "@/hooks/usePlatform";
import { formatDateTime } from "@/lib/format";

function ActionBadge({ action }: { action: string }) {
  const danger = action.includes("delete") || action.includes("disconnect");
  const cls = danger
    ? "bg-rose-50 text-rose-700 ring-rose-600/20"
    : "bg-slate-100 text-slate-600 ring-slate-300";
  return <Badge className={cls}>{action}</Badge>;
}

export default function AuditLog() {
  const { data, isLoading } = useAuditLogs();
  const items = data?.items ?? [];

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Audit Log"
        subtitle="Immutable history of sensitive actions. Secrets and tokens are never recorded."
      />
      {isLoading ? (
        <Spinner label="Loading audit log…" />
      ) : items.length === 0 ? (
        <EmptyState
          title="No audit entries yet"
          description="Connecting integrations, changing policies, or managing notification channels will appear here."
        />
      ) : (
        <Card className="overflow-hidden p-0">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5">Resource</th>
                <th className="px-4 py-2.5">Actor</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50/60">
                  <td className="px-4 py-2.5"><ActionBadge action={log.action} /></td>
                  <td className="px-4 py-2.5 text-xs text-slate-600">
                    {log.resource_type}
                    {log.detail && typeof log.detail === "object" ? (
                      <span className="ml-1 text-slate-400">
                        {Object.entries(log.detail)
                          .map(([k, v]) => `${k}=${String(v)}`)
                          .slice(0, 2)
                          .join(" ")}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{log.actor}</td>
                  <td className="px-4 py-2.5">
                    <span className={log.status === "success" ? "text-emerald-700" : "text-rose-700"}>
                      {log.status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-400">{formatDateTime(log.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
