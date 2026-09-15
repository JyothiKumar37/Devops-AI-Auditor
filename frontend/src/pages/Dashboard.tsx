import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, ScoreRing, Spinner, StatCard } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import { relativeTime } from "@/lib/format";

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

export default function Dashboard() {
  const { data, isLoading, isError } = useStats();

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="animate-in relative overflow-hidden rounded-2xl bg-hero-gradient p-6 text-white shadow-brand-lg sm:p-8">
        <div className="pointer-events-none absolute inset-0 bg-grid-faint [background-size:34px_34px] opacity-40" />
        <div className="pointer-events-none absolute -right-16 -top-24 h-64 w-64 rounded-full bg-white/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 left-1/3 h-56 w-56 rounded-full bg-fuchsia-400/20 blur-3xl" />
        <div className="relative flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div className="max-w-xl">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-white/15 px-2.5 py-0.5 text-xs font-medium text-white ring-1 ring-inset ring-white/25">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" aria-hidden />
              Security &amp; readiness
            </span>
            <h1 className="mt-3 text-2xl font-bold tracking-tight sm:text-3xl">
              Ship infrastructure with confidence.
            </h1>
            <p className="mt-2 max-w-lg text-sm text-indigo-100">
              Continuous auditing of Docker, Kubernetes, Terraform, CI/CD and secrets — with
              AI-grounded reasoning and a production-readiness score.
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Link
                to="/scan/new"
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-white px-3.5 py-2 text-sm font-semibold text-indigo-700 shadow-sm transition hover:bg-indigo-50"
              >
                <Icon path="M12 4v16m8-8H4" />
                New Scan
              </Link>
              <Link
                to="/scans"
                className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/30 bg-white/10 px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-white/20"
              >
                View history
              </Link>
            </div>
          </div>
          {data ? (
            <div className="flex items-center gap-4 rounded-2xl bg-white p-5 shadow-xl ring-1 ring-black/5">
              <ScoreRing score={Math.round(data.average_readiness)} size={112} />
              <div>
                <p className="section-title">Avg readiness</p>
                <p className="mt-1 text-sm text-slate-500">across completed scans</p>
              </div>
            </div>
          ) : null}
        </div>
      </div>

      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load dashboard" description="Is the backend reachable?" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard
              label="Total scans"
              value={data.total_scans}
              tone="indigo"
              icon={<Icon path="M4 6h16M4 12h16M4 18h16" />}
            />
            <StatCard
              label="Repositories"
              value={data.repositories_scanned}
              tone="violet"
              icon={<Icon path="M3 7h18M3 12h18M3 17h18" />}
            />
            <StatCard
              label="Critical issues"
              value={data.critical_issues}
              tone="rose"
              icon={<Icon path="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L14.7 3.9a2 2 0 00-3.4 0z" />}
            />
            <StatCard
              label="High issues"
              value={data.high_issues}
              tone="amber"
              icon={<Icon path="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L14.7 3.9a2 2 0 00-3.4 0z" />}
            />
          </div>

          <Card className="animate-in overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
              <h2 className="text-sm font-semibold text-slate-900">Latest scans</h2>
              <Link to="/scans" className="text-xs font-medium text-brand hover:underline">
                View all
              </Link>
            </div>
            {data.latest_scans.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No scans yet"
                  description="Upload a repository to run your first audit."
                  action={
                    <Link to="/scan/new" className="btn-primary">
                      New Scan
                    </Link>
                  }
                />
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-5 py-2.5 font-medium">Repository</th>
                    <th className="px-5 py-2.5 font-medium">Status</th>
                    <th className="px-5 py-2.5 font-medium">Files</th>
                    <th className="px-5 py-2.5 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.latest_scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="border-b border-slate-200 transition last:border-0 hover:bg-slate-50"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-slate-900 hover:text-brand"
                        >
                          {scan.repository_name}
                        </Link>
                      </td>
                      <td className="px-5 py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-5 py-3 text-slate-500">{scan.file_count}</td>
                      <td className="px-5 py-3 text-slate-500">{relativeTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
