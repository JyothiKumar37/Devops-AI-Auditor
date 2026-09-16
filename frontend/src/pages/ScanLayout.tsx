import { NavLink, Outlet, useParams } from "react-router-dom";

import { ReportExportMenu } from "@/components/ReportExportMenu";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Spinner } from "@/components/ui";
import { useReport, useScan } from "@/hooks/useScans";
import { prettyLabel, relativeTime } from "@/lib/format";

const TABS = [
  { to: "", label: "Overview", end: true, key: "overview" as const },
  { to: "findings", label: "Findings", key: "findings" as const },
  { to: "files", label: "Files", key: "files" as const },
  { to: "readiness", label: "Readiness", key: "readiness" as const },
  { to: "report", label: "Report", key: "report" as const },
];

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-slate-400">{label}</span>
      <span className={`text-slate-600 ${mono ? "font-mono text-[11px]" : ""}`}>{value}</span>
    </span>
  );
}

export default function ScanLayout() {
  const { scanId } = useParams();
  const { data: scan, isLoading } = useScan(scanId ?? null);
  const isDone = scan?.status === "completed";
  const { data: report } = useReport(isDone ? (scanId ?? null) : null);

  const counts: Record<string, number | undefined> = {
    findings: report?.total_findings,
    files: scan?.file_count,
  };

  return (
    <div>
      <div className="mb-4">
        <NavLink to="/scans" className="text-xs text-slate-500 hover:text-slate-700">
          ← All scans
        </NavLink>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2">
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            {scan?.repository_name ?? "Scan"}
          </h1>
          {scan ? <ScanStatusBadge status={scan.status} /> : null}
          {scanId ? (
            <div className="ml-auto">
              <ReportExportMenu scanId={scanId} disabled={scan?.status !== "completed"} />
            </div>
          ) : null}
        </div>
        {scan ? (
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs">
            <Meta label="source" value={prettyLabel(scan.source_type)} />
            <Meta label="files" value={String(scan.file_count)} mono />
            <Meta label="created" value={relativeTime(scan.created_at)} />
            <Meta label="id" value={scan.id.slice(0, 8)} mono />
          </div>
        ) : null}
      </div>

      <div className="mb-6 flex gap-1 overflow-x-auto border-b border-slate-200">
        {TABS.map((tab) => {
          const count = counts[tab.key];
          return (
            <NavLink
              key={tab.key}
              to={tab.to}
              end={tab.end}
              className={({ isActive }) =>
                `-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3.5 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? "border-slate-900 text-slate-900"
                    : "border-transparent text-slate-500 hover:text-slate-800"
                }`
              }
            >
              {tab.label}
              {typeof count === "number" ? (
                <span className="rounded-full bg-slate-100 px-1.5 text-[10px] font-medium tabular-nums text-slate-500">
                  {count}
                </span>
              ) : null}
            </NavLink>
          );
        })}
      </div>

      {isLoading && !scan ? <Spinner /> : <Outlet />}
    </div>
  );
}
