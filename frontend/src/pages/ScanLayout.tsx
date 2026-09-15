import { NavLink, Outlet, useParams } from "react-router-dom";

import { ReportExportMenu } from "@/components/ReportExportMenu";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Spinner } from "@/components/ui";
import { useScan } from "@/hooks/useScans";
import { relativeTime } from "@/lib/format";

const TABS = [
  { to: "", label: "Overview", end: true },
  { to: "findings", label: "Findings" },
  { to: "files", label: "Files" },
  { to: "readiness", label: "Readiness" },
  { to: "report", label: "Report" },
];

export default function ScanLayout() {
  const { scanId } = useParams();
  const { data: scan, isLoading } = useScan(scanId ?? null);

  return (
    <div>
      <div className="mb-5">
        <NavLink to="/scans" className="text-xs text-slate-500 hover:text-slate-700">
          ← All scans
        </NavLink>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold tracking-tight text-slate-900">
            {scan?.repository_name ?? "Scan"}
          </h1>
          {scan ? <ScanStatusBadge status={scan.status} /> : null}
          {scan ? (
            <span className="text-xs text-slate-500">
              {scan.file_count} files · {relativeTime(scan.created_at)}
            </span>
          ) : null}
          {scanId ? (
            <div className="ml-auto">
              <ReportExportMenu scanId={scanId} disabled={scan?.status !== "completed"} />
            </div>
          ) : null}
        </div>
      </div>

      <div className="mb-6 flex gap-1 border-b border-slate-200">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to || "overview"}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              `-mb-px border-b-2 px-4 py-2 text-sm font-medium transition ${
                isActive
                  ? "border-brand text-slate-900"
                  : "border-transparent text-slate-500 hover:text-slate-800"
              }`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </div>

      {isLoading && !scan ? <Spinner /> : <Outlet />}
    </div>
  );
}
