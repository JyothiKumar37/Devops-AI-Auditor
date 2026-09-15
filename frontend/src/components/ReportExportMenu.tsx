// Report actions for the scan header: view the report in-app, or download it as
// PDF / HTML / JSON. Downloads link directly to the backend export endpoint,
// which responds with a Content-Disposition attachment.

import { Link } from "react-router-dom";

import { api } from "@/lib/api";

type Format = "json" | "html" | "pdf";

const FORMATS: { format: Format; label: string }[] = [
  { format: "pdf", label: "PDF" },
  { format: "html", label: "HTML" },
  { format: "json", label: "JSON" },
];

export function ReportExportMenu({
  scanId,
  disabled = false,
}: {
  scanId: string;
  disabled?: boolean;
}) {
  if (disabled) {
    return (
      <span className="text-xs font-medium text-slate-600">Report available once scan completes</span>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <Link
        to={`/scans/${scanId}/report`}
        className="btn-primary px-3 py-1.5 text-xs"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M2.5 12S5.5 5.5 12 5.5 21.5 12 21.5 12 18.5 18.5 12 18.5 2.5 12 2.5 12z"
          />
        </svg>
        View report
      </Link>
      <div className="flex overflow-hidden rounded-lg border border-white/10">
        {FORMATS.map(({ format, label }, index) => (
          <a
            key={format}
            href={api.reportExportUrl(scanId, format)}
            className={`px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white ${
              index > 0 ? "border-l border-white/10" : ""
            }`}
          >
            {label}
          </a>
        ))}
      </div>
    </div>
  );
}
