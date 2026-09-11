// Export controls for the full audit report. Each button links directly to the
// backend export endpoint, which responds with a Content-Disposition attachment
// so the browser downloads the file. Disabled until the scan has completed.

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
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs font-medium uppercase tracking-wide text-slate-500">
        Export report
      </span>
      <div className="flex overflow-hidden rounded-lg border border-white/10">
        {FORMATS.map(({ format, label }, index) =>
          disabled ? (
            <span
              key={format}
              aria-disabled
              className={`px-3 py-1.5 text-xs font-medium text-slate-600 ${
                index > 0 ? "border-l border-white/10" : ""
              }`}
            >
              {label}
            </span>
          ) : (
            <a
              key={format}
              href={api.reportExportUrl(scanId, format)}
              download
              className={`px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white ${
                index > 0 ? "border-l border-white/10" : ""
              }`}
            >
              {label}
            </a>
          ),
        )}
      </div>
    </div>
  );
}
