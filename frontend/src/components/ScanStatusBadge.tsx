import type { ScanStatus } from "@/types/api";

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending: "bg-slate-100 text-slate-600 ring-slate-500/20",
  running: "bg-sky-50 text-sky-700 ring-sky-600/20",
  completed: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  failed: "bg-rose-50 text-rose-700 ring-rose-600/20",
  cancelled: "bg-amber-50 text-amber-700 ring-amber-600/20",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${STATUS_STYLES[status]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {status}
    </span>
  );
}
