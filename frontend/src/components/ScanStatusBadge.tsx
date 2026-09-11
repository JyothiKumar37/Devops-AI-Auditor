import type { ScanStatus } from "@/types/api";

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  running: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  completed: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  failed: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  cancelled: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
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
