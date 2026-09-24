import { useMemo } from "react";
import { useParams, useSearchParams } from "react-router-dom";

import { Card, EmptyState, SectionHeading, Spinner, StatCard } from "@/components/ui";
import { useScan, useScanDiff, useScans } from "@/hooks/useScans";
import { relativeTime, severityMeta, SEVERITY_ORDER } from "@/lib/format";
import type { ScanDiffFinding } from "@/types/api";

function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta === null) {
    return <span className="text-xs text-slate-400">no baseline</span>;
  }
  if (delta === 0) {
    return <span className="text-xs font-medium text-slate-500">no change</span>;
  }
  const improved = delta > 0;
  return (
    <span
      className={`inline-flex items-center gap-1 text-sm font-semibold ${
        improved ? "text-emerald-600" : "text-rose-600"
      }`}
    >
      {improved ? "▲" : "▼"} {improved ? "+" : ""}
      {delta}
    </span>
  );
}

function SeverityCountRow({ counts }: { counts: Record<string, number> }) {
  const active = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (active.length === 0) return null;
  return (
    <div className="mt-1 flex flex-wrap gap-1.5">
      {active.map((sev) => {
        const meta = severityMeta(sev);
        return (
          <span
            key={sev}
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${meta.badge}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden />
            {counts[sev]} {sev}
          </span>
        );
      })}
    </div>
  );
}

function FindingList({
  title,
  findings,
  tone,
}: {
  title: string;
  findings: ScanDiffFinding[];
  tone: "new" | "fixed";
}) {
  const accent = tone === "new" ? "text-rose-600" : "text-emerald-600";
  return (
    <Card className="p-5">
      <div className="flex items-baseline justify-between">
        <p className="section-title">{title}</p>
        <span className={`text-sm font-bold tabular-nums ${accent}`}>{findings.length}</span>
      </div>
      {findings.length === 0 ? (
        <p className="mt-2 text-sm text-slate-500">None.</p>
      ) : (
        <ul className="mt-2 divide-y divide-slate-100">
          {findings.map((f, i) => {
            const meta = severityMeta(f.severity);
            return (
              <li key={`${f.rule_id}-${f.file ?? ""}-${i}`} className="py-2.5">
                <div className="flex items-start gap-2.5">
                  <span
                    className={`mt-0.5 inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${meta.badge}`}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden />
                    {meta.label}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm text-slate-800">{f.title}</p>
                    <p className="mt-0.5 truncate text-xs text-slate-500">
                      <span className="font-mono">{f.rule_id}</span>
                      {f.file ? (
                        <>
                          {" · "}
                          <span className="font-mono">
                            {f.file}
                            {f.line ? `:${f.line}` : ""}
                          </span>
                        </>
                      ) : null}
                    </p>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

export default function ScanDiff() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const [searchParams, setSearchParams] = useSearchParams();
  const base = searchParams.get("base") ?? undefined;

  const { data: scan } = useScan(id);
  const { data: diff, isLoading, isError, error } = useScanDiff(id, base);
  const { data: scanList } = useScans();

  // Prior completed scans of the same repository make valid comparison bases.
  const baseOptions = useMemo(() => {
    if (!scanList || !scan) return [];
    return scanList.items.filter(
      (s) =>
        s.repository_name === scan.repository_name &&
        s.status === "completed" &&
        s.id !== scan.id,
    );
  }, [scanList, scan]);

  if (isLoading && !diff) return <Spinner label="Computing diff…" />;
  if (isError) {
    return (
      <EmptyState
        title="Could not compute the diff"
        description={(error as Error)?.message ?? "The comparison could not be loaded."}
      />
    );
  }
  if (!diff) return <Spinner />;

  const onSelectBase = (value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set("base", value);
    else next.delete("base");
    setSearchParams(next, { replace: true });
  };

  return (
    <div className="space-y-4">
      <Card className="p-5">
        <SectionHeading
          title="Scan comparison"
          subtitle="Findings are matched across scans independently of line numbers, then partitioned into new, fixed and unchanged."
        />
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">
              Compare against
            </span>
            <select
              value={base ?? ""}
              onChange={(e) => onSelectBase(e.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/20"
            >
              <option value="">Previous scan (auto)</option>
              {baseOptions.map((s) => (
                <option key={s.id} value={s.id}>
                  {relativeTime(s.created_at)} · {s.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>

          {diff.base_scan_id ? (
            <div className="flex items-center gap-4 rounded-lg bg-slate-50 px-4 py-3">
              <div className="text-center">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  Base
                </p>
                <p className="text-xl font-bold tabular-nums text-slate-700">
                  {diff.base_readiness}
                </p>
                <p className="text-[11px] text-slate-400">{relativeTime(diff.base_created_at)}</p>
              </div>
              <span className="text-slate-300">→</span>
              <div className="text-center">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  Head
                </p>
                <p className="text-xl font-bold tabular-nums text-slate-900">
                  {diff.head_readiness}
                </p>
                <p className="text-[11px] text-slate-400">{relativeTime(diff.head_created_at)}</p>
              </div>
              <div className="border-l border-slate-200 pl-4 text-center">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  Readiness
                </p>
                <DeltaBadge delta={diff.readiness_delta} />
              </div>
            </div>
          ) : (
            <p className="max-w-sm text-sm text-slate-500">
              No earlier scan of <span className="font-medium">{diff.repository_name}</span> to
              compare against — every current finding is shown as new.
            </p>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="New" value={diff.summary.new} accent="text-rose-600" hint="not in base" />
        <StatCard
          label="Fixed"
          value={diff.summary.fixed}
          accent="text-emerald-600"
          hint="gone in head"
        />
        <StatCard
          label="Unchanged"
          value={diff.summary.unchanged}
          accent="text-slate-700"
          hint="present in both"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          <SeverityCountRow counts={diff.new_severity_counts} />
          <FindingList title="New findings" findings={diff.new_findings} tone="new" />
        </div>
        <div className="space-y-2">
          <SeverityCountRow counts={diff.fixed_severity_counts} />
          <FindingList title="Fixed findings" findings={diff.fixed_findings} tone="fixed" />
        </div>
      </div>
    </div>
  );
}
