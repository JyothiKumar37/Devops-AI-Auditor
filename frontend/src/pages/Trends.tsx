import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { TrendChart } from "@/components/TrendChart";
import type { TrendSeries } from "@/components/TrendChart";
import { Card, EmptyState, Spinner } from "@/components/ui";
import { useScan, useTrends } from "@/hooks/useScans";
import { SEVERITY_META } from "@/lib/format";

function shortDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

const RANGES = [
  { label: "Last 5", value: 5 },
  { label: "Last 10", value: 10 },
  { label: "All", value: 0 },
];

export default function Trends() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data: scan } = useScan(id);
  const isDone = scan?.status === "completed";
  const { data, isLoading } = useTrends(isDone ? id : null);
  const [range, setRange] = useState(0);

  const points = useMemo(() => {
    const all = data?.points ?? [];
    return range > 0 ? all.slice(-range) : all;
  }, [data, range]);

  if (scan && !isDone) {
    return (
      <Card className="p-6">
        <Spinner label={`Scan ${scan.status}…`} />
      </Card>
    );
  }
  if (isLoading || !data) return <Spinner />;

  if (data.points.length < 2) {
    return (
      <EmptyState
        title="Not enough history yet"
        description={`Trends compare this repository's scans over time. ${data.repository_name} has ${data.total_scans} completed scan${
          data.total_scans === 1 ? "" : "s"
        } — scan it again to build a timeline.`}
      />
    );
  }

  const labels = points.map((p) => shortDate(p.created_at));

  const readinessSeries: TrendSeries[] = [
    { label: "Readiness", color: "#7c3aed", values: points.map((p) => p.readiness) },
  ];
  const findingSeries: TrendSeries[] = [
    { label: "Total", color: "#0ea5e9", values: points.map((p) => p.total_findings) },
    { label: "New", color: "#f43f5e", values: points.map((p) => p.new_findings) },
    { label: "Fixed", color: "#16a34a", values: points.map((p) => p.fixed_findings) },
  ];
  const SEV_COLOR: Record<string, string> = {
    critical: "#e11d48",
    high: "#ea580c",
    medium: "#d97706",
    low: "#0ea5e9",
  };
  const severitySeries: TrendSeries[] = (["critical", "high", "medium", "low"] as const).map(
    (sev) => ({
      label: SEVERITY_META[sev]?.label ?? sev,
      color: SEV_COLOR[sev] ?? "#94a3b8",
      values: points.map((p) => p.severity_counts[sev] ?? 0),
    }),
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">
          {data.total_scans} completed scans of{" "}
          <span className="font-medium text-slate-700">{data.repository_name}</span>
        </p>
        <div className="inline-flex overflow-hidden rounded-lg border border-slate-300 text-xs">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => setRange(r.value)}
              className={`px-2.5 py-1 font-medium transition-colors ${
                range === r.value ? "bg-slate-900 text-white" : "bg-white text-slate-600 hover:bg-slate-50"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <Card className="p-5">
        <p className="section-title mb-2">Production readiness</p>
        <TrendChart series={readinessSeries} labels={labels} yMax={100} unit="/100" />
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <p className="section-title mb-2">Findings over time</p>
          <TrendChart series={findingSeries} labels={labels} />
        </Card>
        <Card className="p-5">
          <p className="section-title mb-2">Severity over time</p>
          <TrendChart series={severitySeries} labels={labels} />
        </Card>
      </div>
    </div>
  );
}
