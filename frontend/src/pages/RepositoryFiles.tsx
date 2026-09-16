import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { CodeViewer, type CodeMarker } from "@/components/CodeViewer";
import { Card, Spinner } from "@/components/ui";
import { useFindings, useScanFiles } from "@/hooks/useScans";
import { formatBytes, prettyLabel, severityMeta } from "@/lib/format";
import type { RepositoryFile } from "@/types/api";

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export default function RepositoryFiles() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data, isLoading } = useScanFiles(id);
  const { data: findingsData } = useFindings(id, {});
  const [selected, setSelected] = useState<RepositoryFile | null>(null);
  const [search, setSearch] = useState("");

  const findings = useMemo(() => findingsData?.items ?? [], [findingsData]);
  const fileMeta = useMemo(() => {
    const m = new Map<string, { count: number; worst: string; rank: number }>();
    findings.forEach((f) => {
      if (!f.file_id) return;
      const rank = SEV_RANK[f.severity] ?? 0;
      const cur = m.get(f.file_id);
      if (!cur) m.set(f.file_id, { count: 1, worst: f.severity, rank });
      else {
        cur.count += 1;
        if (rank > cur.rank) {
          cur.rank = rank;
          cur.worst = f.severity;
        }
      }
    });
    return m;
  }, [findings]);

  const groups = useMemo(() => {
    const map = new Map<string, RepositoryFile[]>();
    (data?.items ?? [])
      .filter((f) => f.path.toLowerCase().includes(search.trim().toLowerCase()))
      .forEach((f) => {
        const key = f.file_type;
        if (!map.has(key)) map.set(key, []);
        map.get(key)!.push(f);
      });
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [data, search]);

  const active = selected ?? data?.items[0] ?? null;

  const markers: CodeMarker[] = useMemo(() => {
    if (!active) return [];
    return findings
      .filter((f) => f.file_id === active.id && f.line_number)
      .map((f) => ({
        line: f.line_number as number,
        severity: f.severity,
        message: `${f.severity.toUpperCase()} · ${f.rule_id}: ${f.title}`,
      }));
  }, [findings, active]);

  if (isLoading) return <Spinner />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[20rem_1fr]">
      <Card className="flex max-h-[36rem] flex-col overflow-hidden">
        <div className="border-b border-slate-200 p-3">
          <input
            className="input w-full"
            placeholder="Filter files…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="overflow-y-auto p-2">
          {groups.map(([type, files]) => (
            <div key={type} className="mb-3">
              <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                {prettyLabel(type)} · {files.length}
              </p>
              {files.map((f) => (
                <button
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-xs transition ${
                    active?.id === f.id ? "bg-slate-100 text-slate-900" : "text-slate-500 hover:bg-slate-50"
                  }`}
                >
                  <span className="truncate font-mono">{f.path}</span>
                  <span className="flex shrink-0 items-center gap-1.5">
                    {fileMeta.get(f.id) ? (
                      <span
                        className={`rounded-full px-1.5 font-medium tabular-nums ring-1 ring-inset ${
                          severityMeta(fileMeta.get(f.id)!.worst).badge
                        }`}
                      >
                        {fileMeta.get(f.id)!.count}
                      </span>
                    ) : null}
                    <span className="text-slate-400">{formatBytes(f.size)}</span>
                  </span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </Card>

      <Card className="flex min-h-[36rem] flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 px-4 py-2.5">
          <span className="truncate font-mono text-xs text-slate-500">
            {active?.path ?? "Select a file"}
          </span>
          {active && fileMeta.get(active.id) ? (
            <span
              className={`shrink-0 text-xs font-medium ${severityMeta(fileMeta.get(active.id)!.worst).text}`}
            >
              {fileMeta.get(active.id)!.count} finding{fileMeta.get(active.id)!.count === 1 ? "" : "s"}
            </span>
          ) : null}
        </div>
        <div className="flex-1">
          {active ? (
            <CodeViewer
              scanId={id as string}
              fileId={active.id}
              path={active.path}
              fileType={active.file_type}
              markers={markers}
            />
          ) : null}
        </div>
      </Card>
    </div>
  );
}
