import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { CodeViewer } from "@/components/CodeViewer";
import { Card, Spinner } from "@/components/ui";
import { useScanFiles } from "@/hooks/useScans";
import { formatBytes, prettyLabel } from "@/lib/format";
import type { RepositoryFile } from "@/types/api";

export default function RepositoryFiles() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data, isLoading } = useScanFiles(id);
  const [selected, setSelected] = useState<RepositoryFile | null>(null);
  const [search, setSearch] = useState("");

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

  if (isLoading) return <Spinner />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[20rem_1fr]">
      <Card className="flex max-h-[36rem] flex-col overflow-hidden">
        <div className="border-b border-white/10 p-3">
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
                    active?.id === f.id ? "bg-brand/10 text-brand" : "text-slate-400 hover:bg-white/5"
                  }`}
                >
                  <span className="truncate font-mono">{f.path}</span>
                  <span className="shrink-0 text-slate-600">{formatBytes(f.size)}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </Card>

      <Card className="flex min-h-[36rem] flex-col overflow-hidden">
        <div className="border-b border-white/10 px-4 py-2.5 font-mono text-xs text-slate-400">
          {active?.path ?? "Select a file"}
        </div>
        <div className="flex-1">
          {active ? (
            <CodeViewer
              scanId={id as string}
              fileId={active.id}
              path={active.path}
              fileType={active.file_type}
            />
          ) : null}
        </div>
      </Card>
    </div>
  );
}
