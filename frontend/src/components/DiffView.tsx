// Renders a unified diff with line-level coloring, plus an optional compact
// before/after summary of the changed lines. Read-only and presentational.

interface DiffViewProps {
  diff: string;
  before?: string | null;
  after?: string | null;
}

function lineClass(line: string): string {
  if (line.startsWith("+++") || line.startsWith("---")) return "text-slate-500";
  if (line.startsWith("@@")) return "text-cyan-300";
  if (line.startsWith("+")) return "bg-emerald-500/10 text-emerald-300";
  if (line.startsWith("-")) return "bg-rose-500/10 text-rose-300";
  return "text-slate-400";
}

export function DiffView({ diff, before, after }: DiffViewProps) {
  const lines = diff.replace(/\n$/, "").split("\n");

  return (
    <div className="space-y-3">
      {before || after ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-rose-300/80">
              Before
            </p>
            <pre className="overflow-x-auto rounded-lg border border-rose-500/20 bg-rose-500/5 p-3 font-mono text-xs text-rose-200">
              {before || "—"}
            </pre>
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-emerald-300/80">
              After
            </p>
            <pre className="overflow-x-auto rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 font-mono text-xs text-emerald-200">
              {after || "—"}
            </pre>
          </div>
        </div>
      ) : null}

      <div className="overflow-x-auto rounded-lg border border-white/10 bg-slate-950/70">
        <pre className="min-w-full font-mono text-xs leading-relaxed">
          {lines.map((line, index) => (
            <div key={index} className={`px-3 ${lineClass(line)}`}>
              {line || " "}
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}
