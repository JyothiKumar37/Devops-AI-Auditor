// Renders a unified diff with line-level coloring, plus an optional compact
// before/after summary of the changed lines. Read-only and presentational.

interface DiffViewProps {
  diff: string;
  before?: string | null;
  after?: string | null;
}

function lineClass(line: string): string {
  if (line.startsWith("+++") || line.startsWith("---")) return "text-slate-500";
  if (line.startsWith("@@")) return "text-cyan-700";
  if (line.startsWith("+")) return "bg-emerald-50 text-emerald-700";
  if (line.startsWith("-")) return "bg-rose-50 text-rose-700";
  return "text-slate-500";
}

export function DiffView({ diff, before, after }: DiffViewProps) {
  const lines = diff.replace(/\n$/, "").split("\n");

  return (
    <div className="space-y-3">
      {before || after ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-rose-700/80">
              Before
            </p>
            <pre className="overflow-x-auto rounded-lg border border-rose-200 bg-rose-50 p-3 font-mono text-xs text-rose-700">
              {before || "—"}
            </pre>
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-emerald-700/80">
              After
            </p>
            <pre className="overflow-x-auto rounded-lg border border-emerald-200 bg-emerald-50 p-3 font-mono text-xs text-emerald-700">
              {after || "—"}
            </pre>
          </div>
        </div>
      ) : null}

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50">
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
