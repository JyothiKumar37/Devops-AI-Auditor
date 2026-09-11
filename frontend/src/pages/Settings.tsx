import { Badge, Card, PageHeader } from "@/components/ui";
import { useHealth } from "@/hooks/useHealth";
import { SCANNER_CATALOG } from "@/data/scanners";
import { MAX_UPLOAD_MB } from "@/lib/format";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-white/5 py-2.5 last:border-0">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="text-sm text-slate-200">{value}</span>
    </div>
  );
}

export default function Settings() {
  const { data: health } = useHealth();

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Settings" subtitle="Environment, scanners and system status." />

      <div className="space-y-6">
        <Card className="p-5">
          <h2 className="mb-2 text-sm font-semibold text-white">System</h2>
          <Row
            label="API status"
            value={
              <Badge
                className={
                  health?.status === "healthy"
                    ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
                    : "bg-amber-500/15 text-amber-300 ring-amber-500/30"
                }
              >
                {health?.status ?? "unknown"}
              </Badge>
            }
          />
          <Row label="Version" value={health?.version ?? "—"} />
          <Row label="Environment" value={health?.environment ?? "—"} />
          {health?.components.map((c) => (
            <Row
              key={c.name}
              label={`Dependency · ${c.name}`}
              value={
                <span className={c.state === "healthy" ? "text-emerald-300" : "text-rose-300"}>
                  {c.state}
                </span>
              }
            />
          ))}
        </Card>

        <Card className="p-5">
          <h2 className="mb-2 text-sm font-semibold text-white">Upload limits</h2>
          <Row label="Max archive size" value={`${MAX_UPLOAD_MB} MB`} />
          <Row label="Accepted formats" value=".zip" />
          <Row label="Code execution" value="Never — files are read-only" />
        </Card>

        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold text-white">Scanners</h2>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {SCANNER_CATALOG.map((s) => (
              <div key={s.id} className="flex items-center justify-between rounded-lg border border-white/5 bg-slate-950/40 px-3 py-2">
                <div>
                  <p className="text-sm text-slate-200">{s.label}</p>
                  <p className="text-[11px] text-slate-500">{s.description}</p>
                </div>
                <Badge className="bg-emerald-500/10 text-emerald-300 ring-emerald-500/20">active</Badge>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Deterministic engines run always. Hadolint, Trivy, kube-linter, Checkov, TFLint,
            actionlint and Gitleaks are used automatically when installed. The AI reasoning layer
            uses the configured LLM provider (or a deterministic fallback).
          </p>
        </Card>
      </div>
    </div>
  );
}
