import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import { Badge, Card, EmptyState, StatCard, Spinner } from "@/components/ui";
import { useDependencies, useScan } from "@/hooks/useScans";
import { api } from "@/lib/api";
import { prettyLabel } from "@/lib/format";

const ECOSYSTEM_LABEL: Record<string, string> = {
  npm: "npm (Node.js)",
  pypi: "PyPI (Python)",
};

export default function Dependencies() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data: scan } = useScan(id);
  const isDone = scan?.status === "completed";
  const { data, isLoading } = useDependencies(isDone ? id : null);

  const [ecosystem, setEcosystem] = useState("");
  const [scope, setScope] = useState("");
  const [search, setSearch] = useState("");

  const items = useMemo(() => data?.items ?? [], [data]);
  const ecosystems = useMemo(
    () => [...new Set(items.map((i) => i.ecosystem))].sort(),
    [items],
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return items.filter((i) => {
      if (ecosystem && i.ecosystem !== ecosystem) return false;
      if (scope && i.scope !== scope) return false;
      if (term && !`${i.name} ${i.version}`.toLowerCase().includes(term)) return false;
      return true;
    });
  }, [items, ecosystem, scope, search]);

  if (scan && !isDone) {
    return (
      <Card className="p-6">
        <Spinner label={`Scan ${scan.status}…`} />
      </Card>
    );
  }
  if (isLoading || !data) return <Spinner />;

  if (data.total === 0) {
    return (
      <EmptyState
        title="No dependencies detected"
        description="No supported dependency manifests (package.json, requirements.txt, pyproject.toml, poetry.lock, package-lock.json) were found in this repository."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Total" value={data.total} hint="components" />
        <StatCard label="Direct" value={data.direct} accent="text-brand-deep" />
        <StatCard label="Transitive" value={data.transitive} />
        <StatCard
          label="Ecosystems"
          value={Object.keys(data.ecosystem_counts).length}
          hint={Object.entries(data.ecosystem_counts)
            .map(([e, n]) => `${e}: ${n}`)
            .join(" · ")}
        />
      </div>

      {/* Honest note: this is an inventory, not a vulnerability scan. */}
      {!data.vulnerabilities_available ? (
        <Card className="border-l-4 border-l-amber-400 p-4">
          <p className="text-sm font-medium text-slate-800">Software bill of materials</p>
          <p className="mt-0.5 text-xs text-slate-500">
            This is a dependency inventory (CycloneDX SBOM). No vulnerability database is
            bundled, so CVE/severity data is not shown — the counts are not a claim that the
            dependencies are free of vulnerabilities.
          </p>
        </Card>
      ) : null}

      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Search</span>
            <input
              className="input"
              placeholder="Package name…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Ecosystem</span>
            <select className="input" value={ecosystem} onChange={(e) => setEcosystem(e.target.value)}>
              <option value="">All</option>
              {ecosystems.map((e) => (
                <option key={e} value={e}>
                  {ECOSYSTEM_LABEL[e] ?? e}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-medium uppercase tracking-wide text-slate-500">Scope</span>
            <select className="input" value={scope} onChange={(e) => setScope(e.target.value)}>
              <option value="">All</option>
              <option value="direct">Direct</option>
              <option value="transitive">Transitive</option>
            </select>
          </label>
          <a
            href={api.sbomDownloadUrl(id as string)}
            className="ml-auto inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white transition hover:bg-accent-deep"
            download
          >
            Download SBOM (CycloneDX)
          </a>
        </div>
      </Card>

      {filtered.length === 0 ? (
        <EmptyState title="No dependencies match" description="Try relaxing the filters." />
      ) : (
        <Card className="overflow-hidden">
          <div className="border-b border-slate-200/80 px-5 py-2.5 text-xs text-slate-500">
            Showing <span className="font-semibold text-slate-700">{filtered.length}</span> of{" "}
            {items.length} components
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200/80 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-5 py-2.5 font-semibold">Package</th>
                <th className="px-5 py-2.5 font-semibold">Version</th>
                <th className="px-5 py-2.5 font-semibold">Ecosystem</th>
                <th className="px-5 py-2.5 font-semibold">Scope</th>
                <th className="px-5 py-2.5 font-semibold">License</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((d) => (
                <tr key={d.purl} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/70">
                  <td className="px-5 py-2.5 font-medium text-slate-800">{d.name}</td>
                  <td className="px-5 py-2.5 font-mono text-xs text-slate-600">{d.version}</td>
                  <td className="px-5 py-2.5 text-slate-500">{d.ecosystem}</td>
                  <td className="px-5 py-2.5">
                    <Badge
                      className={
                        d.scope === "direct"
                          ? "bg-brand-50 text-brand-deep ring-brand-600/20"
                          : "bg-slate-100 text-slate-600 ring-slate-300"
                      }
                    >
                      {prettyLabel(d.scope)}
                    </Badge>
                  </td>
                  <td className="px-5 py-2.5 text-xs text-slate-500">{d.license ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
