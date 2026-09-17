import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { Card, EmptyState, Field, SeverityPill, Spinner } from "@/components/ui";
import { useFindings, useScanFiles } from "@/hooks/useScans";
import { SEVERITY_ORDER, prettyLabel, severityMeta } from "@/lib/format";
import type { Finding } from "@/types/api";

function Select({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  placeholder: string;
}) {
  return (
    <select className="input" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {prettyLabel(o)}
        </option>
      ))}
    </select>
  );
}

export default function Findings() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const [searchParams] = useSearchParams();
  const { data, isLoading } = useFindings(id, {});
  const { data: files } = useScanFiles(id);

  // Seed from the URL so deep-links (e.g. ?severity=critical from the
  // dashboard or overview) open pre-filtered.
  const [severity, setSeverity] = useState(() => searchParams.get("severity") ?? "");
  const [category, setCategory] = useState(() => searchParams.get("category") ?? "");
  const [scanner, setScanner] = useState("");
  const [confidence, setConfidence] = useState("");
  const [fileType, setFileType] = useState("");
  const [search, setSearch] = useState("");

  const fileById = useMemo(() => {
    const map = new Map<string, { path: string; file_type: string }>();
    files?.items.forEach((f) => map.set(f.id, { path: f.path, file_type: f.file_type }));
    return map;
  }, [files]);

  const items = useMemo(() => data?.items ?? [], [data]);
  const options = useMemo(() => {
    const uniq = (fn: (f: Finding) => string) => [...new Set(items.map(fn))].filter(Boolean).sort();
    return {
      categories: uniq((f) => f.category),
      scanners: uniq((f) => f.scanner),
      fileTypes: uniq((f) => fileById.get(f.file_id ?? "")?.file_type ?? ""),
    };
  }, [items, fileById]);

  const severityCounts = useMemo(() => {
    const m: Record<string, number> = {};
    items.forEach((f) => {
      m[f.severity] = (m[f.severity] ?? 0) + 1;
    });
    return m;
  }, [items]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return items.filter((f) => {
      if (severity && f.severity !== severity) return false;
      if (category && f.category !== category) return false;
      if (scanner && f.scanner !== scanner) return false;
      if (confidence && f.confidence !== confidence) return false;
      const meta = fileById.get(f.file_id ?? "");
      if (fileType && meta?.file_type !== fileType) return false;
      if (term) {
        const hay = `${f.title} ${f.rule_id} ${meta?.path ?? ""}`.toLowerCase();
        if (!hay.includes(term)) return false;
      }
      return true;
    });
  }, [items, severity, category, scanner, confidence, fileType, search, fileById]);

  const activeFilters =
    Boolean(severity || category || scanner || confidence || fileType || search.trim());

  return (
    <div className="space-y-4">
      {/* Severity summary strip — click a severity to filter. */}
      <Card className="flex flex-wrap items-center gap-2 p-3">
        <button
          type="button"
          onClick={() => setSeverity("")}
          className={`chip transition-colors ${
            severity === ""
              ? "bg-slate-900 text-white ring-slate-900"
              : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"
          }`}
        >
          All · {items.length}
        </button>
        {SEVERITY_ORDER.map((sev) => {
          const count = severityCounts[sev] ?? 0;
          const active = severity === sev;
          const meta = severityMeta(sev);
          return (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverity(active ? "" : sev)}
              className={`chip transition-all ${
                active ? `${meta.badge} ring-2` : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden />
              {meta.label} · {count}
            </button>
          );
        })}
      </Card>

      <Card className="p-4">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
          <Field label="Search">
            <input
              className="input"
              placeholder="Title, rule, file…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </Field>
          <Field label="Severity">
            <Select value={severity} onChange={setSeverity} options={[...SEVERITY_ORDER]} placeholder="All" />
          </Field>
          <Field label="Category">
            <Select value={category} onChange={setCategory} options={options.categories} placeholder="All" />
          </Field>
          <Field label="Scanner">
            <Select value={scanner} onChange={setScanner} options={options.scanners} placeholder="All" />
          </Field>
          <Field label="Confidence">
            <Select value={confidence} onChange={setConfidence} options={["high", "medium", "low"]} placeholder="All" />
          </Field>
          <Field label="File type">
            <Select value={fileType} onChange={setFileType} options={options.fileTypes} placeholder="All" />
          </Field>
        </div>
      </Card>

      {isLoading ? (
        <Spinner />
      ) : filtered.length === 0 ? (
        <EmptyState
          title={activeFilters ? "No findings match" : "No findings"}
          description={activeFilters ? "Try relaxing the filters." : "This scan produced no findings."}
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-200/80 px-5 py-2.5 text-xs text-slate-500">
            <span>
              Showing <span className="font-semibold text-slate-700">{filtered.length}</span> of {items.length} findings
            </span>
            {activeFilters ? (
              <button
                type="button"
                onClick={() => {
                  setSeverity("");
                  setCategory("");
                  setScanner("");
                  setConfidence("");
                  setFileType("");
                  setSearch("");
                }}
                className="font-medium text-brand hover:text-brand-deep hover:underline"
              >
                Clear filters
              </button>
            ) : null}
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200/80 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-5 py-2.5 font-semibold">Severity</th>
                <th className="px-5 py-2.5 font-semibold">Finding</th>
                <th className="px-5 py-2.5 font-semibold">Scanner</th>
                <th className="px-5 py-2.5 font-semibold">Location</th>
                <th className="px-5 py-2.5 font-semibold">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => {
                const meta = fileById.get(f.file_id ?? "");
                return (
                  <tr key={f.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/70">
                    <td className="px-5 py-3">
                      <SeverityPill severity={f.severity} />
                    </td>
                    <td className="px-5 py-3">
                      <Link
                        to={`/scans/${id}/findings/${f.id}`}
                        className="font-medium text-slate-900 hover:text-brand"
                      >
                        {f.title}
                      </Link>
                      <p className="text-xs text-slate-500">
                        {f.rule_id} · {prettyLabel(f.category)}
                      </p>
                    </td>
                    <td className="px-5 py-3 text-slate-500">{f.scanner}</td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-500">
                      {meta?.path ?? "—"}
                      {f.line_number ? `:${f.line_number}` : ""}
                    </td>
                    <td className="px-5 py-3 text-slate-500">{prettyLabel(f.confidence)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
