import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Card, EmptyState, Field, SeverityPill, Spinner } from "@/components/ui";
import { useFindings, useScanFiles } from "@/hooks/useScans";
import { SEVERITY_ORDER, prettyLabel } from "@/lib/format";
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
  const { data, isLoading } = useFindings(id, {});
  const { data: files } = useScanFiles(id);

  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
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

  return (
    <div>
      <Card className="mb-4 p-4">
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
        <EmptyState title="No findings match" description="Try relaxing the filters." />
      ) : (
        <Card>
          <div className="flex items-center justify-between border-b border-white/10 px-5 py-2.5 text-xs text-slate-500">
            <span>
              Showing {filtered.length} of {items.length} findings
            </span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/5 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-5 py-2 font-medium">Severity</th>
                <th className="px-5 py-2 font-medium">Finding</th>
                <th className="px-5 py-2 font-medium">Scanner</th>
                <th className="px-5 py-2 font-medium">Location</th>
                <th className="px-5 py-2 font-medium">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => {
                const meta = fileById.get(f.file_id ?? "");
                return (
                  <tr key={f.id} className="border-b border-white/5 last:border-0 hover:bg-white/5">
                    <td className="px-5 py-3">
                      <SeverityPill severity={f.severity} />
                    </td>
                    <td className="px-5 py-3">
                      <Link
                        to={`/scans/${id}/findings/${f.id}`}
                        className="font-medium text-slate-100 hover:text-brand"
                      >
                        {f.title}
                      </Link>
                      <p className="text-xs text-slate-500">
                        {f.rule_id} · {prettyLabel(f.category)}
                      </p>
                    </td>
                    <td className="px-5 py-3 text-slate-400">{f.scanner}</td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-400">
                      {meta?.path ?? "—"}
                      {f.line_number ? `:${f.line_number}` : ""}
                    </td>
                    <td className="px-5 py-3 text-slate-400">{prettyLabel(f.confidence)}</td>
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
