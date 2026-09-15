import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";

import {
  Card,
  EmptyState,
  Meter,
  ScoreRing,
  SectionHeading,
  Spinner,
} from "@/components/ui";
import { useReportModel } from "@/hooks/useScans";
import { api } from "@/lib/api";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  formatDateTime,
  prettyLabel,
  scoreColor,
  severityMeta,
} from "@/lib/format";
import type { CrossFileRisk, ReportFinding, ReportModel } from "@/types/api";

function DownloadBar({ scanId }: { scanId: string }) {
  const actions: { label: string; href: string; primary?: boolean }[] = [
    { label: "Open printable view", href: api.reportExportUrl(scanId, "html", false) },
    { label: "Download PDF", href: api.reportExportUrl(scanId, "pdf"), primary: true },
    { label: "JSON", href: api.reportExportUrl(scanId, "json") },
  ];
  return (
    <div className="flex flex-wrap items-center gap-2">
      {actions.map((a) => (
        <a
          key={a.label}
          href={a.href}
          target={a.href.includes("download=false") ? "_blank" : undefined}
          rel="noreferrer"
          className={a.primary ? "btn-primary" : "btn-ghost"}
        >
          {a.label}
        </a>
      ))}
    </div>
  );
}

function FindingRow({ f }: { f: ReportFinding }) {
  const [open, setOpen] = useState(false);
  const meta = severityMeta(f.severity);
  return (
    <div className="panel overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-slate-50"
      >
        <span className={`h-2 w-2 shrink-0 rounded-full ${meta.dot}`} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-slate-900">{f.title}</span>
          <span className="mt-0.5 block truncate font-mono text-[11px] text-slate-500">
            {f.file ?? "—"}
            {f.line ? `:${f.line}` : ""}
          </span>
        </span>
        <span className={`chip ${meta.badge}`}>{meta.label}</span>
        <span className="hidden font-mono text-[11px] text-slate-500 sm:inline">{f.rule_id}</span>
        <svg
          className={`h-4 w-4 shrink-0 text-slate-500 transition ${open ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open ? (
        <div className="space-y-3 border-t border-slate-200 px-4 py-3">
          {f.description ? <p className="text-sm text-slate-700">{f.description}</p> : null}
          {f.evidence ? (
            <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800">
              {f.evidence}
            </pre>
          ) : null}
          {f.recommendation ? (
            <p className="text-sm text-slate-700">
              <span className="font-semibold text-slate-800">Recommendation: </span>
              {f.recommendation}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-4 text-[11px] text-slate-500">
            <span>Scanner: {f.scanner}</span>
            <span>Category: {prettyLabel(f.category)}</span>
            <span>Confidence: {prettyLabel(f.confidence)}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ListCard({ title, items, tone }: { title: string; items: string[]; tone: string }) {
  if (items.length === 0) return null;
  return (
    <Card className="p-5">
      <p className={`section-title ${tone}`}>{title}</p>
      <ul className="mt-3 space-y-2">
        {items.map((item, i) => (
          <li key={i} className="flex gap-2 text-sm text-slate-700">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-40" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function CrossFileCard({ risk }: { risk: CrossFileRisk }) {
  const meta = severityMeta(risk.severity);
  return (
    <Card className="p-5">
      <div className="flex items-start gap-2">
        <span className={`chip ${meta.badge}`}>{meta.label}</span>
        <h3 className="text-sm font-semibold text-slate-900">{risk.root_cause}</h3>
      </div>
      <p className="mt-2 text-sm text-slate-700">
        <span className="font-medium text-slate-800">Impact: </span>
        {risk.impact}
      </p>
      {risk.affected_files.length ? (
        <div className="mt-2">
          <p className="section-title">Affected files</p>
          <ul className="mt-1 space-y-0.5">
            {risk.affected_files.slice(0, 8).map((file) => (
              <li key={file} className="truncate font-mono text-[11px] text-slate-500">
                {file}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <p className="mt-3 text-sm text-slate-700">
        <span className="font-medium text-slate-800">Recommendation: </span>
        {risk.recommendation}
      </p>
    </Card>
  );
}

function SeverityDistribution({ model }: { model: ReportModel }) {
  const total = model.total_findings || 1;
  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-slate-50">
        {SEVERITY_ORDER.map((sev) => {
          const count = model.severity_summary[sev] ?? 0;
          if (count === 0) return null;
          return (
            <span
              key={sev}
              className={SEVERITY_META[sev]?.dot ?? "bg-slate-500"}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${SEVERITY_META[sev]?.label ?? sev}: ${count}`}
            />
          );
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5 text-xs text-slate-500">
            <span className={`h-2 w-2 rounded-full ${SEVERITY_META[sev]?.dot ?? "bg-slate-500"}`} />
            {SEVERITY_META[sev]?.label ?? sev}
            <span className="font-semibold text-slate-800">
              {model.severity_summary[sev] ?? 0}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

const SEVERITY_FILTERS = ["all", ...SEVERITY_ORDER] as const;

export default function ReportView() {
  const { scanId } = useParams();
  const id = scanId ?? "";
  const { data: model, isLoading, isError } = useReportModel(id || null);
  const [filter, setFilter] = useState<(typeof SEVERITY_FILTERS)[number]>("all");
  const [limit, setLimit] = useState(60);

  const filtered = useMemo(() => {
    if (!model) return [];
    if (filter === "all") return model.detailed_findings;
    return model.detailed_findings.filter((f) => f.severity === filter);
  }, [model, filter]);

  if (isLoading) return <Spinner label="Generating report…" />;
  if (isError || !model) {
    return (
      <EmptyState
        title="Report unavailable"
        description="The report could not be generated for this scan yet."
      />
    );
  }

  const pr = model.production_readiness;
  const applicable = pr.category_scores.filter((c) => c.applicable);

  return (
    <div className="space-y-6">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-900">Audit Report</h1>
          <p className="mt-0.5 text-xs text-slate-500">
            Generated {formatDateTime(model.generated_at)} · schema v{model.schema_version}
            {model.llm_used ? " · AI-assisted" : " · deterministic"}
          </p>
        </div>
        <DownloadBar scanId={id} />
      </div>

      {/* Hero: score + executive summary */}
      <Card className="animate-in relative overflow-hidden">
        <span className="absolute inset-x-0 top-0 h-1 bg-brand-gradient" aria-hidden />
        <div className="grid gap-6 p-6 md:grid-cols-[auto_1fr]">
          <div
            className={`flex flex-col items-center justify-center gap-3 rounded-xl bg-gradient-to-b to-white p-4 md:pr-6 ${
              pr.ready ? "from-emerald-50" : "from-rose-50"
            }`}
          >
            <ScoreRing score={pr.score} />
            <span
              className={`chip ${
                pr.ready
                  ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                  : "bg-rose-50 text-rose-700 ring-rose-600/20"
              }`}
            >
              {pr.ready ? "Production Ready" : "Not Production Ready"}
            </span>
            <span className="text-xs text-slate-500">Rated {pr.rating}</span>
          </div>
          <div className="min-w-0">
            <p className="section-title">Executive Summary</p>
            <p className="mt-2 text-sm leading-relaxed text-slate-700">{model.executive_summary}</p>
            <div className="mt-4">
              <SeverityDistribution model={model} />
            </div>
          </div>
        </div>
      </Card>

      {/* Repository + category scores */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="animate-in p-6">
          <SectionHeading title="Repository" />
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            {[
              ["Name", model.repository.name],
              ["Files analyzed", String(model.repository.total_files)],
              ["Total findings", String(model.total_findings)],
              ["Reviewed false positives", String(model.reviewed_false_positives)],
              ["Source", prettyLabel(model.repository.source_type)],
              ["Status", prettyLabel(model.repository.status)],
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="text-xs text-slate-500">{k}</dt>
                <dd className="truncate font-medium text-slate-800">{v}</dd>
              </div>
            ))}
          </dl>
          {model.repository.technologies.length ? (
            <div className="mt-4">
              <p className="section-title">Technologies</p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {model.repository.technologies.map((t) => (
                  <span key={t} className="chip bg-slate-50 text-slate-700 ring-slate-200">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
        </Card>

        <Card className="animate-in p-6">
          <SectionHeading title="Readiness by category" />
          {applicable.length === 0 ? (
            <p className="text-sm text-slate-500">No applicable categories.</p>
          ) : (
            <div className="space-y-3">
              {applicable.map((c) => (
                <div key={c.category}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="text-slate-700">{c.label}</span>
                    <span className="font-semibold" style={{ color: scoreColor(c.score) }}>
                      {c.score}
                    </span>
                  </div>
                  <Meter value={c.score} />
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Blockers / risks / next actions */}
      {pr.blockers.length || pr.top_risks.length || pr.next_actions.length ? (
        <div className="grid gap-6 lg:grid-cols-3">
          <ListCard title="Production Blockers" items={pr.blockers} tone="text-rose-700" />
          <ListCard title="Top Risks" items={pr.top_risks} tone="text-orange-700" />
          <ListCard title="Recommended Next Actions" items={pr.next_actions} tone="text-sky-700" />
        </div>
      ) : null}

      {/* Remediation plan */}
      {model.remediation_plan.length ? (
        <Card className="animate-in overflow-hidden">
          <div className="border-b border-slate-200 px-6 py-4">
            <SectionHeading title="Recommended remediation plan" />
          </div>
          <div className="divide-y divide-white/5">
            {model.remediation_plan.map((step) => {
              const meta = severityMeta(step.severity);
              return (
                <div key={step.priority} className="flex items-center gap-4 px-6 py-3">
                  <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full bg-slate-50 text-xs font-bold text-slate-700">
                    {step.priority}
                  </span>
                  <span className={`chip ${meta.badge}`}>{meta.label}</span>
                  <span className="min-w-0 flex-1 text-sm text-slate-800">{step.action}</span>
                  <span className="hidden font-mono text-[11px] text-slate-500 md:inline">
                    {step.affected_rule_ids.join(", ")}
                  </span>
                  <span className="chip bg-slate-50 text-slate-500 ring-slate-200">
                    {step.finding_count}×
                  </span>
                </div>
              );
            })}
          </div>
        </Card>
      ) : null}

      {/* Cross-file risks */}
      {model.cross_file_risks.length ? (
        <div>
          <SectionHeading
            title="Cross-file risks"
            subtitle="Related findings correlated into root-cause issues"
          />
          <div className="grid gap-4 lg:grid-cols-2">
            {model.cross_file_risks.map((risk, i) => (
              <CrossFileCard key={i} risk={risk} />
            ))}
          </div>
        </div>
      ) : null}

      {/* Detailed findings */}
      <div>
        <SectionHeading
          title="Detailed findings"
          subtitle={`${model.total_findings} findings with evidence and location`}
          actions={
            <div className="flex flex-wrap gap-1">
              {SEVERITY_FILTERS.map((sev) => {
                const count =
                  sev === "all" ? model.total_findings : model.severity_summary[sev] ?? 0;
                const active = filter === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => {
                      setFilter(sev);
                      setLimit(60);
                    }}
                    className={`chip capitalize ${
                      active
                        ? "bg-brand/20 text-brand ring-brand/40"
                        : "bg-slate-50 text-slate-500 ring-slate-200 hover:text-slate-800"
                    }`}
                  >
                    {sev} {count}
                  </button>
                );
              })}
            </div>
          }
        />
        {filtered.length === 0 ? (
          <EmptyState title="No findings" description="Nothing at this severity." />
        ) : (
          <div className="space-y-2">
            {filtered.slice(0, limit).map((f) => (
              <FindingRow key={f.id} f={f} />
            ))}
            {filtered.length > limit ? (
              <button
                type="button"
                onClick={() => setLimit((n) => n + 100)}
                className="btn-ghost w-full"
              >
                Show more ({filtered.length - limit} remaining)
              </button>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
