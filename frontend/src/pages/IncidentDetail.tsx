import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Badge, Card, EmptyState, Spinner } from "@/components/ui";
import {
  useAddIncidentNote,
  useGeneratePlans,
  useIncident,
  useIncidentInvestigations,
  useIncidentRelationships,
  useInvestigateIncident,
  usePlanDecision,
  useRemediationPlans,
  useTransitionIncident,
  useUpdateIncident,
} from "@/hooks/useIncidents";
import { ApiError } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type {
  ContainmentPlan,
  IncidentDetail as IncidentDetailType,
  IncidentTimelineEntry,
  InvestigationResult,
} from "@/types/api";

const TABS = ["Overview", "Events", "Timeline", "Graph", "Plans", "Investigate", "Notes"] as const;
type Tab = (typeof TABS)[number];

const STATUSES = [
  "new", "triaging", "investigating", "containment_planned",
  "containment_approved", "contained", "resolved", "false_positive", "accepted_risk",
];

const EVIDENCE_CLASS_STYLE: Record<string, string> = {
  confirmed: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  reported: "bg-sky-50 text-sky-700 ring-sky-600/20",
  inferred: "bg-amber-50 text-amber-700 ring-amber-600/20",
  hypothesis: "bg-violet-50 text-violet-700 ring-violet-600/20",
  action: "bg-slate-100 text-slate-600 ring-slate-300",
};

export default function IncidentDetail() {
  const { incidentId } = useParams();
  const [tab, setTab] = useState<Tab>("Overview");
  const { data: incident, isLoading } = useIncident(incidentId ?? null);

  if (isLoading && !incident) return <Spinner label="Loading incident…" />;
  if (!incident) return <EmptyState title="Not found" description="This incident does not exist." />;

  return (
    <div className="mx-auto max-w-5xl">
      <Link to="/incidents/list" className="text-xs font-medium text-slate-500 hover:text-brand">
        ← All incidents
      </Link>
      <Header incident={incident} />

      <div className="mb-6 flex gap-1 overflow-x-auto border-b border-slate-200">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`-mb-px whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors ${
              tab === t
                ? "border-brand text-brand-deep"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" ? <Overview incident={incident} /> : null}
      {tab === "Events" ? <Events incident={incident} /> : null}
      {tab === "Timeline" ? <Timeline id={incident.id} /> : null}
      {tab === "Graph" ? <Graph id={incident.id} /> : null}
      {tab === "Plans" ? <Plans id={incident.id} /> : null}
      {tab === "Investigate" ? <Investigate id={incident.id} /> : null}
      {tab === "Notes" ? <Notes incident={incident} /> : null}
    </div>
  );
}

function Header({ incident }: { incident: IncidentDetailType }) {
  const transition = useTransitionIncident(incident.id);
  const [target, setTarget] = useState("");

  return (
    <div className="my-3 rounded-2xl border border-slate-200/70 bg-white p-5 shadow-soft">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">{incident.severity}</Badge>
        <h1 className="text-xl font-bold tracking-tight text-slate-900">{incident.title}</h1>
        <Badge className="bg-indigo-50 text-indigo-700 ring-indigo-600/20">
          {incident.status.replace(/_/g, " ")}
        </Badge>
      </div>
      <p className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-500">
        <span>priority <b className="tabular-nums text-slate-700">{incident.priority}</b></span>
        <span>{incident.event_count} event(s)</span>
        <span>owner: {incident.owner || "unassigned"}</span>
        <span>account: {incident.account_ref || "—"}</span>
        <span>updated {relativeTime(incident.updated_at)}</span>
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <select
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-brand"
        >
          <option value="">Change status…</option>
          {STATUSES.filter((s) => s !== incident.status).map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
          ))}
        </select>
        <button
          type="button"
          disabled={!target || transition.isPending}
          onClick={() =>
            transition.mutate(
              { status: target, actor: "ui" },
              { onSuccess: () => setTarget("") },
            )
          }
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          Apply
        </button>
        {transition.isError ? (
          <span className="text-xs text-rose-600">
            {transition.error instanceof ApiError ? transition.error.message : "Transition failed."}
          </span>
        ) : null}
      </div>
    </div>
  );
}

function Overview({ incident }: { incident: IncidentDetailType }) {
  const update = useUpdateIncident(incident.id);
  const [owner, setOwner] = useState(incident.owner);
  const factors = incident.risk_rationale.factors ?? [];

  return (
    <div className="space-y-5">
      <Card className="p-4">
        <h3 className="mb-2 text-sm font-semibold text-slate-900">Assignment</h3>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder="owner (team or user)"
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm outline-none focus:border-brand"
          />
          <button
            type="button"
            onClick={() => update.mutate({ owner })}
            disabled={update.isPending}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            Assign
          </button>
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="mb-2 text-sm font-semibold text-slate-900">
          Deterministic risk rationale
          <span className="ml-2 text-xs font-normal text-slate-400">
            score {incident.priority} · {incident.risk_rationale.method ?? "deterministic"}
          </span>
        </h3>
        {factors.length === 0 ? (
          <p className="text-xs text-slate-500">No rationale computed yet.</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {factors.map((f) => (
              <li key={f.factor} className="flex items-start justify-between gap-3">
                <span className="text-slate-600">
                  {f.factor.replace(/_/g, " ")}
                  <span className="ml-1 text-xs text-slate-400">{f.detail}</span>
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums text-slate-500">
                  {f.points}/{f.max}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-4">
        <h3 className="mb-2 text-sm font-semibold text-slate-900">Affected resources</h3>
        {incident.resources.length === 0 ? (
          <p className="text-xs text-slate-500">No specific resources.</p>
        ) : (
          <ul className="space-y-1 font-mono text-[11px] text-slate-600">
            {incident.resources.map((r) => (
              <li key={r.resource_id}>
                {r.resource_id} · {r.service || "?"} · {r.region || "global"} ·{" "}
                <span className={r.exposure === "public" ? "text-rose-600" : ""}>{r.exposure}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Events({ incident }: { incident: IncidentDetailType }) {
  if (incident.events.length === 0) {
    return <EmptyState title="No events" description="This incident has no member events." />;
  }
  return (
    <div className="space-y-3">
      {incident.events.map((ev) => (
        <Card key={ev.id} className="p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="bg-slate-100 text-slate-600 ring-slate-300">{ev.source_type}</Badge>
            <span className="font-medium text-slate-800">{ev.title}</span>
            <Badge className="bg-slate-100 text-slate-500 ring-slate-300">{ev.severity}</Badge>
            {ev.verified ? (
              <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">verified</Badge>
            ) : (
              <Badge className="bg-sky-50 text-sky-700 ring-sky-600/20">reported</Badge>
            )}
          </div>
          {ev.resource_id ? (
            <p className="mt-1 font-mono text-[11px] text-slate-400">{ev.resource_id}</p>
          ) : null}
          {ev.rationale ? (
            <p className="mt-2 text-xs text-slate-500">
              <span className="font-semibold text-slate-600">Correlation ({ev.correlation_signal}):</span>{" "}
              {ev.rationale}
            </p>
          ) : null}
        </Card>
      ))}
    </div>
  );
}

function Timeline({ id }: { id: string }) {
  const { data, isLoading } = useIncidentRelationshipsSafeTimeline(id);
  if (isLoading && !data) return <Spinner label="Loading timeline…" />;
  if (!data || data.length === 0) {
    return <EmptyState title="No timeline" description="No timeline entries yet." />;
  }
  return (
    <ol className="relative space-y-3 border-l border-slate-200 pl-5">
      {data.map((entry) => (
        <li key={entry.id} className="relative">
          <span className="absolute -left-[1.42rem] top-1.5 h-2.5 w-2.5 rounded-full bg-slate-300" />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-slate-800">{entry.title}</span>
            <Badge className={EVIDENCE_CLASS_STYLE[entry.evidence_class] ?? EVIDENCE_CLASS_STYLE.action}>
              {entry.evidence_class}
            </Badge>
            <span className="text-xs text-slate-400">{relativeTime(entry.occurred_at)}</span>
          </div>
          {entry.actor ? <p className="text-xs text-slate-500">by {entry.actor}</p> : null}
        </li>
      ))}
    </ol>
  );
}

// Timeline comes from the incident detail payload; this small hook reuses it.
function useIncidentRelationshipsSafeTimeline(id: string): {
  data: IncidentTimelineEntry[] | undefined;
  isLoading: boolean;
} {
  const { data, isLoading } = useIncident(id);
  return { data: data?.timeline, isLoading };
}

function Graph({ id }: { id: string }) {
  const { data, isLoading } = useIncidentRelationships(id);
  if (isLoading && !data) return <Spinner label="Building graph…" />;
  if (!data || data.nodes.length <= 1) {
    return <EmptyState title="No relationships" description="Not enough data to build a graph." />;
  }
  const label = (nid: string) => data.nodes.find((n) => n.id === nid)?.label ?? nid;
  return (
    <div className="space-y-4">
      <Card className="p-4">
        <h3 className="mb-2 text-sm font-semibold text-slate-900">Nodes</h3>
        <div className="flex flex-wrap gap-1.5">
          {data.nodes.map((n) => (
            <Badge key={n.id} className="bg-slate-100 text-slate-600 ring-slate-300">
              {n.type}: {n.label}
            </Badge>
          ))}
        </div>
      </Card>
      <Card className="overflow-hidden p-0">
        <table className="min-w-full divide-y divide-slate-200 text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-2.5">Source</th>
              <th className="px-4 py-2.5">Relation</th>
              <th className="px-4 py-2.5">Target</th>
              <th className="px-4 py-2.5">Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.edges.map((e, i) => (
              <tr key={i}>
                <td className="px-4 py-2 text-slate-700">{label(e.source)}</td>
                <td className="px-4 py-2">
                  <Badge className="bg-slate-100 text-slate-500 ring-slate-300">{e.relation}</Badge>
                </td>
                <td className="px-4 py-2 text-slate-700">{label(e.target)}</td>
                <td className="px-4 py-2">
                  <Badge className={EVIDENCE_CLASS_STYLE[e.evidence_class] ?? EVIDENCE_CLASS_STYLE.action}>
                    {e.evidence_class}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function Plans({ id }: { id: string }) {
  const { data, isLoading } = useRemediationPlans(id);
  const generate = useGeneratePlans(id);
  const plans = data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">
          Containment is plan-first and approval-gated. Execution never mutates infrastructure in
          this read-only build.
        </p>
        <button
          type="button"
          onClick={() => generate.mutate()}
          disabled={generate.isPending}
          className="btn-primary px-3.5 py-1.5 text-xs disabled:opacity-50"
        >
          {generate.isPending ? "Generating…" : "Generate plans"}
        </button>
      </div>

      {isLoading && !data ? (
        <Spinner label="Loading plans…" />
      ) : plans.length === 0 ? (
        <EmptyState title="No plans" description="Generate containment plans for this incident." />
      ) : (
        plans.map((plan) => <PlanCard key={plan.id} incidentId={id} plan={plan} />)
      )}
    </div>
  );
}

function PlanCard({ incidentId, plan }: { incidentId: string; plan: ContainmentPlan }) {
  const { approve, reject, execute, verify } = usePlanDecision(incidentId);
  const busy =
    approve.isPending || reject.isPending || execute.isPending || verify.isPending;

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-slate-800">{plan.title}</span>
        <Badge className="bg-slate-100 text-slate-600 ring-slate-300">{plan.capability}</Badge>
        <Badge
          className={
            plan.status === "verified"
              ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
              : plan.status === "rejected"
                ? "bg-rose-50 text-rose-700 ring-rose-600/20"
                : "bg-indigo-50 text-indigo-700 ring-indigo-600/20"
          }
        >
          {plan.status}
        </Badge>
      </div>
      <p className="mt-2 text-sm text-slate-700">{plan.proposed_action}</p>
      <dl className="mt-2 space-y-1 text-xs text-slate-500">
        <div><span className="font-semibold text-slate-600">Impact:</span> {plan.potential_impact}</div>
        <div><span className="font-semibold text-slate-600">Rollback:</span> {plan.rollback_plan}</div>
        {plan.required_permissions.length > 0 ? (
          <div>
            <span className="font-semibold text-slate-600">Permissions:</span>{" "}
            <span className="font-mono">{plan.required_permissions.join(", ")}</span>
          </div>
        ) : null}
      </dl>
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || plan.status !== "proposed"}
          onClick={() => approve.mutate({ planId: plan.id, approver: "ui" })}
          className="rounded-lg border border-emerald-200 bg-white px-3 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-50 disabled:opacity-40"
        >
          Approve
        </button>
        <button
          type="button"
          disabled={busy || !["proposed", "approved"].includes(plan.status)}
          onClick={() => reject.mutate({ planId: plan.id, approver: "ui" })}
          className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50 disabled:opacity-40"
        >
          Reject
        </button>
        <button
          type="button"
          disabled={busy || plan.status !== "approved"}
          onClick={() => execute.mutate({ planId: plan.id, actor: "ui" })}
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
        >
          Execute
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => verify.mutate({ planId: plan.id })}
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
        >
          Verify
        </button>
      </div>
      {execute.data ? (
        <p className="mt-2 text-xs text-slate-500">Execution: {execute.data.status} — {execute.data.output}</p>
      ) : null}
      {verify.data ? (
        <p className="mt-1 text-xs text-slate-500">
          Verification: <b>{verify.data.verification.status}</b>
        </p>
      ) : null}
    </Card>
  );
}

function Investigate({ id }: { id: string }) {
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const investigate = useInvestigateIncident(id);
  const { data: history } = useIncidentInvestigations(id);

  const suggestions = [
    "What is the root cause of this incident?",
    "What is the blast radius?",
    "What should we contain first?",
  ];

  const run = (q: string) => {
    const text = q.trim();
    if (!text) return;
    investigate.mutate(text, { onSuccess: setResult });
  };

  return (
    <div className="space-y-4">
      <Card className="p-5">
        <h3 className="mb-1 text-sm font-semibold text-slate-900">AI investigation</h3>
        <p className="mb-3 text-xs text-slate-500">
          Evidence-grounded, read-only. Verified facts are distinguished from hypotheses; nothing
          here overrides deterministic findings.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run(question);
          }}
          className="flex gap-2"
        >
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about this incident…"
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
          <button
            type="submit"
            disabled={investigate.isPending || !question.trim()}
            className="btn-primary px-4 py-2 text-xs disabled:opacity-50"
          >
            {investigate.isPending ? "Investigating…" : "Investigate"}
          </button>
        </form>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {suggestions.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => { setQuestion(s); run(s); }}
              className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-slate-600 hover:border-brand hover:text-brand"
            >
              {s}
            </button>
          ))}
        </div>
      </Card>

      {investigate.isPending ? <Spinner label="Gathering evidence…" /> : null}
      {result ? <ResultCard result={result} /> : null}

      {history && history.length > 0 ? (
        <div>
          <h4 className="mb-2 text-sm font-semibold text-slate-900">Previous investigations</h4>
          <div className="space-y-1.5">
            {history.slice(0, 10).map((inv) => (
              <div key={inv.id} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs">
                <span className="text-slate-700">{inv.question}</span>
                <span className="ml-2 text-slate-400">({inv.confidence})</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ResultCard({ result }: { result: InvestigationResult }) {
  return (
    <Card className="p-5">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Badge className="bg-brand-50 text-brand-deep ring-brand-200">{result.label}</Badge>
        <Badge className="bg-slate-100 text-slate-600 ring-slate-300">
          confidence: {result.confidence}
        </Badge>
        {!result.ai_used ? (
          <Badge className="bg-slate-100 text-slate-500 ring-slate-300">AI disabled</Badge>
        ) : null}
        {result.hallucination_guard_triggered ? (
          <Badge className="bg-rose-50 text-rose-700 ring-rose-600/20">
            unverifiable claims removed
          </Badge>
        ) : null}
      </div>
      <div className="prose prose-sm max-w-none whitespace-pre-wrap text-slate-700">
        {result.answer}
      </div>
      {result.root_cause ? (
        <p className="mt-3 text-sm text-slate-700">
          <span className="font-semibold">Root cause:</span> {result.root_cause}
        </p>
      ) : null}
      {result.recommendations.length > 0 ? (
        <ol className="mt-2 list-decimal space-y-0.5 pl-5 text-sm text-slate-700">
          {result.recommendations.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ol>
      ) : null}
    </Card>
  );
}

function Notes({ incident }: { incident: IncidentDetailType }) {
  const addNote = useAddIncidentNote(incident.id);
  const [body, setBody] = useState("");
  return (
    <div className="space-y-4">
      <Card className="p-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!body.trim()) return;
            addNote.mutate({ body: body.trim(), author: "ui" }, { onSuccess: () => setBody("") });
          }}
          className="flex gap-2"
        >
          <input
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Add a note…"
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
          <button
            type="submit"
            disabled={addNote.isPending || !body.trim()}
            className="btn-primary px-4 py-2 text-xs disabled:opacity-50"
          >
            Add
          </button>
        </form>
      </Card>
      {incident.notes.length === 0 ? (
        <EmptyState title="No notes" description="Add the first note above." />
      ) : (
        <div className="space-y-2">
          {incident.notes.map((n) => (
            <Card key={n.id} className="p-3">
              <p className="text-sm text-slate-700">{n.body}</p>
              <p className="mt-1 text-[11px] text-slate-400">
                {n.author || "anon"} · {relativeTime(n.created_at)}
              </p>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
