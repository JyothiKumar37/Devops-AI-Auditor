import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { CodeViewer } from "@/components/CodeViewer";
import { DiffView } from "@/components/DiffView";
import { Badge, Card, SeverityPill, Spinner } from "@/components/ui";
import {
  useApplyRemediation,
  useFindings,
  useGenerateRemediation,
  useReport,
  useScanFiles,
} from "@/hooks/useScans";
import { prettyLabel } from "@/lib/format";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      <div className="text-sm leading-relaxed text-slate-700">{children}</div>
    </div>
  );
}

const PRIMARY_BTN =
  "inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white transition hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50";
const APPROVE_BTN =
  "inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3.5 py-2 text-sm font-medium text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50";

export default function FindingDetails() {
  const { scanId, findingId } = useParams();
  const id = scanId ?? null;
  const fid = findingId ?? "";

  const { data, isLoading } = useFindings(id, {});
  const { data: files } = useScanFiles(id);
  const { data: report } = useReport(id);

  const generate = useGenerateRemediation(id ?? "", fid);
  const apply = useApplyRemediation(id ?? "", fid);

  const finding = data?.items.find((f) => f.id === findingId);
  const file = useMemo(
    () => files?.items.find((f) => f.id === finding?.file_id) ?? null,
    [files, finding],
  );
  const aiReasoning = useMemo(
    () =>
      report?.key_findings.find((kf) => (finding ? kf.source_finding_ids.includes(finding.id) : false))
        ?.reasoning ?? null,
    [report, finding],
  );

  // Once a fix is applied and verified, the finding is removed server-side, so
  // show a persistent success view rather than a "not found" flash.
  const applied = apply.data;
  if (applied?.resolved) {
    return (
      <div>
        <Link to={`/scans/${id}/findings`} className="text-xs text-slate-500 hover:text-slate-700">
          ← All findings
        </Link>
        <Card className="mt-3 p-6">
          <div className="mb-3 flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
              ✓
            </span>
            <div>
              <h1 className="text-lg font-semibold text-slate-900">Finding resolved</h1>
              <p className="text-sm text-slate-500">{applied.message}</p>
            </div>
          </div>
          <p className="mb-4 text-xs text-slate-500">
            The fix was applied to the stored analysis copy only — your repository was never
            modified — and the {applied.rule_id} finding no longer triggers on re-scan.
          </p>
          {applied.diff ? <DiffView diff={applied.diff} /> : null}
        </Card>
      </div>
    );
  }

  if (isLoading) return <Spinner />;
  if (!finding) {
    return (
      <Card className="p-8 text-center text-sm text-slate-500">
        Finding not found.{" "}
        <Link to={`/scans/${id}/findings`} className="text-brand hover:underline">
          Back to findings
        </Link>
      </Card>
    );
  }

  const proposal = generate.data;
  const canApprove = proposal?.status === "proposed";

  return (
    <div>
      <Link to={`/scans/${id}/findings`} className="text-xs text-slate-500 hover:text-slate-700">
        ← All findings
      </Link>

      <div className="mt-3 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="flex flex-col divide-y divide-white/5">
          <div className="p-5">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityPill severity={finding.severity} />
              <Badge className="bg-slate-50 text-slate-700 ring-slate-200">{finding.scanner}</Badge>
              <Badge className="bg-slate-50 text-slate-500 ring-slate-200">{finding.rule_id}</Badge>
            </div>
            <h1 className="text-lg font-semibold text-slate-900">{finding.title}</h1>
            <p className="mt-1 font-mono text-xs text-slate-500">
              {file?.path ?? "—"}
              {finding.line_number ? `:${finding.line_number}` : ""}
            </p>
          </div>

          <div className="space-y-4 p-5">
            <Section title="Why it matters">{finding.description || finding.title}</Section>
            {finding.evidence ? (
              <Section title="Evidence">
                <pre className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800">
                  {finding.evidence}
                </pre>
              </Section>
            ) : null}
            {aiReasoning ? <Section title="AI reasoning">{aiReasoning}</Section> : null}
            <Section title="Recommendation">{finding.recommendation}</Section>
            <div className="flex flex-wrap gap-6 pt-1 text-xs text-slate-500">
              <span>Category: {prettyLabel(finding.category)}</span>
              <span>Confidence: {prettyLabel(finding.confidence)}</span>
            </div>
          </div>
        </Card>

        <Card className="flex flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-200 px-4 py-2.5">
            <span className="font-mono text-xs text-slate-500">{file?.path ?? "source"}</span>
            {finding.line_number ? (
              <span className="text-xs text-amber-700">line {finding.line_number}</span>
            ) : null}
          </div>
          <div className="h-[28rem]">
            <CodeViewer
              scanId={id as string}
              fileId={finding.file_id}
              path={file?.path}
              fileType={file?.file_type}
              highlightLine={finding.line_number}
            />
          </div>
        </Card>
      </div>

      {/* Remediation: generate -> review diff -> approve -> apply -> verify */}
      <Card className="mt-6 p-5">
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Suggested remediation</h2>
            <p className="text-xs text-slate-500">
              Fixes are deterministic and applied only to the stored analysis copy after your
              explicit approval. Your repository is never modified.
            </p>
          </div>
          {!proposal ? (
            <button
              type="button"
              className={PRIMARY_BTN}
              onClick={() => generate.mutate()}
              disabled={generate.isPending}
            >
              {generate.isPending ? "Generating…" : "Generate fix"}
            </button>
          ) : null}
        </div>

        {generate.isError ? (
          <p className="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 ring-1 ring-inset ring-rose-600/20">
            {(generate.error as Error).message}
          </p>
        ) : null}

        {proposal?.status === "manual_required" ? (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <p className="text-sm font-medium text-amber-700">Manual remediation required.</p>
            <p className="mt-1 text-sm text-amber-100/80">
              No safe automatic fix can be generated for this finding without guessing a value.
            </p>
            {proposal.rationale ? (
              <p className="mt-2 text-xs text-amber-100/70">{proposal.rationale}</p>
            ) : null}
          </div>
        ) : null}

        {canApprove && proposal ? (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium text-slate-800">{proposal.summary}</p>
              {proposal.rationale ? (
                <p className="mt-0.5 text-xs text-slate-500">{proposal.rationale}</p>
              ) : null}
            </div>

            {proposal.diff ? (
              <DiffView diff={proposal.diff} before={proposal.before} after={proposal.after} />
            ) : null}

            {apply.data && !apply.data.resolved ? (
              <p className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-700 ring-1 ring-inset ring-amber-600/20">
                {apply.data.message}
              </p>
            ) : null}
            {apply.isError ? (
              <p className="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700 ring-1 ring-inset ring-rose-600/20">
                {(apply.error as Error).message}
              </p>
            ) : null}

            <div className="flex items-center gap-3">
              <button
                type="button"
                className={APPROVE_BTN}
                onClick={() => apply.mutate()}
                disabled={apply.isPending}
              >
                {apply.isPending ? "Applying…" : "Approve & apply fix"}
              </button>
              <span className="text-xs text-slate-500">
                Applies the patch, then re-runs the scanner to verify the fix.
              </span>
            </div>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
