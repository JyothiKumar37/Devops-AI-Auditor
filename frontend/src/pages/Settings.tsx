import { useState } from "react";

import { Badge, Card, PageHeader } from "@/components/ui";
import {
  useHealth,
  useLLMHealth,
  useLLMSettings,
  useUpdateLLMModel,
} from "@/hooks/useHealth";
import { SCANNER_CATALOG } from "@/data/scanners";
import { MAX_UPLOAD_MB } from "@/lib/format";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-200 py-2.5 last:border-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm text-slate-800">{value}</span>
    </div>
  );
}

export default function Settings() {
  const { data: health } = useHealth();
  const [checkLLM, setCheckLLM] = useState(false);
  const { data: llm, isFetching: llmChecking, refetch: refetchLLM } = useLLMHealth(checkLLM);

  const { data: llmSettings } = useLLMSettings();
  const updateModel = useUpdateLLMModel();
  const [modelDraft, setModelDraft] = useState<string | null>(null);
  const modelValue = modelDraft ?? llmSettings?.model ?? "";
  const dirty = llmSettings != null && modelValue.trim() !== llmSettings.model;

  const llmBadge = !llm
    ? null
    : !llm.configured
      ? { text: "not configured", cls: "bg-slate-100 text-slate-600 ring-slate-300" }
      : llm.ok
        ? { text: "connected", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20" }
        : { text: "error", cls: "bg-rose-50 text-rose-700 ring-rose-600/20" };

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Settings" subtitle="Environment, scanners and system status." />

      <div className="space-y-6">
        <Card className="p-5">
          <h2 className="mb-2 text-sm font-semibold text-slate-900">System</h2>
          <Row
            label="API status"
            value={
              <Badge
                className={
                  health?.status === "healthy"
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                    : "bg-amber-50 text-amber-700 ring-amber-600/20"
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
                <span className={c.state === "healthy" ? "text-emerald-700" : "text-rose-700"}>
                  {c.state}
                </span>
              }
            />
          ))}
        </Card>

        <Card className="p-5">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">AI provider</h2>
            <button
              type="button"
              onClick={() => {
                setCheckLLM(true);
                void refetchLLM();
              }}
              disabled={llmChecking}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
            >
              {llmChecking ? "Checking…" : "Check connection"}
            </button>
          </div>

          {llmSettings ? (
            <div className="mb-3 rounded-lg border border-slate-200 bg-slate-50/60 p-3">
              <label
                htmlFor="llm-model"
                className="text-xs font-semibold uppercase tracking-wide text-slate-500"
              >
                Active model
                <span className="ml-2 font-normal normal-case text-slate-400">
                  provider: {llmSettings.provider}
                </span>
              </label>
              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                <input
                  id="llm-model"
                  value={modelValue}
                  onChange={(e) => setModelDraft(e.target.value)}
                  spellCheck={false}
                  placeholder="e.g. gemini-3.8-flash"
                  className="min-w-[12rem] flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs text-slate-900 outline-none transition focus:border-brand focus:ring-2 focus:ring-brand/20"
                />
                <button
                  type="button"
                  onClick={() => updateModel.mutate(modelValue.trim(), { onSuccess: () => setModelDraft(null) })}
                  disabled={!dirty || updateModel.isPending}
                  className="rounded-lg bg-brand px-3.5 py-2 text-xs font-medium text-white transition hover:bg-brand/90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {updateModel.isPending ? "Saving…" : "Save"}
                </button>
                {llmSettings.overridden ? (
                  <button
                    type="button"
                    onClick={() => updateModel.mutate("", { onSuccess: () => setModelDraft(null) })}
                    disabled={updateModel.isPending}
                    className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
                  >
                    Use default
                  </button>
                ) : null}
              </div>
              <p className="mt-2 text-[11px] text-slate-400">
                {llmSettings.overridden
                  ? `Overriding the env default (${llmSettings.env_model}). Switch models here if one is overloaded — no redeploy needed.`
                  : `Using the env default (${llmSettings.env_model}). Save a different model to override it at runtime.`}
              </p>
              {updateModel.isError ? (
                <p className="mt-1 text-[11px] text-rose-600">Could not update the model.</p>
              ) : null}
            </div>
          ) : null}

          {!checkLLM ? (
            <p className="text-xs text-slate-500">
              Runs a live connectivity check against the configured LLM (one small model call).
            </p>
          ) : llmChecking && !llm ? (
            <Row label="Status" value="Checking…" />
          ) : llm && llmBadge ? (
            <>
              <Row label="Provider" value={llm.provider} />
              <Row label="Model" value={<span className="font-mono text-xs">{llm.model}</span>} />
              <Row label="Status" value={<Badge className={llmBadge.cls}>{llmBadge.text}</Badge>} />
              <Row label="Detail" value={<span className="text-slate-500">{llm.detail}</span>} />
              {llm.latency_ms != null ? (
                <Row label="Latency" value={`${llm.latency_ms} ms`} />
              ) : null}
            </>
          ) : (
            <Row
              label="Status"
              value={<span className="text-rose-700">check failed (endpoint unreachable)</span>}
            />
          )}
        </Card>

        <Card className="p-5">
          <h2 className="mb-2 text-sm font-semibold text-slate-900">Upload limits</h2>
          <Row label="Max archive size" value={`${MAX_UPLOAD_MB} MB`} />
          <Row label="Accepted formats" value=".zip" />
          <Row label="Code execution" value="Never — files are read-only" />
        </Card>

        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-900">Scanners</h2>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {SCANNER_CATALOG.map((s) => (
              <div key={s.id} className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                <div>
                  <p className="text-sm text-slate-800">{s.label}</p>
                  <p className="text-[11px] text-slate-500">{s.description}</p>
                </div>
                <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">active</Badge>
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
