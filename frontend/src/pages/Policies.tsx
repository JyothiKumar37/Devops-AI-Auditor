import { useState } from "react";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import {
  useAssignPolicy,
  useCreatePolicy,
  useDeletePolicy,
  usePolicies,
  useUpdatePolicy,
} from "@/hooks/usePlatform";
import { ApiError } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type { Policy } from "@/types/api";

const EXAMPLE_POLICY = `version: 1
name: production-gate
description: Block merges that introduce critical or high risk.
rules:
  - id: no-critical
    condition:
      severity: critical
    action: fail
  - id: no-new-high
    condition:
      severity: high
      is_new: true
    action: fail
  - id: warn-secrets
    condition:
      scanner: gitleaks
    action: warn
`;

function PolicyEditor({ policy, onDone }: { policy: Policy | null; onDone: () => void }) {
  const create = useCreatePolicy();
  const update = useUpdatePolicy();
  const [name, setName] = useState(policy?.name ?? "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [yaml, setYaml] = useState(policy?.yaml_text ?? EXAMPLE_POLICY);
  const pending = create.isPending || update.isPending;
  const err = create.error ?? update.error;

  const onSave = () => {
    if (policy) {
      update.mutate(
        { id: policy.id, payload: { yaml_text: yaml, description } },
        { onSuccess: onDone },
      );
    } else {
      if (!name.trim()) return;
      create.mutate({ name: name.trim(), yaml_text: yaml, description }, { onSuccess: onDone });
    }
  };

  return (
    <Card className="p-5">
      <h2 className="mb-3 text-sm font-semibold text-slate-900">
        {policy ? `Edit "${policy.name}"` : "New policy"}
      </h2>
      <div className="space-y-3">
        {!policy ? (
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Policy name"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        ) : null}
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description (optional)"
          className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
        />
        <textarea
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          spellCheck={false}
          rows={16}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs leading-relaxed outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
        />
        {err ? (
          <p className="text-xs text-rose-600">
            {err instanceof ApiError ? err.message : "Could not save the policy."}
          </p>
        ) : null}
        <div className="flex gap-2">
          <button type="button" onClick={onSave} disabled={pending} className="btn-primary px-4 py-2 text-xs disabled:opacity-50">
            {pending ? "Saving…" : policy ? "Save changes" : "Create policy"}
          </button>
          <button type="button" onClick={onDone} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50">
            Cancel
          </button>
        </div>
      </div>
    </Card>
  );
}

export default function Policies() {
  const { data, isLoading } = usePolicies();
  const remove = useDeletePolicy();
  const update = useUpdatePolicy();
  const assign = useAssignPolicy();
  const [editing, setEditing] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);
  const policies = data?.items ?? [];

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Policies"
        subtitle="Policy-as-code gates. YAML rules evaluated against each PR's new findings."
        actions={
          !creating && !editing ? (
            <button type="button" onClick={() => setCreating(true)} className="btn-primary px-3.5 py-2 text-xs">
              New policy
            </button>
          ) : null
        }
      />

      {creating ? (
        <PolicyEditor policy={null} onDone={() => setCreating(false)} />
      ) : editing ? (
        <PolicyEditor policy={editing} onDone={() => setEditing(null)} />
      ) : isLoading ? (
        <Spinner label="Loading policies…" />
      ) : policies.length === 0 ? (
        <EmptyState
          title="No policies defined"
          description="Create a YAML policy to gate pull requests on severity, risk, scanner or new-vs-existing findings."
          action={
            <button type="button" onClick={() => setCreating(true)} className="btn-primary px-3.5 py-2 text-xs">
              New policy
            </button>
          }
        />
      ) : (
        <div className="space-y-3">
          {policies.map((p) => (
            <Card key={p.id} className="p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-slate-800">{p.name}</span>
                    <Badge className="bg-slate-100 text-slate-500 ring-slate-300">v{p.version}</Badge>
                    {p.enabled ? (
                      <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">enabled</Badge>
                    ) : (
                      <Badge className="bg-slate-100 text-slate-500 ring-slate-300">disabled</Badge>
                    )}
                  </div>
                  {p.description ? <p className="mt-1 text-xs text-slate-500">{p.description}</p> : null}
                  <p className="mt-1 text-[11px] text-slate-400">updated {relativeTime(p.updated_at)}</p>
                </div>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => assign.mutate({ id: p.id, scope_type: "global" })}
                    title="Apply to all repositories"
                    className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  >
                    Set global
                  </button>
                  <button
                    type="button"
                    onClick={() => update.mutate({ id: p.id, payload: { enabled: !p.enabled } })}
                    className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  >
                    {p.enabled ? "Disable" : "Enable"}
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditing(p)}
                    className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={() => confirm(`Delete policy "${p.name}"?`) && remove.mutate(p.id)}
                    className="rounded-lg border border-rose-200 bg-white px-2.5 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
