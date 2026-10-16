import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import {
  useCloudAccounts,
  useConnectCloudAccount,
  useDeleteCloudAccount,
} from "@/hooks/useCloud";
import { ApiError } from "@/lib/api";
import { relativeTime } from "@/lib/format";

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "connected"
      ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
      : status === "error"
        ? "bg-rose-50 text-rose-700 ring-rose-600/20"
        : "bg-amber-50 text-amber-700 ring-amber-600/20";
  return <Badge className={cls}>{status}</Badge>;
}

function ConnectForm() {
  const connect = useConnectCloudAccount();
  const [name, setName] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [regions, setRegions] = useState("");

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleArn.trim()) return;
    connect.mutate(
      {
        name: name.trim() || undefined,
        role_arn: roleArn.trim(),
        external_id: externalId.trim() || undefined,
        regions: regions
          .split(",")
          .map((r) => r.trim())
          .filter(Boolean),
      },
      {
        onSuccess: () => {
          setName("");
          setRoleArn("");
          setExternalId("");
          setRegions("");
        },
      },
    );
  };

  return (
    <Card className="p-5">
      <h2 className="mb-1 text-sm font-semibold text-slate-900">Connect an AWS account</h2>
      <p className="mb-3 text-xs text-slate-500">
        Read-only access via STS AssumeRole — no AWS keys are stored. Create an IAM role that
        trusts this platform (with an external id) and grant read-only describe/list permissions.
        The external id is stored encrypted and never returned.
      </p>
      <form onSubmit={onSubmit} className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium uppercase tracking-wide text-slate-500">Name (optional)</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="production"
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium uppercase tracking-wide text-slate-500">
            Regions (comma-separated, optional)
          </span>
          <input
            value={regions}
            onChange={(e) => setRegions(e.target.value)}
            placeholder="us-east-1, eu-west-1"
            className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs sm:col-span-2">
          <span className="font-medium uppercase tracking-wide text-slate-500">Role ARN</span>
          <input
            value={roleArn}
            onChange={(e) => setRoleArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/DevOpsAuditorReadOnly"
            autoComplete="off"
            className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs sm:col-span-2">
          <span className="font-medium uppercase tracking-wide text-slate-500">
            External id (recommended)
          </span>
          <input
            type="password"
            value={externalId}
            onChange={(e) => setExternalId(e.target.value)}
            placeholder="confused-deputy protection"
            autoComplete="off"
            className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={connect.isPending || !roleArn.trim()}
            className="btn-primary px-4 py-2 text-xs disabled:opacity-50"
          >
            {connect.isPending ? "Connecting…" : "Connect account"}
          </button>
          {connect.isError ? (
            <p className="mt-2 text-xs text-rose-600">
              {connect.error instanceof ApiError
                ? connect.error.message
                : "Could not assume the role. Check the ARN, external id, and trust policy."}
            </p>
          ) : null}
        </div>
      </form>
    </Card>
  );
}

export default function CloudAccounts() {
  const { data, isLoading, isError } = useCloudAccounts();
  const remove = useDeleteCloudAccount();
  const accounts = data?.items ?? [];

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Cloud accounts"
        subtitle="Read-only AWS runtime intelligence, IaC drift, and compliance."
      />

      {isError ? (
        <Card className="p-5">
          <p className="text-sm text-rose-600">Could not load cloud accounts.</p>
        </Card>
      ) : null}

      <div className="space-y-6">
        <ConnectForm />

        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-900">Connected accounts</h2>
          {isLoading ? (
            <Spinner label="Loading accounts…" />
          ) : accounts.length === 0 ? (
            <EmptyState
              title="No cloud accounts yet"
              description="Connect an AWS account above to discover assets and assess posture."
            />
          ) : (
            <div className="space-y-3">
              {accounts.map((acct) => (
                <Card key={acct.id} className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link
                          to={`/cloud/${acct.id}`}
                          className="font-medium text-slate-800 hover:text-brand"
                        >
                          {acct.name || acct.account_id}
                        </Link>
                        <StatusBadge status={acct.status} />
                        <Badge className="bg-slate-100 text-slate-500 ring-slate-300">
                          {acct.provider}
                        </Badge>
                      </div>
                      <p className="mt-1 font-mono text-[11px] text-slate-500">
                        account {acct.account_id} · {acct.regions.join(", ") || "default regions"}
                      </p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        {acct.last_synced_at
                          ? `last synced ${relativeTime(acct.last_synced_at)}`
                          : "never synced"}
                        {acct.status_detail ? ` · ${acct.status_detail}` : ""}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <Link
                        to={`/cloud/${acct.id}`}
                        className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                      >
                        Open
                      </Link>
                      <button
                        type="button"
                        onClick={() => {
                          if (
                            confirm(
                              `Disconnect ${acct.name || acct.account_id}? Discovered data will be removed.`,
                            )
                          ) {
                            remove.mutate(acct.id);
                          }
                        }}
                        className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
                      >
                        Disconnect
                      </button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
