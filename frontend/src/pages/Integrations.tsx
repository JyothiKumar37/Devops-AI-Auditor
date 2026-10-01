import { useState } from "react";

import { Badge, Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import {
  useAssignPolicy,
  useConnectIntegration,
  useDeleteIntegration,
  useImportRepository,
  useIntegrations,
  usePolicies,
  useRepositories,
} from "@/hooks/usePlatform";
import { ApiError } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type { SCMProviderName } from "@/types/api";

function ProviderBadge({ provider }: { provider: string }) {
  const cls =
    provider === "github"
      ? "bg-slate-900 text-white ring-slate-700"
      : "bg-orange-50 text-orange-700 ring-orange-600/20";
  return <Badge className={cls}>{provider}</Badge>;
}

function ConnectForm() {
  const connect = useConnectIntegration();
  const [provider, setProvider] = useState<SCMProviderName>("github");
  const [token, setToken] = useState("");
  const [name, setName] = useState("");

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) return;
    connect.mutate(
      { provider, token: token.trim(), name: name.trim() || undefined },
      { onSuccess: () => { setToken(""); setName(""); } },
    );
  };

  return (
    <Card className="p-5">
      <h2 className="mb-1 text-sm font-semibold text-slate-900">Connect a provider</h2>
      <p className="mb-3 text-xs text-slate-500">
        Paste a personal access token. It is validated, then stored encrypted — the token is
        never shown again or returned by the API.
      </p>
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium uppercase tracking-wide text-slate-500">Provider</span>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as SCMProviderName)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          >
            <option value="github">GitHub</option>
            <option value="gitlab">GitLab</option>
          </select>
        </label>
        <label className="flex flex-1 flex-col gap-1 text-xs">
          <span className="font-medium uppercase tracking-wide text-slate-500">Access token</span>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={provider === "github" ? "ghp_…" : "glpat-…"}
            autoComplete="off"
            className="rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium uppercase tracking-wide text-slate-500">Name (optional)</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="acme-org"
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
          />
        </label>
        <button
          type="submit"
          disabled={connect.isPending || !token.trim()}
          className="btn-primary px-4 py-2 text-xs disabled:opacity-50"
        >
          {connect.isPending ? "Connecting…" : "Connect"}
        </button>
      </form>
      {connect.isError ? (
        <p className="mt-2 text-xs text-rose-600">
          {connect.error instanceof ApiError
            ? connect.error.message
            : "Could not connect. Check the token and try again."}
        </p>
      ) : null}
    </Card>
  );
}

function ImportedRepos() {
  const { data, isLoading } = useRepositories();
  const { data: policies } = usePolicies();
  const assign = useAssignPolicy();

  if (isLoading) return <Spinner label="Loading repositories…" />;
  const repos = data?.items ?? [];
  if (repos.length === 0) {
    return (
      <EmptyState
        title="No repositories imported"
        description="Import a repository from a connected integration to track its pull requests."
      />
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-2.5">Repository</th>
            <th className="px-4 py-2.5">Default branch</th>
            <th className="px-4 py-2.5">Policy</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {repos.map((repo) => (
            <tr key={repo.id} className="hover:bg-slate-50/60">
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <ProviderBadge provider={repo.provider} />
                  <a href={repo.web_url} target="_blank" rel="noreferrer" className="font-medium text-slate-800 hover:text-brand">
                    {repo.full_name}
                  </a>
                  {repo.private ? <Badge className="bg-slate-100 text-slate-500 ring-slate-300">private</Badge> : null}
                </div>
              </td>
              <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{repo.default_branch}</td>
              <td className="px-4 py-2.5">
                <select
                  value={repo.policy_id ?? ""}
                  onChange={(e) =>
                    assign.mutate({
                      id: e.target.value,
                      scope_type: "repo",
                      scope_value: repo.full_name,
                    })
                  }
                  disabled={!policies?.items.length}
                  className="rounded-lg border border-slate-300 px-2 py-1 text-xs outline-none focus:border-brand"
                >
                  <option value="">— none —</option>
                  {policies?.items.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ImportRepoForm({ integrationId }: { integrationId: string }) {
  const importRepo = useImportRepository();
  const [value, setValue] = useState("");

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const [owner, name] = value.split("/");
    if (!owner || !name) return;
    importRepo.mutate(
      { integrationId, owner: owner.trim(), name: name.trim() },
      { onSuccess: () => setValue("") },
    );
  };

  return (
    <form onSubmit={onSubmit} className="mt-2 flex items-center gap-2">
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="owner/repo"
        className="flex-1 rounded-lg border border-slate-300 px-2.5 py-1.5 font-mono text-xs outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
      />
      <button
        type="submit"
        disabled={importRepo.isPending || !value.includes("/")}
        className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
      >
        {importRepo.isPending ? "Importing…" : "Import"}
      </button>
    </form>
  );
}

export default function Integrations() {
  const { data, isLoading, isError } = useIntegrations();
  const remove = useDeleteIntegration();
  const integrations = data?.items ?? [];

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Integrations"
        subtitle="Connect GitHub or GitLab to scan pull requests continuously."
      />

      {isError ? (
        <Card className="p-5">
          <p className="text-sm text-rose-600">
            Could not load integrations. If this persists, the encryption key may not be
            configured on the server.
          </p>
        </Card>
      ) : null}

      <div className="space-y-6">
        <ConnectForm />

        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-900">Connected providers</h2>
          {isLoading ? (
            <Spinner label="Loading integrations…" />
          ) : integrations.length === 0 ? (
            <EmptyState title="No integrations yet" description="Connect a provider above to get started." />
          ) : (
            <div className="space-y-3">
              {integrations.map((integ) => (
                <Card key={integ.id} className="p-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <ProviderBadge provider={integ.provider} />
                        <span className="font-medium text-slate-800">{integ.name}</span>
                        <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">{integ.status}</Badge>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">
                        {integ.account ? `@${integ.account} · ` : ""}connected {relativeTime(integ.created_at)}
                      </p>
                      <ImportRepoForm integrationId={integ.id} />
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(`Disconnect ${integ.name}? Imported repositories will be removed.`)) {
                          remove.mutate(integ.id);
                        }
                      }}
                      className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-medium text-rose-600 hover:bg-rose-50"
                    >
                      Disconnect
                    </button>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>

        <div>
          <h2 className="mb-3 text-sm font-semibold text-slate-900">Imported repositories</h2>
          <ImportedRepos />
        </div>
      </div>
    </div>
  );
}
