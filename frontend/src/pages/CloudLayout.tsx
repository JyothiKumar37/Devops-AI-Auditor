import { NavLink, Outlet, useParams } from "react-router-dom";

import { Badge, Spinner } from "@/components/ui";
import { useCloudAccount, useSyncCloudAccount } from "@/hooks/useCloud";
import { relativeTime } from "@/lib/format";

const TABS = [
  { to: "", label: "Overview", end: true },
  { to: "assets", label: "Assets" },
  { to: "findings", label: "Findings" },
  { to: "network", label: "Network" },
  { to: "drift", label: "IaC Drift" },
  { to: "compliance", label: "Compliance" },
  { to: "changes", label: "Changes" },
  { to: "eks", label: "EKS" },
  { to: "investigate", label: "Investigate" },
];

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-slate-400">{label}</span>
      <span className={`text-slate-600 ${mono ? "font-mono text-[11px]" : ""}`}>{value}</span>
    </span>
  );
}

export default function CloudLayout() {
  const { accountId } = useParams();
  const { data: account, isLoading } = useCloudAccount(accountId ?? null);
  const sync = useSyncCloudAccount(accountId ?? "");

  return (
    <div>
      <div className="mb-4 rounded-2xl border border-slate-200/70 bg-white p-4 shadow-soft sm:p-5">
        <NavLink to="/cloud" className="text-xs font-medium text-slate-500 hover:text-brand">
          ← All accounts
        </NavLink>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-brand-gradient text-white shadow-glow">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 014-4 5 5 0 019.6-1.5A3.5 3.5 0 0118 15H6a3 3 0 01-3-3z" />
            </svg>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">
            {account?.name || account?.account_id || "Cloud account"}
          </h1>
          {account ? (
            <Badge
              className={
                account.status === "connected"
                  ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                  : account.status === "error"
                    ? "bg-rose-50 text-rose-700 ring-rose-600/20"
                    : "bg-amber-50 text-amber-700 ring-amber-600/20"
              }
            >
              {account.status}
            </Badge>
          ) : null}
          {accountId ? (
            <div className="ml-auto">
              <button
                type="button"
                onClick={() => sync.mutate()}
                disabled={sync.isPending}
                className="btn-primary px-3.5 py-2 text-xs disabled:opacity-50"
              >
                {sync.isPending ? "Syncing…" : "Sync now"}
              </button>
            </div>
          ) : null}
        </div>
        {account ? (
          <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 rounded-lg bg-slate-50 px-3 py-2 text-xs">
            <Meta label="account" value={account.account_id} mono />
            <Meta label="regions" value={account.regions.join(", ") || "default"} />
            <Meta
              label="synced"
              value={account.last_synced_at ? relativeTime(account.last_synced_at) : "never"}
            />
          </div>
        ) : null}
        {sync.isError ? (
          <p className="mt-2 text-xs text-rose-600">Sync failed. Re-validate the role access.</p>
        ) : null}
      </div>

      <div className="mb-6 flex gap-1 overflow-x-auto border-b border-slate-200">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to || "overview"}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              `-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-semibold transition-colors ${
                isActive
                  ? "border-brand text-brand-deep"
                  : "border-transparent text-slate-500 hover:text-slate-800"
              }`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </div>

      {isLoading && !account ? <Spinner /> : <Outlet />}
    </div>
  );
}
