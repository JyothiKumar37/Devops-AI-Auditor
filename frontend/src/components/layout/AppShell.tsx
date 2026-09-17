import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

import { useHealth } from "@/hooks/useHealth";

interface NavItem {
  to: string;
  label: string;
  hint: string;
  icon: ReactNode;
  end?: boolean;
}

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-[18px] w-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

const NAV: NavItem[] = [
  { to: "/", end: true, label: "Dashboard", hint: "Fleet overview", icon: <Icon path="M3 12l9-9 9 9M5 10v10h14V10" /> },
  { to: "/scan/new", label: "New Scan", hint: "Audit a repository", icon: <Icon path="M12 4v16m8-8H4" /> },
  { to: "/scans", label: "Scans", hint: "History & status", icon: <Icon path="M4 6h16M4 12h16M4 18h16" /> },
  {
    to: "/settings",
    label: "Settings",
    hint: "Workspace config",
    icon: (
      <Icon path="M10.3 4.3a1 1 0 011.4 0l1 1a1 1 0 001.1.2l1.3-.5a1 1 0 011.3.6l.5 1.3a1 1 0 00.8.6l1.4.2a1 1 0 01.9 1v1.4a1 1 0 00.4 1l1 1a1 1 0 010 1.4l-1 1a1 1 0 00-.4 1v1.4a1 1 0 01-.9 1l-1.4.2M12 15a3 3 0 100-6 3 3 0 000 6z" />
    ),
  },
];

function useHealthState() {
  const { data, isError, isLoading } = useHealth();
  const state = isLoading ? "loading" : isError || data?.status === "unhealthy" ? "down" : "up";
  return { state, environment: data?.environment ?? null, version: data?.version ?? null };
}

function HealthDot({ compact = false }: { compact?: boolean }) {
  const { state } = useHealthState();
  const color =
    state === "up" ? "bg-emerald-500" : state === "down" ? "bg-rose-500" : "bg-amber-500";
  const label = state === "up" ? "API healthy" : state === "down" ? "API unreachable" : "Connecting";
  return (
    <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
      <span className="relative flex h-2 w-2">
        {state === "up" ? (
          <span className="absolute inline-flex h-full w-full animate-pulse-ring rounded-full" />
        ) : null}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${color}`} aria-hidden />
      </span>
      {!compact && label}
    </div>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-3 px-1">
      <div className="relative grid h-9 w-9 place-items-center rounded-xl bg-brand-gradient text-white shadow-glow">
        <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V7l7-4z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l1.8 1.8L15 10" />
        </svg>
      </div>
      <div className="leading-tight">
        <p className="text-[15px] font-bold tracking-tight text-slate-900">
          DevOps <span className="text-gradient">Auditor</span>
        </p>
        <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-400">
          static analysis
        </p>
      </div>
    </div>
  );
}

function NavList() {
  return (
    <nav className="flex flex-1 flex-col gap-1">
      <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">
        Workspace
      </p>
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            `group relative flex items-center gap-3 rounded-xl px-2.5 py-2 transition-all ${
              isActive
                ? "bg-brand-50 text-slate-900 shadow-[inset_0_0_0_1px_rgba(99,102,241,0.18)]"
                : "text-slate-600 hover:bg-slate-100/70 hover:text-slate-900"
            }`
          }
        >
          {({ isActive }) => (
            <>
              <span
                className={`absolute left-0 top-1/2 h-6 -translate-y-1/2 rounded-r-full bg-brand-gradient transition-all ${
                  isActive ? "w-1 opacity-100" : "w-0 opacity-0"
                }`}
              />
              <span
                className={`icon-tile transition-colors ${
                  isActive
                    ? "bg-white text-brand ring-brand-200"
                    : "bg-slate-50 text-slate-400 ring-slate-200 group-hover:text-slate-600"
                }`}
              >
                {item.icon}
              </span>
              <span className="flex flex-col">
                <span className="text-sm font-medium leading-tight">{item.label}</span>
                <span className="text-[11px] leading-tight text-slate-400">{item.hint}</span>
              </span>
            </>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

function StatusCard() {
  const { state, environment, version } = useHealthState();
  const tone =
    state === "up"
      ? "from-emerald-50 to-white ring-emerald-200/70"
      : state === "down"
        ? "from-rose-50 to-white ring-rose-200/70"
        : "from-amber-50 to-white ring-amber-200/70";
  return (
    <div className={`rounded-xl bg-gradient-to-br ${tone} p-3 ring-1 ring-inset`}>
      <div className="flex items-center justify-between">
        <HealthDot />
        {environment ? (
          <span className="chip bg-white/70 text-slate-500 ring-slate-300/60 capitalize">{environment}</span>
        ) : null}
      </div>
      <p className="mt-2 font-mono text-[10px] text-slate-400">build v{version ?? "0.1.0"}</p>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-full">
      <aside className="fixed inset-y-0 left-0 hidden w-64 flex-col border-r border-slate-200/80 bg-white/70 px-3 py-4 backdrop-blur-xl lg:flex">
        <div className="mb-7 mt-1">
          <Brand />
        </div>
        <NavList />
        <div className="mt-auto pt-3">
          <StatusCard />
        </div>
      </aside>

      <div className="flex min-h-full flex-1 flex-col lg:pl-64">
        <header className="glass sticky top-0 z-20 flex h-16 items-center justify-between border-x-0 border-t-0 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <div className="grid h-7 w-7 place-items-center rounded-lg bg-brand-gradient text-white">
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V7l7-4z" />
              </svg>
            </div>
            <span className="text-sm font-bold text-slate-900">DevOps Auditor</span>
          </div>
          <div className="hidden items-center gap-2 lg:flex">
            <span className="text-sm font-semibold text-slate-800">Control Center</span>
            <span className="chip bg-brand-50 text-brand-deep ring-brand-200">live</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:block">
              <HealthDot />
            </div>
            <span className="hidden h-5 w-px bg-slate-200 sm:block" />
            <NavLink to="/scan/new" className="btn-primary px-3.5 py-2 text-xs">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              New Scan
            </NavLink>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
