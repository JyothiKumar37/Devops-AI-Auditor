import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

import { useHealth } from "@/hooks/useHealth";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

const NAV: NavItem[] = [
  { to: "/", end: true, label: "Dashboard", icon: <Icon path="M3 12l9-9 9 9M5 10v10h14V10" /> },
  { to: "/scan/new", label: "New Scan", icon: <Icon path="M12 4v16m8-8H4" /> },
  { to: "/scans", label: "Scan History", icon: <Icon path="M4 6h16M4 12h16M4 18h16" /> },
  { to: "/settings", label: "Settings", icon: <Icon path="M10.3 4.3a1 1 0 011.4 0l1 1a1 1 0 001.1.2l1.3-.5a1 1 0 011.3.6l.5 1.3a1 1 0 00.8.6l1.4.2a1 1 0 01.9 1v1.4a1 1 0 00.4 1l1 1a1 1 0 010 1.4l-1 1a1 1 0 00-.4 1v1.4a1 1 0 01-.9 1l-1.4.2M12 15a3 3 0 100-6 3 3 0 000 6z" /> },
];

function HealthDot() {
  const { data, isError, isLoading } = useHealth();
  const state = isLoading ? "loading" : isError || data?.status === "unhealthy" ? "down" : "up";
  const color =
    state === "up" ? "bg-emerald-500" : state === "down" ? "bg-rose-500" : "bg-amber-500";
  const label = state === "up" ? "API healthy" : state === "down" ? "API unreachable" : "Connecting";
  return (
    <div className="flex items-center gap-2 text-xs text-slate-400">
      <span className={`h-2 w-2 rounded-full ${color}`} aria-hidden />
      {label}
    </div>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-3 px-2">
      <div className="grid h-10 w-10 place-items-center rounded-xl bg-brand-gradient text-white shadow-[0_8px_24px_-8px_rgba(56,189,248,0.7)]">
        <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V7l7-4z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l1.8 1.8L15 10" />
        </svg>
      </div>
      <div className="leading-tight">
        <p className="text-sm font-semibold text-white">DevOps Auditor</p>
        <p className="text-[11px] text-slate-500">Security &amp; readiness</p>
      </div>
    </div>
  );
}

function NavList() {
  return (
    <nav className="flex flex-1 flex-col gap-1">
      <p className="mb-1 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">
        Workspace
      </p>
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            `group relative flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition ${
              isActive
                ? "bg-white/[0.06] text-white ring-1 ring-inset ring-white/10"
                : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200"
            }`
          }
        >
          {({ isActive }) => (
            <>
              <span
                className={`absolute left-0 top-1/2 h-5 -translate-y-1/2 rounded-full bg-brand-gradient transition-all ${
                  isActive ? "w-1 opacity-100" : "w-0 opacity-0"
                }`}
              />
              <span className={isActive ? "text-brand" : "text-slate-500 group-hover:text-slate-300"}>
                {item.icon}
              </span>
              {item.label}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-full">
      <aside className="fixed inset-y-0 left-0 hidden w-64 flex-col border-r border-white/[0.06] bg-slate-950/50 px-4 py-6 backdrop-blur-xl lg:flex">
        <div className="mb-8">
          <Brand />
        </div>
        <NavList />
        <div className="mt-auto space-y-3 border-t border-white/[0.06] pt-4">
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2.5">
            <HealthDot />
          </div>
          <p className="px-1 text-[10px] text-slate-600">v0.1 · Enterprise edition</p>
        </div>
      </aside>

      <div className="flex min-h-full flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-white/[0.06] bg-slate-950/40 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <span className="brand-text text-sm font-bold">DevOps Auditor</span>
          </div>
          <div className="hidden items-center gap-2 text-xs text-slate-500 lg:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-brand" />
            Repository security &amp; production-readiness auditing
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:block">
              <HealthDot />
            </div>
            <NavLink to="/scan/new" className="btn-primary px-3.5 py-1.5 text-xs">
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
