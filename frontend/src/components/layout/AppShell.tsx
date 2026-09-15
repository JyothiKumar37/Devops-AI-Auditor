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
    <svg className="h-[18px] w-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

const NAV: NavItem[] = [
  { to: "/", end: true, label: "Dashboard", icon: <Icon path="M3 12l9-9 9 9M5 10v10h14V10" /> },
  { to: "/scan/new", label: "New Scan", icon: <Icon path="M12 4v16m8-8H4" /> },
  { to: "/scans", label: "Scans", icon: <Icon path="M4 6h16M4 12h16M4 18h16" /> },
  { to: "/settings", label: "Settings", icon: <Icon path="M10.3 4.3a1 1 0 011.4 0l1 1a1 1 0 001.1.2l1.3-.5a1 1 0 011.3.6l.5 1.3a1 1 0 00.8.6l1.4.2a1 1 0 01.9 1v1.4a1 1 0 00.4 1l1 1a1 1 0 010 1.4l-1 1a1 1 0 00-.4 1v1.4a1 1 0 01-.9 1l-1.4.2M12 15a3 3 0 100-6 3 3 0 000 6z" /> },
];

function HealthDot() {
  const { data, isError, isLoading } = useHealth();
  const state = isLoading ? "loading" : isError || data?.status === "unhealthy" ? "down" : "up";
  const color =
    state === "up" ? "bg-emerald-500" : state === "down" ? "bg-rose-500" : "bg-amber-500";
  const label = state === "up" ? "API healthy" : state === "down" ? "API unreachable" : "Connecting";
  return (
    <div className="flex items-center gap-2 text-xs text-slate-500">
      <span className={`h-2 w-2 rounded-full ${color}`} aria-hidden />
      {label}
    </div>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-1">
      <div className="grid h-8 w-8 place-items-center rounded-md bg-slate-900 text-white">
        <svg className="h-[18px] w-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l7 4v5c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V7l7-4z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l1.8 1.8L15 10" />
        </svg>
      </div>
      <div className="leading-tight">
        <p className="text-sm font-semibold text-slate-900">DevOps Auditor</p>
        <p className="font-mono text-[10px] text-slate-400">static analysis</p>
      </div>
    </div>
  );
}

function NavList() {
  return (
    <nav className="flex flex-1 flex-col gap-0.5">
      <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
        Workspace
      </p>
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            `group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors ${
              isActive
                ? "bg-slate-100 font-medium text-slate-900"
                : "text-slate-600 hover:bg-slate-100/70 hover:text-slate-900"
            }`
          }
        >
          {({ isActive }) => (
            <>
              <span
                className={`absolute left-0 top-1/2 h-4 -translate-y-1/2 rounded-r bg-brand transition-all ${
                  isActive ? "w-0.5 opacity-100" : "w-0 opacity-0"
                }`}
              />
              <span className={isActive ? "text-brand" : "text-slate-400 group-hover:text-slate-500"}>
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
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-slate-200 bg-white px-3 py-4 lg:flex">
        <div className="mb-6 mt-1">
          <Brand />
        </div>
        <NavList />
        <div className="mt-auto space-y-2 border-t border-slate-200 pt-3">
          <div className="px-2">
            <HealthDot />
          </div>
          <p className="px-2 font-mono text-[10px] text-slate-400">v0.1.0</p>
        </div>
      </aside>

      <div className="flex min-h-full flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <span className="text-sm font-semibold text-slate-900">DevOps Auditor</span>
          </div>
          <div className="hidden lg:block" />
          <div className="flex items-center gap-4">
            <div className="hidden sm:block">
              <HealthDot />
            </div>
            <NavLink to="/scan/new" className="btn-primary px-3 py-1.5 text-xs">
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
