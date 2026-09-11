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

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-full">
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-white/10 bg-slate-950/70 px-4 py-5 lg:flex">
        <div className="mb-8 flex items-center gap-2.5 px-2">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-brand/15 text-brand ring-1 ring-inset ring-brand/30">
            <span className="text-sm font-bold">DA</span>
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-white">DevOps Auditor</p>
            <p className="text-[11px] text-slate-500">Security &amp; readiness</p>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  isActive
                    ? "bg-brand/10 text-brand ring-1 ring-inset ring-brand/20"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                }`
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto border-t border-white/10 pt-4">
          <HealthDot />
        </div>
      </aside>

      <div className="flex min-h-full flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-white/10 bg-slate-950/60 px-4 backdrop-blur sm:px-6 lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <span className="text-sm font-semibold text-white">DevOps Auditor</span>
          </div>
          <div className="hidden text-xs text-slate-500 lg:block">
            Repository security &amp; production-readiness auditing
          </div>
          <div className="flex items-center gap-4">
            <NavLink
              to="/scan/new"
              className="rounded-lg bg-brand px-3 py-1.5 text-xs font-semibold text-slate-950 transition hover:bg-brand-muted"
            >
              New Scan
            </NavLink>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
