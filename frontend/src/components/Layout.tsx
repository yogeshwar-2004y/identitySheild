import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, BookOpenCheck, FlaskConical, Gauge, LogOut, Moon, ScrollText, Search, Settings, ShieldCheck,
  Sun, UserCog, Users, Workflow,
} from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { streamAlerts } from "../api/client";
import { cx } from "./ui";

interface NavItem { to: string; label: string; icon: typeof Gauge; roles?: string[]; lab?: boolean }

export const NAV: NavItem[] = [
  { to: "/", label: "Overview", icon: Gauge, roles: ["admin", "analyst"] },
  { to: "/alerts", label: "Alerts", icon: AlertTriangle, roles: ["admin", "analyst"] },
  { to: "/hunt", label: "Hunt Console", icon: Search, roles: ["admin", "analyst"] },
  { to: "/timeline", label: "User Timeline", icon: Activity, roles: ["admin", "analyst"] },
  { to: "/lifecycle", label: "Lifecycle", icon: Workflow, roles: ["admin", "hr", "analyst"] },
  { to: "/sessions", label: "Sessions", icon: Users },
  { to: "/rules", label: "Rules & Playbooks", icon: BookOpenCheck, roles: ["admin", "analyst"] },
  { to: "/audit", label: "Audit Log", icon: ScrollText, roles: ["admin", "analyst"] },
  { to: "/settings", label: "Tenant Settings", icon: Settings },
  { to: "/lab", label: "Attack Lab", icon: FlaskConical, roles: ["admin"], lab: true },
];

interface LiveAlert { id: string; title: string; severity: string; rule_key: string }

function useTheme(): [boolean, () => void] {
  const [dark, setDark] = useState(() => {
    try {
      return (localStorage.getItem("is-theme") ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("is-theme", dark ? "dark" : "light"); // UI preference only; never tokens
    } catch {
      /* ignore */
    }
  }, [dark]);
  return [dark, () => setDark((d) => !d)];
}

export function Layout() {
  const { me, hasRole, logout } = useAuth();
  const [dark, toggle] = useTheme();
  const [live, setLive] = useState(false);
  const [toasts, setToasts] = useState<LiveAlert[]>([]);
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  useEffect(() => {
    if (!hasRole("admin", "analyst")) return;
    return streamAlerts(
      (a) => {
        const alert = a as LiveAlert;
        setToasts((t) => [alert, ...t].slice(0, 4));
        window.dispatchEvent(new CustomEvent("is:alert", { detail: alert }));
        window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== alert.id)), 9000);
      },
      setLive,
    );
  }, [hasRole]);

  const items = NAV.filter((n) => (!n.roles || hasRole(...n.roles)) && (!n.lab || me?.lab_mode));
  const doLogout = async (all: boolean) => {
    setBusy(true);
    await logout(all);
  };

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-slate-200 bg-white px-3 py-4 dark:border-slate-800 dark:bg-slate-900 md:flex">
        <div className="mb-6 flex items-center gap-2 px-2">
          <ShieldCheck className="h-6 w-6 text-indigo-500" />
          <div>
            <div className="text-sm font-semibold">IdentityShield</div>
            <div className="text-xs text-slate-500">ITDR · {me?.tenant.name}</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5">
          {items.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm",
                  isActive ? "bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
                )
              }
            >
              <n.icon className="h-4 w-4" /> {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-4 border-t border-slate-200 pt-3 text-xs text-slate-500 dark:border-slate-800">
          <div className="flex items-center gap-1.5">
            <span className={cx("h-2 w-2 rounded-full", live ? "bg-emerald-500" : "bg-slate-400")} />
            {hasRole("admin", "analyst") ? (live ? "Live alert stream" : "Stream reconnecting…") : "Signed in"}
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-slate-200 bg-white/80 px-4 py-2.5 backdrop-blur dark:border-slate-800 dark:bg-slate-900/80">
          <select
            aria-label="Navigate"
            className="rounded-lg border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-800 md:hidden"
            onChange={(e) => nav(e.target.value)}
            value={location.pathname}
          >
            {items.map((n) => <option key={n.to} value={n.to}>{n.label}</option>)}
          </select>
          <div className="hidden text-sm text-slate-500 md:block">
            Realm <span className="font-mono">{me?.tenant.realm}</span>
          </div>
          <div className="flex items-center gap-2">
            <button aria-label="Toggle theme" className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={toggle}>
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <div className="hidden text-right text-xs leading-tight sm:block">
              <div className="font-medium text-slate-700 dark:text-slate-200">{me?.full_name || me?.username}</div>
              <div className="text-slate-500">{me?.roles.join(", ")}</div>
            </div>
            <UserCog className="hidden h-5 w-5 text-slate-400 sm:block" />
            <button
              className="inline-flex items-center gap-1 rounded-lg border border-slate-300 px-2.5 py-1 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
              onClick={() => void doLogout(false)}
              disabled={busy}
            >
              <LogOut className="h-4 w-4" /> Logout
            </button>
            <button className="hidden rounded-lg px-2 py-1 text-xs text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 sm:block" onClick={() => void doLogout(true)} disabled={busy}>
              Logout all devices
            </button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
          <Outlet />
        </main>
      </div>

      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <button
            key={t.id}
            onClick={() => nav(`/alerts/${t.id}`)}
            className="pointer-events-auto rounded-xl border border-red-200 bg-white p-3 text-left text-sm shadow-lg dark:border-red-900 dark:bg-slate-900"
          >
            <div className="flex items-center gap-2 text-xs font-semibold uppercase text-red-600">
              <AlertTriangle className="h-3.5 w-3.5" /> New {t.severity} alert · {t.rule_key}
            </div>
            <div className="mt-1 line-clamp-2">{t.title}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
