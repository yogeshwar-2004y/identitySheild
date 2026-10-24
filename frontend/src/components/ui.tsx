import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Loader2 } from "lucide-react";

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(" ");
}

export function Card({ title, actions, children, className }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

const SEV: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-300 text-amber-950",
  low: "bg-sky-200 text-sky-900 dark:bg-sky-900 dark:text-sky-100",
};
const STATE: Record<string, string> = {
  ACTIVE: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
  PENDING: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200",
  SUSPENDED: "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200",
  DEPROVISIONED: "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
  OPEN: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  ACKNOWLEDGED: "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200",
  RESOLVED: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
  FALSE_POSITIVE: "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
  COMPLETED: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
  FAILED: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  PENDING_APPROVAL: "bg-violet-100 text-violet-800 dark:bg-violet-900/50 dark:text-violet-200",
  SCHEDULED: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200",
  RUNNING: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200",
  REJECTED: "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
  ACTIVE_MODE: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  DRY_RUN: "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const key = (tone ?? String(children)).toString();
  const cls = SEV[key.toLowerCase()] ?? STATE[key.toUpperCase()] ?? "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200";
  return <span className={cx("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap", cls)}>{children}</span>;
}

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost"; busy?: boolean };

export function Button({ variant = "secondary", busy, className, children, disabled, ...rest }: BtnProps) {
  const styles = {
    primary: "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-300",
    secondary: "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700",
    danger: "bg-red-600 text-white hover:bg-red-500 disabled:bg-red-300",
    ghost: "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
  }[variant];
  return (
    <button
      className={cx("inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed", styles, className)}
      disabled={disabled || busy}
      {...rest}
    >
      {busy && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-slate-500" role="status">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="flex items-start justify-between gap-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/50 dark:text-red-200">
      <span>{msg}</span>
      {onRetry && <button className="underline" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-slate-500">{children}</p>;
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: "red" | "amber" | "green" | "default" }) {
  const color = { red: "text-red-600 dark:text-red-400", amber: "text-amber-600 dark:text-amber-400", green: "text-emerald-600 dark:text-emerald-400", default: "" }[tone ?? "default"];
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className={cx("mt-1 text-2xl font-semibold tabular-nums", color)}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function JsonView({ value }: { value: unknown }) {
  return (
    <pre className="max-h-96 overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Table({ head, children, empty }: { head: ReactNode[]; children: ReactNode; empty?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>{head.map((h, i) => <th key={i} className="whitespace-nowrap px-3 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{children}</tbody>
      </table>
      {empty && <Empty>Nothing to show.</Empty>}
    </div>
  );
}

export const td = "px-3 py-2 align-top";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium text-slate-700 dark:text-slate-300">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export const inputCls =
  "w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
