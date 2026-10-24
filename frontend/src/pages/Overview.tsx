import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import { Badge, Card, Empty, ErrorBox, PageHeader, Spinner, Stat } from "../components/ui";
import { ago } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { useLiveReload } from "../lib/live";

interface OverviewData {
  kpis: Record<string, number>;
  alerts_daily: { day: string; total: number; critical: number; high: number }[];
  logins_hourly: { hour: string; success: number; failure: number }[];
  alerts_by_rule: { rule_key: string; count: number }[];
  risky_users: { user_id: string; username: string; max_risk: number; alerts: number }[];
  login_countries: { country: string; count: number }[];
  recent_alerts: { id: string; rule_key: string; title: string; severity: string; risk: number; created_at: string; status: string }[];
  users_by_state: Record<string, number>;
}

const axis = { fontSize: 11, fill: "#94a3b8" };

export default function Overview() {
  const { data, error, loading, reload } = useAsync(() => api<OverviewData>("/overview"));
  useLiveReload(reload);
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return null;
  const k = data.kpis;
  const hourly = data.logins_hourly.map((h) => ({ ...h, label: new Date(h.hour).toLocaleTimeString([], { hour: "2-digit" }) }));
  return (
    <div className="space-y-5">
      <PageHeader title="Overview" subtitle="Identity threat posture for this tenant" />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Open alerts" value={k.open_alerts} tone={k.open_alerts ? "amber" : "green"} />
        <Stat label="Critical open" value={k.critical_open} tone={k.critical_open ? "red" : "green"} />
        <Stat label="Active sessions" value={k.active_sessions} />
        <Stat label="Active users" value={k.active_users} />
        <Stat label="Deprovisioned" value={k.deprovisioned_users} />
        <Stat label="Pending approvals" value={k.pending_approvals} tone={k.pending_approvals ? "amber" : "default"} />
        <Stat label="Events (24h)" value={k.events_24h} />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Logins, last 24 hours">
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={hourly}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.3} />
                <XAxis dataKey="label" tick={axis} />
                <YAxis tick={axis} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Area type="monotone" dataKey="success" stroke="#10b981" fill="#10b981" fillOpacity={0.25} name="Success" />
                <Area type="monotone" dataKey="failure" stroke="#ef4444" fill="#ef4444" fillOpacity={0.25} name="Failure" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Alerts, last 7 days">
          <div className="h-56">
            {data.alerts_daily.length ? (
              <ResponsiveContainer>
                <BarChart data={data.alerts_daily}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.3} />
                  <XAxis dataKey="day" tick={axis} />
                  <YAxis tick={axis} allowDecimals={false} />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="critical" stackId="a" fill="#dc2626" name="Critical" />
                  <Bar dataKey="high" stackId="a" fill="#f97316" name="High" />
                </BarChart>
              </ResponsiveContainer>
            ) : <Empty>No alerts this week.</Empty>}
          </div>
        </Card>
        <Card title="Alerts by detection (7 days)">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={data.alerts_by_rule} layout="vertical">
                <XAxis type="number" tick={axis} allowDecimals={false} />
                <YAxis type="category" dataKey="rule_key" tick={axis} width={40} interval={0} />
                <Tooltip />
                <Bar dataKey="count" fill="#6366f1" name="Alerts" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Riskiest identities (open alerts)">
          {data.risky_users.length === 0 ? <Empty>No open risk.</Empty> : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.risky_users.map((u) => (
                <li key={u.user_id} className="flex items-center justify-between py-2 text-sm">
                  <Link to={`/timeline?user=${u.user_id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">{u.username}</Link>
                  <span className="text-slate-500">{u.alerts} alerts · max risk <b className="tabular-nums text-slate-800 dark:text-slate-200">{u.max_risk}</b></span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card title="Recent alerts" actions={<Link className="text-sm text-indigo-600 hover:underline dark:text-indigo-400" to="/alerts">All alerts</Link>}>
        {data.recent_alerts.length === 0 ? <Empty>No alerts.</Empty> : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {data.recent_alerts.map((a) => (
              <li key={a.id} className="flex items-center gap-3 py-2 text-sm">
                <Badge>{a.severity}</Badge>
                <span className="font-mono text-xs text-slate-500">{a.rule_key}</span>
                <Link to={`/alerts/${a.id}`} className="flex-1 truncate hover:underline">{a.title}</Link>
                <span className="tabular-nums text-slate-500">risk {a.risk}</span>
                <span className="w-20 text-right text-xs text-slate-500">{ago(a.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
