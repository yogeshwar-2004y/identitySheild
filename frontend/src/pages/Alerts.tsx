import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, ErrorBox, inputCls, PageHeader, Spinner, Table, td } from "../components/ui";
import { ago } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { useLiveReload } from "../lib/live";

export interface AlertRow {
  id: string; rule_key: string; title: string; severity: string; risk: number; status: string;
  attack_technique: string; user_id: string | null; username: string | null; session_id: string | null; created_at: string;
}

export default function Alerts() {
  const [status, setStatus] = useState("OPEN");
  const [severity, setSeverity] = useState("");
  const q = new URLSearchParams();
  if (status) q.set("status", status);
  if (severity) q.set("severity", severity);
  const { data, error, loading, reload } = useAsync(() => api<AlertRow[]>(`/alerts?${q.toString()}`), [status, severity]);
  useLiveReload(reload);
  return (
    <div>
      <PageHeader title="Alerts" subtitle="Detections D01–D12 with risk score and automated response" />
      <Card
        title={`${data?.length ?? 0} alerts`}
        actions={
          <>
            <select aria-label="Status" className={inputCls} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">All statuses</option>
              {["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <select aria-label="Severity" className={inputCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </>
        }
      >
        <ErrorBox error={error} onRetry={reload} />
        {loading && !data ? <Spinner /> : (
          <Table head={["Severity", "Rule", "Alert", "User", "Risk", "Status", "When"]} empty={data?.length === 0}>
            {data?.map((a) => (
              <tr key={a.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <td className={td}><Badge>{a.severity}</Badge></td>
                <td className={`${td} font-mono text-xs`}>{a.rule_key}</td>
                <td className={td}>
                  <Link className="font-medium hover:underline" to={`/alerts/${a.id}`}>{a.title}</Link>
                  <div className="text-xs text-slate-500">{a.attack_technique}</div>
                </td>
                <td className={td}>{a.user_id ? <Link className="text-indigo-600 hover:underline dark:text-indigo-400" to={`/timeline?user=${a.user_id}`}>{a.username}</Link> : "—"}</td>
                <td className={`${td} tabular-nums font-semibold`}>{a.risk}</td>
                <td className={td}><Badge>{a.status}</Badge></td>
                <td className={`${td} whitespace-nowrap text-xs text-slate-500`}>{ago(a.created_at)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
