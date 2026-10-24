import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Button, Card, ErrorBox, Field, inputCls, JsonView, PageHeader, Spinner, Table, td } from "../components/ui";
import { fmtTime } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { AlertRow } from "./Alerts";

interface AlertFull extends AlertRow {
  evidence: Record<string, unknown>;
  response: { tier: string; mode: string; contribution: number; carry: number; planned_actions: string[]; results: { action: string; status: string; detail: string }[] };
  user: { id: string; username: string; email: string; state: string; department: string } | null;
  trigger_event?: { type: string; ts: string; ip: string; geo: unknown; source: string; details: unknown };
  notes: string | null;
}

export default function AlertDetail() {
  const { id } = useParams();
  const { data, error, loading, reload } = useAsync(() => api<AlertFull>(`/alerts/${id}`), [id]);
  const [notes, setNotes] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return null;
  const update = async (status?: string) => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/alerts/${data.id}`, { method: "PATCH", json: { status, notes: notes ?? data.notes ?? "" } });
      await reload();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  const r = data.response;
  return (
    <div className="space-y-5">
      <PageHeader
        title={data.title}
        subtitle={`${data.rule_key} · ${data.attack_technique} · ${fmtTime(data.created_at)}`}
        actions={<><Badge>{data.severity}</Badge><Badge>{data.status}</Badge></>}
      />
      <ErrorBox error={err} />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Risk & response" className="lg:col-span-1">
          <div className="text-4xl font-semibold tabular-nums">{data.risk}</div>
          <div className="mt-1 text-sm text-slate-500">
            risk = weight × confidence ({r.contribution}) + carry ({r.carry}) → tier <b>{r.tier}</b>
          </div>
          <div className="mt-3 text-sm">Playbook mode: <Badge tone={r.mode === "ACTIVE" ? "ACTIVE_MODE" : "DRY_RUN"}>{r.mode}</Badge></div>
          <ul className="mt-3 space-y-1.5 text-sm">
            {r.results.map((x, i) => (
              <li key={i} className="rounded-lg bg-slate-50 px-2 py-1.5 dark:bg-slate-800">
                <span className="font-mono text-xs">{x.action}</span> <Badge tone={x.status === "done" ? "COMPLETED" : x.status === "failed" ? "FAILED" : "DRY_RUN"}>{x.status}</Badge>
                <div className="text-xs text-slate-500">{x.detail}</div>
              </li>
            ))}
            {r.results.length === 0 && <li className="text-slate-500">No automated action (log only).</li>}
          </ul>
        </Card>
        <Card title="Identity" className="lg:col-span-1">
          {data.user ? (
            <div className="space-y-1 text-sm">
              <div className="font-medium">{data.user.username} <Badge>{data.user.state}</Badge></div>
              <div className="text-slate-500">{data.user.email}</div>
              <div className="text-slate-500">{data.user.department}</div>
              <div className="pt-2"><Link className="text-indigo-600 hover:underline dark:text-indigo-400" to={`/timeline?user=${data.user.id}`}>Open user timeline →</Link></div>
              {data.session_id && <div className="pt-1 text-xs text-slate-500">Session <span className="font-mono">{data.session_id}</span></div>}
            </div>
          ) : <p className="text-sm text-slate-500">Not tied to a single identity (for example an IP-level detection).</p>}
        </Card>
        <Card title="Triage" className="lg:col-span-1">
          <Field label="Analyst notes">
            <textarea className={inputCls} rows={4} value={notes ?? data.notes ?? ""} onChange={(e) => setNotes(e.target.value)} />
          </Field>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button busy={busy} onClick={() => void update("ACKNOWLEDGED")}>Acknowledge</Button>
            <Button busy={busy} variant="primary" onClick={() => void update("RESOLVED")}>Resolve</Button>
            <Button busy={busy} onClick={() => void update("FALSE_POSITIVE")}>False positive</Button>
            <Button busy={busy} variant="ghost" onClick={() => void update(undefined)}>Save notes</Button>
          </div>
        </Card>
      </div>
      <Card title="Evidence"><JsonView value={data.evidence} /></Card>
      {data.trigger_event && (
        <Card title="Triggering event">
          <Table head={["Type", "Time", "IP", "Source"]}>
            <tr><td className={td}>{data.trigger_event.type}</td><td className={td}>{fmtTime(data.trigger_event.ts)}</td><td className={td}>{data.trigger_event.ip}</td><td className={td}>{data.trigger_event.source}</td></tr>
          </Table>
          <div className="mt-3"><JsonView value={data.trigger_event.details} /></div>
        </Card>
      )}
    </div>
  );
}
