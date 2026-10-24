import { useState } from "react";
import { Link } from "react-router-dom";
import { Play } from "lucide-react";
import { api } from "../api/client";
import { Badge, Button, Card, Empty, ErrorBox, Field, inputCls, PageHeader, Spinner, Table, td } from "../components/ui";
import { ago } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface Hunt {
  id: string; name: string; hypothesis: string; query: Record<string, unknown>; attack_technique: string; prebuilt: boolean;
  last_run: { id: string; run_at: string; result_count: number; verdict: string } | null;
}
type Row = Record<string, unknown>;

const EVENT_TYPES = ["LOGIN", "LOGIN_ERROR", "LOGOUT", "TOKEN_REFRESH", "APP_TOKEN_REFRESH", "REFRESH_TOKEN_REUSE", "TOKEN_REJECTED",
  "SESSION_CREATED", "SESSION_REVOKED", "SESSION_ANOMALY", "ROLE_GRANT", "ROLE_REVOKE", "USER_DISABLE", "MFA_DENIED", "RESOURCE_ACCESS"];

function ResultTable({ rows }: { rows: Row[] }) {
  if (!rows.length) return <Empty>No results.</Empty>;
  const cols = Object.keys(rows[0] ?? {}).filter((c) => c !== "details").slice(0, 9);
  return (
    <Table head={cols}>
      {rows.slice(0, 300).map((r, i) => (
        <tr key={i}>
          {cols.map((c) => {
            const v = r[c];
            const text = v === null || v === undefined ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
            const isUser = c === "user_id" && typeof v === "string";
            return (
              <td key={c} className={`${td} max-w-xs truncate text-xs`} title={text}>
                {isUser ? <Link className="text-indigo-600 hover:underline dark:text-indigo-400" to={`/timeline?user=${v}`}>{text.slice(0, 8)}</Link> : text}
              </td>
            );
          })}
        </tr>
      ))}
    </Table>
  );
}

export default function HuntPage() {
  const { data, error, loading, reload } = useAsync(() => api<{ hunts: Hunt[] }>("/hunts"));
  const [active, setActive] = useState<{ hunt: Hunt; run: { id: string; result_count: number; verdict: string }; results: Row[] } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);

  const run = async (h: Hunt) => {
    setBusy(h.id);
    setErr(null);
    try {
      const res = await api<{ run: { id: string; result_count: number; verdict: string }; results: Row[] }>(`/hunts/${h.id}/run`, { method: "POST", json: { params: {} } });
      setActive({ hunt: h, ...res });
      void reload();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  };
  const verdict = async (v: string) => {
    if (!active) return;
    await api(`/hunts/runs/${active.run.id}`, { method: "PATCH", json: { verdict: v, notes: "" } });
    setActive({ ...active, run: { ...active.run, verdict: v } });
    void reload();
  };

  return (
    <div className="space-y-5">
      <PageHeader title="Hunt Console" subtitle="Hypothesis-driven hunts over identity events, sessions and lifecycle data" />
      <ErrorBox error={error || err} onRetry={reload} />
      <div className="grid gap-5 xl:grid-cols-5">
        <Card title="Saved hunts" className="xl:col-span-2">
          {loading && !data ? <Spinner /> : (
            <ul className="space-y-2">
              {data?.hunts.map((h) => (
                <li key={h.id} className={`rounded-lg border p-3 ${active?.hunt.id === h.id ? "border-indigo-400" : "border-slate-200 dark:border-slate-800"}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-medium">{h.name}</div>
                      <div className="mt-0.5 text-xs text-slate-500">{h.hypothesis}</div>
                      <div className="mt-1 flex flex-wrap gap-1.5 text-xs text-slate-500">
                        <span className="font-mono">{h.attack_technique}</span>
                        {h.last_run && <span>· last run {ago(h.last_run.run_at)}: {h.last_run.result_count} hits</span>}
                        {h.last_run && <Badge>{h.last_run.verdict}</Badge>}
                      </div>
                    </div>
                    <Button aria-label={`Run ${h.name}`} busy={busy === h.id} onClick={() => void run(h)}><Play className="h-3.5 w-3.5" /> Run</Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <div className="space-y-5 xl:col-span-3">
          <Card
            title={active ? `${active.hunt.name}: ${active.run.result_count} results` : "Results"}
            actions={active && (
              <>
                <span className="text-xs text-slate-500">Verdict</span>
                {["CONFIRMED", "BENIGN", "INCONCLUSIVE"].map((v) => (
                  <Button key={v} variant={active.run.verdict === v ? "primary" : "secondary"} onClick={() => void verdict(v)}>{v.toLowerCase()}</Button>
                ))}
              </>
            )}
          >
            {active ? (
              <>
                <pre className="mb-3 overflow-auto rounded-lg bg-slate-100 p-2 text-xs dark:bg-slate-800">{JSON.stringify(active.hunt.query)}</pre>
                <ResultTable rows={active.results} />
              </>
            ) : <Empty>Run a saved hunt, or use the ad hoc search below.</Empty>}
          </Card>
          <AdHoc />
        </div>
      </div>
    </div>
  );
}

function AdHoc() {
  const [f, setF] = useState({ types: [] as string[], outcome: "", username: "", ip: "", country: "", since_hours: 24, group_by: "" });
  const [rows, setRows] = useState<Row[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const body: Record<string, unknown> = { since_hours: f.since_hours, limit: 500 };
      if (f.types.length) body.types = f.types;
      if (f.outcome) body.outcome = f.outcome;
      if (f.username) body.username = f.username;
      if (f.ip) body.ip = f.ip;
      if (f.country) body.country = f.country;
      if (f.group_by) body.group_by = f.group_by;
      setRows((await api<{ results: Row[] }>("/hunt/search", { method: "POST", json: body })).results);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Ad hoc search (filter builder)">
      <form onSubmit={submit} className="grid gap-3 md:grid-cols-3">
        <Field label="Event types">
          <select multiple className={`${inputCls} h-28`} value={f.types} onChange={(e) => setF({ ...f, types: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
            {EVENT_TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
        <div className="space-y-3">
          <Field label="Username starts with"><input className={inputCls} value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
          <Field label="Source IP"><input className={inputCls} value={f.ip} onChange={(e) => setF({ ...f, ip: e.target.value })} /></Field>
        </div>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <Field label="Outcome">
              <select className={inputCls} value={f.outcome} onChange={(e) => setF({ ...f, outcome: e.target.value })}>
                <option value="">Any</option><option>SUCCESS</option><option>FAILURE</option>
              </select>
            </Field>
            <Field label="Country"><input className={inputCls} maxLength={2} value={f.country} onChange={(e) => setF({ ...f, country: e.target.value.toUpperCase() })} /></Field>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Last N hours"><input type="number" min={1} max={8760} className={inputCls} value={f.since_hours} onChange={(e) => setF({ ...f, since_hours: Number(e.target.value) })} /></Field>
            <Field label="Group by">
              <select className={inputCls} value={f.group_by} onChange={(e) => setF({ ...f, group_by: e.target.value })}>
                <option value="">None</option><option value="user">user</option><option value="ip">ip</option><option value="type">type</option><option value="country">country</option>
              </select>
            </Field>
          </div>
        </div>
        <div className="md:col-span-3"><Button type="submit" variant="primary" busy={busy}>Search</Button></div>
      </form>
      <div className="mt-4">
        <ErrorBox error={err} />
        {rows && <ResultTable rows={rows} />}
      </div>
    </Card>
  );
}
