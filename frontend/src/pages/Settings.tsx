import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Button, Card, ErrorBox, Field, inputCls, PageHeader, Spinner, Table, td } from "../components/ui";
import { fmtTime } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface TenantSettings {
  access_token_ttl_seconds: number; idle_timeout_minutes: number; absolute_timeout_hours: number; max_concurrent_sessions: number;
  concurrent_policy: string; drift_policy: string; leaver_sla_minutes: number; require_mfa: boolean;
}
interface Tenant { id: string; name: string; realm: string; status: string; settings: TenantSettings; created_at: string }
interface Key { id: string; name: string; prefix: string; created_at: string; revoked_at: string | null }

const NUMS: [keyof TenantSettings, string, string][] = [
  ["access_token_ttl_seconds", "Access token lifetime (s)", "60–900"],
  ["idle_timeout_minutes", "Idle timeout (min)", "5–240"],
  ["absolute_timeout_hours", "Absolute session limit (h)", "1–24"],
  ["max_concurrent_sessions", "Max concurrent sessions per user", "1–20"],
  ["leaver_sla_minutes", "Leaver SLA (min) for D12", "5–10080"],
];

export default function Settings() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const t = useAsync(() => api<Tenant>("/tenants/me"));
  const [s, setS] = useState<TenantSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (t.data) setS(t.data.settings);
  }, [t.data]);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      await api("/tenants/me/settings", { method: "PUT", json: s });
      setSaved(true);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  if (t.loading && !t.data) return <Spinner />;
  return (
    <div className="space-y-5">
      <PageHeader title="Tenant Settings" subtitle={t.data ? `${t.data.name} · realm ${t.data.realm} · created ${fmtTime(t.data.created_at)}` : ""} />
      <ErrorBox error={t.error} onRetry={t.reload} />
      {s && (
        <Card title="Session policy">
          <form onSubmit={save} className="grid gap-4 md:grid-cols-3">
            {NUMS.map(([k, label, hint]) => (
              <Field key={k} label={label} hint={hint}>
                <input type="number" className={inputCls} disabled={!admin} value={s[k] as number} onChange={(e) => setS({ ...s, [k]: Number(e.target.value) })} />
              </Field>
            ))}
            <Field label="When the session cap is reached">
              <select className={inputCls} disabled={!admin} value={s.concurrent_policy} onChange={(e) => setS({ ...s, concurrent_policy: e.target.value })}>
                <option value="evict_oldest">Evict the oldest session</option><option value="block">Block the new login</option>
              </select>
            </Field>
            <Field label="Device / network drift">
              <select className={inputCls} disabled={!admin} value={s.drift_policy} onChange={(e) => setS({ ...s, drift_policy: e.target.value })}>
                <option value="detect">Detect (D02 → risk-based response)</option><option value="revoke">Always revoke immediately</option>
              </select>
            </Field>
            <label className="flex items-center gap-2 self-end text-sm"><input type="checkbox" disabled={!admin} checked={s.require_mfa} onChange={(e) => setS({ ...s, require_mfa: e.target.checked })} /> Require MFA for new joiners</label>
            {admin && <div className="md:col-span-3"><Button type="submit" variant="primary" busy={busy}>Save</Button> {saved && <span className="ml-2 text-sm text-emerald-600">Saved (audited).</span>}</div>}
          </form>
          <div className="mt-3"><ErrorBox error={err} /></div>
        </Card>
      )}
      {admin && <HrWebhook />}
      <ApiKeys />
    </div>
  );
}

function HrWebhook() {
  const [info, setInfo] = useState<Record<string, string> | null>(null);
  const [err, setErr] = useState<unknown>(null);
  return (
    <Card title="HR system webhook (HMAC-signed)" actions={!info && <Button onClick={async () => { try { setInfo(await api("/tenants/me/hr-webhook")); } catch (e) { setErr(e); } }}>Reveal secret</Button>}>
      <ErrorBox error={err} />
      {info ? (
        <dl className="grid gap-1 text-sm">
          {Object.entries(info).map(([k, v]) => <div key={k} className="grid grid-cols-4 gap-2"><dt className="text-slate-500">{k}</dt><dd className="col-span-3 break-all font-mono text-xs">{v}</dd></div>)}
        </dl>
      ) : <p className="text-sm text-slate-500">POST /api/lifecycle/webhook/hr with events hire / transfer / terminate. Revealing the secret is audited.</p>}
    </Card>
  );
}

function ApiKeys() {
  const keys = useAsync(() => api<Key[]>("/api-keys"));
  const [name, setName] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const r = await api<{ key: string }>("/api-keys", { method: "POST", json: { name } });
      setCreated(r.key);
      setName("");
      void keys.reload();
    } catch (e2) {
      setErr(e2);
    }
  };
  return (
    <Card title="My API keys (personal access tokens)">
      <form onSubmit={create} className="flex gap-2">
        <input className={inputCls} required minLength={2} placeholder="Key name" value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit">Create</Button>
      </form>
      {created && <p className="mt-2 break-all rounded-lg bg-amber-50 p-2 font-mono text-xs dark:bg-amber-950">{created}<br /><span className="font-sans text-amber-700">Shown once. Revoked automatically by the Leaver workflow.</span></p>}
      <ErrorBox error={err || keys.error} />
      <div className="mt-3">
        <Table head={["Name", "Prefix", "Created", "Status", ""]} empty={keys.data?.length === 0}>
          {keys.data?.map((k) => (
            <tr key={k.id}>
              <td className={td}>{k.name}</td><td className={`${td} font-mono text-xs`}>{k.prefix}…</td><td className={`${td} text-xs`}>{fmtTime(k.created_at)}</td>
              <td className={`${td} text-xs`}>{k.revoked_at ? `revoked ${fmtTime(k.revoked_at)}` : "active"}</td>
              <td className={td}>{!k.revoked_at && <Button variant="danger" onClick={async () => { await api(`/api-keys/${k.id}`, { method: "DELETE" }); void keys.reload(); }}>Revoke</Button>}</td>
            </tr>
          ))}
        </Table>
      </div>
    </Card>
  );
}
