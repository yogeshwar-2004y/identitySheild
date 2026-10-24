import { Fragment, useMemo, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Badge, Button, Card, ErrorBox, Field, inputCls, JsonView, PageHeader, Spinner, Table, td } from "../components/ui";
import { ago, fmtTime } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface Role { id: string; name: string; sensitivity: string }
interface RolesResp { roles: Role[]; templates: { department: string; roles: string[] }[] }
interface UserRow { id: string; username: string; full_name: string; email: string; department: string; state: string; roles: string[] | null; last_login_at: string | null }
interface Req {
  id: string; kind: string; status: string; requested_by: string; user: { username: string; state: string; department: string } | null;
  payload: Record<string, unknown>; steps: Record<string, { at: string } & Record<string, unknown>>; access_diff: { added?: string[]; removed?: string[]; sensitive?: string[] } | null;
  error: string | null; attempts: number; created_at: string; completed_at: string | null; effective_at: string | null;
}

const TABS = ["Requests", "Joiner", "Mover", "Leaver"] as const;

export default function Lifecycle() {
  const { hasRole, me } = useAuth();
  const canSubmit = hasRole("admin", "hr");
  const [tab, setTab] = useState<(typeof TABS)[number]>("Requests");
  const roles = useAsync(() => api<RolesResp>("/roles"));
  const users = useAsync(() => api<UserRow[]>("/users"));
  const reqs = useAsync(() => api<Req[]>("/lifecycle/requests"));
  const refreshAll = () => { void users.reload(); void reqs.reload(); };
  return (
    <div className="space-y-5">
      <PageHeader title="Identity Lifecycle" subtitle="Joiner · Mover · Leaver with approvals, access diff and verification" />
      <div className="flex gap-1 rounded-lg bg-slate-100 p-1 text-sm dark:bg-slate-800">
        {TABS.filter((t) => t === "Requests" || canSubmit).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`rounded-md px-3 py-1.5 ${tab === t ? "bg-white font-medium shadow dark:bg-slate-900" : "text-slate-600 dark:text-slate-300"}`}>{t}</button>
        ))}
      </div>
      {tab === "Requests" && <Requests reqs={reqs} canApprove={hasRole("admin")} canRetry={canSubmit} me={me?.email ?? ""} onChange={refreshAll} />}
      {tab === "Joiner" && roles.data && <Joiner roles={roles.data} labMode={!!me?.lab_mode} onDone={() => { refreshAll(); setTab("Requests"); }} />}
      {tab === "Mover" && roles.data && users.data && <Mover roles={roles.data} users={users.data} onDone={() => { refreshAll(); setTab("Requests"); }} />}
      {tab === "Leaver" && users.data && <Leaver users={users.data} selfId={me?.id ?? ""} onDone={() => { refreshAll(); setTab("Requests"); }} />}
      {tab !== "Requests" && (roles.loading || users.loading) && <Spinner />}
      <Card title="Directory">
        <ErrorBox error={users.error} onRetry={users.reload} />
        <Table head={["User", "Department", "Roles", "State", "Last login"]}>
          {users.data?.map((u) => (
            <tr key={u.id}>
              <td className={td}><div className="font-medium">{u.full_name}</div><div className="text-xs text-slate-500">{u.username} · {u.email}</div></td>
              <td className={td}>{u.department}</td>
              <td className={td}><div className="flex flex-wrap gap-1">{(u.roles ?? []).map((r) => <Badge key={r} tone="role">{r}</Badge>)}</div></td>
              <td className={td}><Badge>{u.state}</Badge></td>
              <td className={`${td} text-xs text-slate-500`}>{ago(u.last_login_at)}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}

function Requests({ reqs, canApprove, canRetry, me, onChange }: { reqs: ReturnType<typeof useAsync<Req[]>>; canApprove: boolean; canRetry: boolean; me: string; onChange: () => void }) {
  const [open, setOpen] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const act = async (id: string, path: string, json?: unknown) => {
    setBusy(id + path);
    setErr(null);
    try {
      await api(`/lifecycle/${id}/${path}`, { method: "POST", json });
      onChange();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <Card title="Requests" actions={<Button onClick={() => void reqs.reload()}>Refresh</Button>}>
      <ErrorBox error={reqs.error || err} />
      {reqs.loading && !reqs.data ? <Spinner /> : (
        <Table head={["Kind", "User", "Status", "Access diff", "Requested", ""]} empty={reqs.data?.length === 0}>
          {reqs.data?.map((r) => (
            <Fragment key={r.id}>
              <tr className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => setOpen(open === r.id ? null : r.id)}>
                <td className={`${td} font-mono text-xs`}>{r.kind}</td>
                <td className={td}>{r.user?.username ?? "—"} {r.user && <Badge>{r.user.state}</Badge>}</td>
                <td className={td}><Badge>{r.status}</Badge>{r.error && <div className="mt-1 max-w-xs text-xs text-red-600">{r.error}</div>}</td>
                <td className={`${td} text-xs`}>
                  {r.access_diff?.added?.map((x) => <span key={x} className="mr-1 text-emerald-600">+{x}</span>)}
                  {r.access_diff?.removed?.map((x) => <span key={x} className="mr-1 text-red-600">−{x}</span>)}
                  {!!r.access_diff?.sensitive?.length && <div className="text-violet-600">needs approval: {r.access_diff.sensitive.join(", ")}</div>}
                </td>
                <td className={`${td} text-xs text-slate-500`}>{r.requested_by}<div>{ago(r.created_at)}</div></td>
                <td className={td} onClick={(e) => e.stopPropagation()}>
                  <div className="flex gap-1">
                    {r.status === "PENDING_APPROVAL" && canApprove && (
                      <>
                        <Button variant="primary" busy={busy === r.id + "approve"} disabled={r.requested_by === `user:${me}`} title={r.requested_by === `user:${me}` ? "Separation of duties: you requested this" : ""} onClick={() => void act(r.id, "approve", { approve: true, reason: "approved in UI" })}>Approve</Button>
                        <Button onClick={() => void act(r.id, "approve", { approve: false, reason: "rejected in UI" })}>Reject</Button>
                      </>
                    )}
                    {r.status === "FAILED" && canRetry && <Button busy={busy === r.id + "retry"} onClick={() => void act(r.id, "retry")}>Retry</Button>}
                  </div>
                </td>
              </tr>
              {open === r.id && (
                <tr>
                  <td colSpan={6} className="bg-slate-50 px-3 py-3 dark:bg-slate-800/40">
                    <div className="grid gap-3 md:grid-cols-2">
                      <div>
                        <div className="mb-1 text-xs font-semibold uppercase text-slate-500">Workflow steps</div>
                        <ol className="space-y-1 text-sm">
                          {Object.entries(r.steps ?? {}).map(([k, v]) => (
                            <li key={k} className="flex items-center gap-2"><span className="text-emerald-600">✓</span><span className="font-mono text-xs">{k}</span><span className="text-xs text-slate-500">{fmtTime(v.at)}</span></li>
                          ))}
                        </ol>
                        {r.effective_at && <div className="mt-2 text-xs">Effective at {fmtTime(r.effective_at)}</div>}
                      </div>
                      <JsonView value={{ payload: r.payload, verification: r.steps?.verify }} />
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </Table>
      )}
    </Card>
  );
}

function Joiner({ roles, labMode, onDone }: { roles: RolesResp; labMode: boolean; onDone: () => void }) {
  const [f, setF] = useState({ full_name: "", email: "", department: roles.templates[0]?.department ?? "Engineering", extra_roles: [] as string[], require_mfa: true, send_invite: true, lab_demo_password: false });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [res, setRes] = useState<Req | null>(null);
  const tpl = roles.templates.find((t) => t.department === f.department)?.roles ?? [];
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await api<Req>("/lifecycle/joiner", { method: "POST", json: f, headers: { "Idempotency-Key": `joiner:${f.email}` } });
      setRes(r);
      onDone();
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Joiner: provision a new identity">
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <Field label="Full name"><input required className={inputCls} value={f.full_name} onChange={(e) => setF({ ...f, full_name: e.target.value })} placeholder="Asha Kumar" /></Field>
        <Field label="Work email"><input required type="email" className={inputCls} value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} placeholder="asha@acme.example" /></Field>
        <Field label="Department (role template)" hint={`Template grants: ${tpl.join(", ")}`}>
          <select className={inputCls} value={f.department} onChange={(e) => setF({ ...f, department: e.target.value })}>
            {roles.templates.map((t) => <option key={t.department}>{t.department}</option>)}
          </select>
        </Field>
        <Field label="Extra roles" hint="HIGH sensitivity roles require admin approval">
          <select multiple className={`${inputCls} h-24`} value={f.extra_roles} onChange={(e) => setF({ ...f, extra_roles: Array.from(e.target.selectedOptions).map((o) => o.value) })}>
            {roles.roles.filter((r) => !tpl.includes(r.name)).map((r) => <option key={r.id} value={r.name}>{r.name}{r.sensitivity === "HIGH" ? " (HIGH)" : ""}</option>)}
          </select>
        </Field>
        <div className="space-y-2 text-sm md:col-span-2">
          <label className="flex items-center gap-2"><input type="checkbox" checked={f.require_mfa} onChange={(e) => setF({ ...f, require_mfa: e.target.checked })} /> Require TOTP enrolment (Keycloak required action CONFIGURE_TOTP)</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={f.send_invite} disabled={f.lab_demo_password} onChange={(e) => setF({ ...f, send_invite: e.target.checked })} /> Send invite email (verify email + set password) — view at http://localhost:8025</label>
          {labMode && <label className="flex items-center gap-2 text-amber-700 dark:text-amber-400"><input type="checkbox" checked={f.lab_demo_password} onChange={(e) => setF({ ...f, lab_demo_password: e.target.checked })} /> LAB: set the demo password instead of an invite (lets the simulator log in)</label>}
        </div>
        <div className="md:col-span-2"><Button type="submit" variant="primary" busy={busy}>Submit joiner</Button></div>
      </form>
      <div className="mt-3"><ErrorBox error={err} />{res && <p className="text-sm text-emerald-600">Created request {res.id.slice(0, 8)}: {res.status}. The account is PENDING until first login.</p>}</div>
    </Card>
  );
}

function Mover({ roles, users, onDone }: { roles: RolesResp; users: UserRow[]; onDone: () => void }) {
  const movable = users.filter((u) => u.state === "ACTIVE" || u.state === "PENDING");
  const [userId, setUserId] = useState(movable[0]?.id ?? "");
  const [dept, setDept] = useState("");
  const [add, setAdd] = useState<string[]>([]);
  const [remove, setRemove] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const user = movable.find((u) => u.id === userId);
  const preview = useMemo(() => {
    if (!user) return null;
    const cur = new Set(user.roles ?? []);
    const next = new Set(cur);
    if (dept && dept !== user.department) {
      (roles.templates.find((t) => t.department === user.department)?.roles ?? []).forEach((r) => next.delete(r));
      (roles.templates.find((t) => t.department === dept)?.roles ?? []).forEach((r) => next.add(r));
    }
    add.forEach((r) => next.add(r));
    remove.forEach((r) => next.delete(r));
    next.add("user");
    const sens = new Set(roles.roles.filter((r) => r.sensitivity === "HIGH").map((r) => r.name));
    const added = [...next].filter((r) => !cur.has(r));
    return { added, removed: [...cur].filter((r) => !next.has(r)), sensitive: added.filter((r) => sens.has(r)) };
  }, [user, dept, add, remove, roles]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api("/lifecycle/mover", { method: "POST", json: { user_id: userId, new_department: dept || null, add_roles: add, remove_roles: remove, reason: "UI mover" } });
      onDone();
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Mover: change department / roles">
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <Field label="User">
          <select className={inputCls} value={userId} onChange={(e) => setUserId(e.target.value)}>
            {movable.map((u) => <option key={u.id} value={u.id}>{u.username} ({u.department})</option>)}
          </select>
        </Field>
        <Field label="New department">
          <select className={inputCls} value={dept} onChange={(e) => setDept(e.target.value)}>
            <option value="">(unchanged)</option>
            {roles.templates.map((t) => <option key={t.department}>{t.department}</option>)}
          </select>
        </Field>
        <Field label="Add roles"><select multiple className={`${inputCls} h-24`} value={add} onChange={(e) => setAdd(Array.from(e.target.selectedOptions).map((o) => o.value))}>{roles.roles.map((r) => <option key={r.id} value={r.name}>{r.name}{r.sensitivity === "HIGH" ? " (HIGH)" : ""}</option>)}</select></Field>
        <Field label="Remove roles"><select multiple className={`${inputCls} h-24`} value={remove} onChange={(e) => setRemove(Array.from(e.target.selectedOptions).map((o) => o.value))}>{(user?.roles ?? []).map((r) => <option key={r}>{r}</option>)}</select></Field>
        {preview && (
          <div className="rounded-lg bg-slate-50 p-3 text-sm dark:bg-slate-800 md:col-span-2">
            <div className="font-medium">Access diff preview</div>
            <div className="text-emerald-600">+ {preview.added.join(", ") || "nothing"}</div>
            <div className="text-red-600">− {preview.removed.join(", ") || "nothing"}</div>
            {preview.sensitive.length > 0 && <div className="mt-1 text-violet-600">Sensitive additions ({preview.sensitive.join(", ")}) will wait for admin approval.</div>}
            <div className="mt-1 text-xs text-slate-500">Active sessions are re-issued with new claims (new session id) after the change.</div>
          </div>
        )}
        <div className="md:col-span-2"><Button type="submit" variant="primary" busy={busy} disabled={!userId}>Submit mover</Button></div>
      </form>
      <div className="mt-3"><ErrorBox error={err} /></div>
    </Card>
  );
}

function Leaver({ users, selfId, onDone }: { users: UserRow[]; selfId: string; onDone: () => void }) {
  const candidates = users.filter((u) => u.state !== "DEPROVISIONED" && u.id !== selfId);
  const [userId, setUserId] = useState(candidates[0]?.id ?? "");
  const [reason, setReason] = useState("");
  const [when, setWhen] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [res, setRes] = useState<Req | null>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!window.confirm("Deprovision this identity? Sessions, tokens, roles and API keys will be revoked.")) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api<Req>("/lifecycle/leaver", { method: "POST", json: { user_id: userId, reason, effective_at: when ? new Date(when).toISOString() : null } });
      setRes(r);
      onDone();
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Leaver: deprovision an identity">
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-3">
        <Field label="User"><select className={inputCls} value={userId} onChange={(e) => setUserId(e.target.value)}>{candidates.map((u) => <option key={u.id} value={u.id}>{u.username} ({u.department})</option>)}</select></Field>
        <Field label="Reason"><input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Resigned" /></Field>
        <Field label="Effective at (optional)" hint="Leave empty to run now; otherwise the worker runs it at that time"><input type="datetime-local" className={inputCls} value={when} onChange={(e) => setWhen(e.target.value)} /></Field>
        <div className="text-xs text-slate-500 md:col-span-3">
          Steps: disable in Keycloak → revoke sessions & refresh tokens → add jtis to revocation list → remove roles → revoke API keys → mark DEPROVISIONED → verify.
        </div>
        <div className="md:col-span-3"><Button type="submit" variant="danger" busy={busy} disabled={!userId}>Run leaver</Button></div>
      </form>
      <div className="mt-3"><ErrorBox error={err} />{res && <p className="text-sm">Leaver {res.id.slice(0, 8)}: <Badge>{res.status}</Badge> {res.error}</p>}</div>
    </Card>
  );
}
