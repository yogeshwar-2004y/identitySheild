import { useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Badge, Button, Card, ErrorBox, PageHeader, Spinner, Table, td } from "../components/ui";
import { ago, fmtTime, geoLabel } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface SessionRow {
  id: string; user_id: string; username: string | null; ip: string; geo: { city?: string; country?: string } | null; asn: string | null;
  ua_hash: string; user_agent: string; source: string; created_at: string; expires_at: string; last_activity: string;
  revoked_at: string | null; revoke_reason: string | null; active: boolean; current: boolean; claims_version: number;
}

function SessionTable({ rows, showUser, onKill, busy }: { rows: SessionRow[]; showUser?: boolean; onKill: (s: SessionRow) => void; busy: string | null }) {
  return (
    <Table head={[...(showUser ? ["User"] : []), "Session", "Device binding", "Started", "Last activity", "Absolute expiry", "Status", ""]} empty={rows.length === 0}>
      {rows.map((s) => (
        <tr key={s.id}>
          {showUser && <td className={`${td} font-medium`}>{s.username}</td>}
          <td className={`${td} font-mono text-xs`}>{s.id.slice(0, 8)} {s.current && <Badge tone="ACTIVE">this device</Badge>}<div className="text-slate-500">{s.source} · v{s.claims_version}</div></td>
          <td className={`${td} text-xs`}>
            <div>{s.ip} · {geoLabel(s.geo)} · {s.asn}</div>
            <div className="max-w-xs truncate text-slate-500" title={s.user_agent}>{s.user_agent || "—"}</div>
            <div className="font-mono text-slate-400">ua#{s.ua_hash}</div>
          </td>
          <td className={`${td} text-xs`}>{fmtTime(s.created_at)}</td>
          <td className={`${td} text-xs`}>{ago(s.last_activity)}</td>
          <td className={`${td} text-xs`}>{fmtTime(s.expires_at)}</td>
          <td className={td}>{s.active ? <Badge tone="ACTIVE">active</Badge> : <><Badge tone="REJECTED">ended</Badge><div className="text-xs text-slate-500">{s.revoke_reason}</div></>}</td>
          <td className={td}>{s.active && <Button variant="danger" busy={busy === s.id} onClick={() => onKill(s)}>Kill</Button>}</td>
        </tr>
      ))}
    </Table>
  );
}

export default function Sessions() {
  const { hasRole, logout } = useAuth();
  const [showEnded, setShowEnded] = useState(false);
  const mine = useAsync(() => api<SessionRow[]>(`/sessions?include_revoked=${showEnded}`), [showEnded]);
  const isAdmin = hasRole("admin", "analyst");
  const all = useAsync(() => (isAdmin ? api<SessionRow[]>("/sessions/all") : Promise.resolve([])), [isAdmin]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const kill = async (s: SessionRow) => {
    if (s.current) {
      await logout(false);
      return;
    }
    setBusy(s.id);
    setErr(null);
    try {
      await api(`/sessions/${s.id}`, { method: "DELETE" });
      await Promise.all([mine.reload(), all.reload()]);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="space-y-5">
      <PageHeader
        title="Sessions"
        subtitle="5-minute access tokens · rotating refresh tokens · 15 min idle / 8 h absolute timeout · device & IP binding"
        actions={<Button variant="danger" onClick={() => void logout(true)}>Log out all my devices</Button>}
      />
      <ErrorBox error={err} />
      <Card title="My sessions" actions={<label className="flex items-center gap-1.5 text-xs"><input type="checkbox" checked={showEnded} onChange={(e) => setShowEnded(e.target.checked)} /> include ended</label>}>
        <ErrorBox error={mine.error} onRetry={mine.reload} />
        {mine.loading && !mine.data ? <Spinner /> : <SessionTable rows={mine.data ?? []} onKill={(s) => void kill(s)} busy={busy} />}
      </Card>
      {isAdmin && (
        <Card title="All active sessions in tenant" actions={<Button onClick={() => void all.reload()}>Refresh</Button>}>
          <ErrorBox error={all.error} onRetry={all.reload} />
          {all.loading && !all.data ? <Spinner /> : <SessionTable rows={all.data ?? []} showUser onKill={(s) => void kill(s)} busy={busy} />}
        </Card>
      )}
    </div>
  );
}
