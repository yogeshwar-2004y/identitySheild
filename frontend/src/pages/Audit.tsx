import { Fragment, useState } from "react";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import { Button, Card, ErrorBox, inputCls, JsonView, PageHeader, Spinner, Table, td } from "../components/ui";
import { fmtTime } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface Entry { id: number; ts: string; actor: string; action: string; target: string; detail: unknown; prev_hash: string; hash: string }
interface Verify { valid: boolean; checked: number; broken_at_id: number | null; reason?: string; head?: string }

export default function Audit() {
  const [action, setAction] = useState("");
  const log = useAsync(() => api<Entry[]>(`/audit?limit=300${action ? `&action=${encodeURIComponent(action)}` : ""}`), [action]);
  const [verify, setVerify] = useState<Verify | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [open, setOpen] = useState<number | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    try {
      setVerify(await api<Verify>("/audit/verify"));
      void log.reload();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-5">
      <PageHeader title="Audit Log" subtitle="Append-only, hash-chained: hash = SHA-256(prev_hash ‖ canonical_json(entry))" actions={<Button variant="primary" busy={busy} onClick={() => void run()}>Verify hash chain</Button>} />
      <ErrorBox error={err} />
      {verify && (
        <div className={`flex items-center gap-3 rounded-xl border p-4 ${verify.valid ? "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/40" : "border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/40"}`}>
          {verify.valid ? <ShieldCheck className="h-8 w-8 text-emerald-600" /> : <ShieldAlert className="h-8 w-8 text-red-600" />}
          <div className="text-sm">
            {verify.valid ? <><b>Chain intact.</b> {verify.checked} entries verified. Head <span className="font-mono text-xs">{verify.head?.slice(0, 16)}…</span></>
              : <><b>Tampering detected</b> at entry #{verify.broken_at_id} ({verify.reason}). {verify.checked} entries verified before the break.</>}
          </div>
        </div>
      )}
      <Card title="Entries" actions={<input className={inputCls} placeholder="Filter action prefix (e.g. lifecycle)" value={action} onChange={(e) => setAction(e.target.value)} />}>
        <ErrorBox error={log.error} onRetry={log.reload} />
        {log.loading && !log.data ? <Spinner /> : (
          <Table head={["#", "Time", "Actor", "Action", "Target", "Hash"]}>
            {log.data?.map((e) => (
              <Fragment key={e.id}>
                <tr className={`cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50 ${verify && !verify.valid && verify.broken_at_id === e.id ? "bg-red-50 dark:bg-red-950/40" : ""}`} onClick={() => setOpen(open === e.id ? null : e.id)}>
                  <td className={`${td} tabular-nums text-xs`}>{e.id}</td>
                  <td className={`${td} whitespace-nowrap text-xs`}>{fmtTime(e.ts)}</td>
                  <td className={`${td} text-xs`}>{e.actor}</td>
                  <td className={`${td} font-mono text-xs`}>{e.action}</td>
                  <td className={`${td} max-w-[14rem] truncate text-xs`}>{e.target}</td>
                  <td className={`${td} font-mono text-xs text-slate-500`}>{e.hash.slice(0, 12)}…</td>
                </tr>
                {open === e.id && <tr><td colSpan={6} className="px-3 pb-3"><JsonView value={e} /></td></tr>}
              </Fragment>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
