import { useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Badge, Button, Card, ErrorBox, PageHeader, Spinner, Table, td } from "../components/ui";
import { useAsync } from "../lib/useAsync";

interface Rule { id: string; rule_key: string; name: string; severity: string; weight: number; attack_technique: string; enabled: boolean; params: Record<string, number>; periodic: boolean; event_types: string[] }
interface Playbook { id: string; rule_key: string; actions: string[]; mode: string; enabled: boolean }
interface PbResp { playbooks: Playbook[]; available_actions: Record<string, string>; risk_tiers: { min_risk: number; tier: string; actions: string[] }[] }

export default function Rules() {
  const { hasRole } = useAuth();
  const admin = hasRole("admin");
  const rules = useAsync(() => api<Rule[]>("/rules"));
  const pbs = useAsync(() => api<PbResp>("/playbooks"));
  const [err, setErr] = useState<unknown>(null);
  const save = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try {
      await fn();
      await Promise.all([rules.reload(), pbs.reload()]);
    } catch (e) {
      setErr(e);
    }
  };
  const pbFor = (k: string) => pbs.data?.playbooks.find((p) => p.rule_key === k);
  return (
    <div className="space-y-5">
      <PageHeader title="Rules & Playbooks" subtitle="Pluggable detections mapped to MITRE ATT&CK, with per-tenant response playbooks" />
      <ErrorBox error={err || rules.error || pbs.error} />
      {pbs.data && (
        <Card title="Risk tiers (risk = Σ weight × confidence, clamped 0–100)">
          <div className="grid gap-2 sm:grid-cols-4">
            {[...pbs.data.risk_tiers].reverse().map((t) => (
              <div key={t.tier} className="rounded-lg bg-slate-50 p-3 text-sm dark:bg-slate-800">
                <div className="font-medium">≥ {t.min_risk}: {t.tier}</div>
                <div className="text-xs text-slate-500">{t.actions.join(", ") || "log only"}</div>
              </div>
            ))}
          </div>
        </Card>
      )}
      <Card title="Detection rules">
        {rules.loading && !rules.data ? <Spinner /> : (
          <Table head={["Rule", "Severity", "Weight", "ATT&CK", "Parameters", "Playbook", "Enabled"]}>
            {rules.data?.map((r) => {
              const pb = pbFor(r.rule_key);
              return (
                <tr key={r.id}>
                  <td className={td}><div className="font-medium"><span className="font-mono text-xs text-slate-500">{r.rule_key}</span> {r.name}</div><div className="text-xs text-slate-500">{r.periodic ? "periodic" : r.event_types.join(", ")}</div></td>
                  <td className={td}><Badge>{r.severity}</Badge></td>
                  <td className={`${td} tabular-nums`}>{r.weight}</td>
                  <td className={`${td} text-xs`}>{r.attack_technique}</td>
                  <td className={`${td} font-mono text-xs`}>{Object.entries(r.params).map(([k, v]) => <div key={k}>{k}={v}</div>)}</td>
                  <td className={`${td} text-xs`}>
                    {pb && (
                      <div className="space-y-1">
                        <div>{pb.actions.join(", ") || "tier defaults"}</div>
                        <div className="flex items-center gap-1">
                          <Badge tone={pb.mode === "ACTIVE" ? "ACTIVE_MODE" : "DRY_RUN"}>{pb.mode}</Badge>
                          {admin && <button className="text-indigo-600 underline dark:text-indigo-400" onClick={() => void save(() => api(`/playbooks/${pb.id}`, { method: "PUT", json: { actions: pb.actions, mode: pb.mode === "ACTIVE" ? "DRY_RUN" : "ACTIVE", enabled: pb.enabled } }))}>switch</button>}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className={td}>
                    {admin ? (
                      <Button variant={r.enabled ? "primary" : "secondary"} onClick={() => void save(() => api(`/rules/${r.id}`, { method: "PUT", json: { enabled: !r.enabled } }))}>{r.enabled ? "On" : "Off"}</Button>
                    ) : <Badge>{r.enabled ? "on" : "off"}</Badge>}
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
      {pbs.data && (
        <Card title="Available response actions">
          <ul className="grid gap-2 text-sm sm:grid-cols-2">
            {Object.entries(pbs.data.available_actions).map(([k, v]) => <li key={k}><span className="font-mono text-xs">{k}</span> — <span className="text-slate-500">{v}</span></li>)}
          </ul>
        </Card>
      )}
    </div>
  );
}
