import { useState } from "react";
import { Link } from "react-router-dom";
import { FlaskConical } from "lucide-react";
import { api } from "../api/client";
import { Button, Card, ErrorBox, Field, inputCls, PageHeader, Spinner } from "../components/ui";
import { useAsync } from "../lib/useAsync";

interface Scenario { name: string; expected: string; description: string }
interface RunResult { scenario: string; expected: string; ok: boolean; output: string[] }

export default function Lab() {
  const list = useAsync(() => api<{ scenarios: Scenario[] }>("/lab/scenarios"));
  const [victim, setVictim] = useState("asha");
  const [busy, setBusy] = useState<string | null>(null);
  const [results, setResults] = useState<RunResult[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const run = async (name: string) => {
    setBusy(name);
    setErr(null);
    try {
      const r = await api<RunResult>(`/lab/scenarios/${name}`, { method: "POST", json: { victim } });
      setResults((x) => [r, ...x]);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="space-y-5">
      <PageHeader title="Attack Lab" subtitle="LAB MODE ONLY · runs the simulator scenarios against this local stack" />
      <div className="rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
        The simulator only targets localhost / the Docker network and labels its traffic with documentation-range IPs (203.0.113.x = IN, 198.51.100.x = US, …).
      </div>
      <Card title="Scenarios" actions={<Field label=""><input aria-label="Victim username" className={inputCls} value={victim} onChange={(e) => setVictim(e.target.value)} /></Field>}>
        <ErrorBox error={list.error || err} />
        {list.loading && !list.data ? <Spinner /> : (
          <div className="grid gap-3 md:grid-cols-2">
            {list.data?.scenarios.map((s) => (
              <div key={s.name} className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <div className="font-mono text-sm font-medium">{s.name}</div>
                  <span className="text-xs text-slate-500">expects {s.expected}</span>
                </div>
                <p className="mt-1 text-xs text-slate-500">{s.description}</p>
                <Button className="mt-2" variant="primary" busy={busy === s.name} disabled={!!busy} onClick={() => void run(s.name)}><FlaskConical className="h-4 w-4" /> Run</Button>
              </div>
            ))}
          </div>
        )}
      </Card>
      {results.map((r, i) => (
        <Card key={i} title={`${r.scenario} → ${r.ok ? "detected ✓" : "not confirmed"}`} actions={<Link className="text-sm text-indigo-600 hover:underline dark:text-indigo-400" to="/alerts">View alerts</Link>}>
          <pre className="overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100">{r.output.join("\n")}</pre>
        </Card>
      ))}
    </div>
  );
}
