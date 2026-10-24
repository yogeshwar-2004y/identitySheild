import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, ErrorBox, inputCls, PageHeader, Spinner } from "../components/ui";
import { fmtTime } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface UserLite { id: string; username: string; full_name: string; state: string; department: string; roles: string[] | null }
interface Item { ts: string; category: string; type: string; outcome: string; summary: string; ref: string; data: Record<string, unknown> }

const DOT: Record<string, string> = { alert: "bg-red-500", lifecycle: "bg-violet-500", session: "bg-sky-500", event: "bg-slate-400" };

export default function Timeline() {
  const [params, setParams] = useSearchParams();
  const userId = params.get("user") ?? "";
  const [filter, setFilter] = useState("");
  const [cats, setCats] = useState<string[]>(["alert", "lifecycle", "session", "event"]);
  const users = useAsync(() => api<UserLite[]>("/users"));
  const tl = useAsync(() => (userId ? api<{ user: UserLite; items: Item[] }>(`/users/${userId}/timeline`) : Promise.resolve(null)), [userId]);
  const list = (users.data ?? []).filter((u) => !filter || `${u.username} ${u.full_name}`.toLowerCase().includes(filter.toLowerCase()));
  const items = (tl.data?.items ?? []).filter((i) => cats.includes(i.category));
  return (
    <div className="space-y-5">
      <PageHeader title="User Timeline" subtitle="Lifecycle, session, event and alert history for one identity" />
      <div className="grid gap-5 lg:grid-cols-4">
        <Card title="Identities" className="lg:col-span-1">
          <input className={inputCls} placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <ErrorBox error={users.error} />
          <ul className="mt-2 max-h-[60vh] space-y-0.5 overflow-auto">
            {list.map((u) => (
              <li key={u.id}>
                <button
                  onClick={() => setParams({ user: u.id })}
                  className={`flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-left text-sm ${u.id === userId ? "bg-indigo-50 dark:bg-indigo-950" : "hover:bg-slate-50 dark:hover:bg-slate-800"}`}
                >
                  <span>{u.username}</span><Badge>{u.state}</Badge>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card
          className="lg:col-span-3"
          title={tl.data ? `${tl.data.user.full_name} (${tl.data.user.username}) · ${tl.data.user.department}` : "Timeline"}
          actions={
            <div className="flex flex-wrap gap-2 text-xs">
              {Object.keys(DOT).map((c) => (
                <label key={c} className="flex items-center gap-1">
                  <input type="checkbox" checked={cats.includes(c)} onChange={(e) => setCats(e.target.checked ? [...cats, c] : cats.filter((x) => x !== c))} /> {c}
                </label>
              ))}
            </div>
          }
        >
          {!userId ? <Empty>Pick an identity.</Empty> : tl.loading && !tl.data ? <Spinner /> : (
            <>
              <ErrorBox error={tl.error} />
              {tl.data && (
                <div className="mb-3 flex flex-wrap gap-2 text-sm">
                  <Badge>{tl.data.user.state}</Badge>
                  {(tl.data.user.roles ?? []).map((r) => <Badge key={r} tone="role">{r}</Badge>)}
                </div>
              )}
              <ol className="relative ml-2 border-l border-slate-200 dark:border-slate-700">
                {items.map((i, idx) => (
                  <li key={`${i.ref}-${idx}`} className="mb-3 ml-4">
                    <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${DOT[i.category] ?? "bg-slate-400"}`} />
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <span>{fmtTime(i.ts)}</span><span className="font-mono">{i.category}/{i.type}</span><Badge>{i.outcome}</Badge>
                    </div>
                    <div className="text-sm">
                      {i.category === "alert" ? <Link className="hover:underline" to={`/alerts/${i.ref}`}>{i.summary}</Link> : i.summary}
                    </div>
                  </li>
                ))}
                {items.length === 0 && <Empty>No history.</Empty>}
              </ol>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
