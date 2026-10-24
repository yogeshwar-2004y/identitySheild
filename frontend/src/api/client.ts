/**
 * API client. The access token lives ONLY in this module's memory (never localStorage /
 * sessionStorage). The refresh token is an HttpOnly cookie the SPA cannot read; refresh and
 * logout calls send the double-submit CSRF token from the readable CSRF cookie.
 */
export interface SessionUser {
  id: string;
  email: string;
  username: string;
  full_name: string;
  department: string;
  state: string;
  roles: string[];
}

export interface TokenResponse {
  access_token: string;
  expires_at: string;
  session_id: string;
  session_expires_at: string;
  user: SessionUser;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public body?: unknown) {
    super(message);
  }
}

const BASE = "/api";
let accessToken: string | null = null;
let expiresAt = 0;
let refreshing: Promise<TokenResponse | null> | null = null;
let onSessionLost: (() => void) | null = null;
let onTokens: ((t: TokenResponse) => void) | null = null;

export function configureAuth(handlers: { onSessionLost: () => void; onTokens: (t: TokenResponse) => void }): void {
  onSessionLost = handlers.onSessionLost;
  onTokens = handlers.onTokens;
}

export function wipeTokens(): void {
  accessToken = null;
  expiresAt = 0;
}

export function hasToken(): boolean {
  return accessToken !== null;
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)(?:__Host-)?is_csrf=([^;]+)/);
  return m?.[1] ? decodeURIComponent(m[1]) : "";
}

async function parseError(res: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* not json */
  }
  const detail = (body as { detail?: unknown } | null)?.detail;
  let code = `http_${res.status}`;
  let message = res.statusText || "Request failed";
  if (typeof detail === "string") message = detail;
  else if (detail && typeof detail === "object") {
    const d = detail as { code?: string; message?: string; errors?: { msg: string; loc: unknown[] }[] };
    code = d.code ?? code;
    message = d.message ?? (d.errors ? d.errors.map((e) => `${(e.loc ?? []).slice(1).join(".")}: ${e.msg}`).join("; ") : message);
  }
  return new ApiError(res.status, code, message, body);
}

/** Single-flight refresh: concurrent 401s trigger one rotation, not many (which would look like reuse). */
export function refreshSession(): Promise<TokenResponse | null> {
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await fetch(`${BASE}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRF-Token": csrfToken(), "Content-Type": "application/json" },
          cache: "no-store",
        });
        if (!res.ok) {
          wipeTokens();
          return null;
        }
        const t = (await res.json()) as TokenResponse;
        accessToken = t.access_token;
        expiresAt = Date.parse(t.expires_at);
        onTokens?.(t);
        return t;
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

export function msUntilExpiry(): number {
  return expiresAt - Date.now();
}

const RETRYABLE = new Set(["token_expired", "claims_changed", "missing_token"]);

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}, retry = true): Promise<T> {
  if (!accessToken && retry) await refreshSession();
  const headers = new Headers(init.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers, body, credentials: "same-origin", cache: "no-store" });
  if (res.status === 401) {
    const err = await parseError(res);
    if (retry && RETRYABLE.has(err.code)) {
      const t = await refreshSession();
      if (t) return api<T>(path, init, false);
    }
    wipeTokens();
    onSessionLost?.();
    throw err;
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export async function logout(everywhere: boolean): Promise<string> {
  const headers: Record<string, string> = { "X-CSRF-Token": csrfToken() };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let url = "/login?logged_out=1";
  try {
    const res = await fetch(`${BASE}/auth/${everywhere ? "logout-all" : "logout"}`, {
      method: "POST",
      credentials: "same-origin",
      headers,
      cache: "no-store",
    });
    if (res.ok) url = ((await res.json()) as { logout_url: string }).logout_url || url;
  } finally {
    wipeTokens();
  }
  return url;
}

/** Server-sent events via fetch so the bearer token stays in a header (not the URL). */
export function streamAlerts(onAlert: (a: unknown) => void, onState: (live: boolean) => void): () => void {
  const ctrl = new AbortController();
  let stopped = false;
  const run = async (): Promise<void> => {
    while (!stopped) {
      try {
        if (!accessToken) await refreshSession();
        const res = await fetch(`${BASE}/alerts/stream`, {
          headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
          signal: ctrl.signal,
          cache: "no-store",
        });
        if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
        onState(true);
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const chunk = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const ev = /^event: (.*)$/m.exec(chunk)?.[1];
            const data = /^data: (.*)$/m.exec(chunk)?.[1];
            if (ev === "alert" && data) onAlert(JSON.parse(data));
          }
        }
      } catch {
        /* reconnect below */
      }
      onState(false);
      if (!stopped) await new Promise((r) => setTimeout(r, 4000));
    }
  };
  void run();
  return () => {
    stopped = true;
    ctrl.abort();
  };
}
