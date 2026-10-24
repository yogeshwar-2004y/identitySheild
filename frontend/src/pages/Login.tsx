import { useState } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { Button, Field, inputCls } from "../components/ui";

const ERRORS: Record<string, string> = {
  unknown_tenant: "Unknown organisation.",
  invalid_state: "Login expired or was tampered with. Please try again.",
  login_failed: "Login could not be completed.",
  not_provisioned: "Your account is not provisioned in IdentityShield.",
  account_inactive: "This account is suspended or deprovisioned.",
  access_denied: "Login was cancelled.",
};

export default function Login() {
  const { status, me } = useAuth();
  const [params] = useSearchParams();
  const [tenant, setTenant] = useState(() => {
    try {
      return localStorage.getItem("is-tenant") ?? "acme";
    } catch {
      return "acme";
    }
  });
  const [busy, setBusy] = useState(false);
  if (status === "signed-in") return <Navigate to={me && (me.roles.includes("admin") || me.roles.includes("analyst")) ? "/" : "/sessions"} replace />;
  const error = params.get("error");

  const go = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      localStorage.setItem("is-tenant", tenant); // remembers the org name only
    } catch {
      /* ignore */
    }
    // Full-page navigation: the API starts the OIDC code flow with PKCE and redirects to Keycloak.
    window.location.assign(`/api/auth/login?tenant=${encodeURIComponent(tenant.trim().toLowerCase())}`);
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-100 to-indigo-100 p-4 dark:from-slate-950 dark:to-indigo-950">
      <form onSubmit={go} className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-8 shadow-xl dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-3">
          <ShieldCheck className="h-9 w-9 text-indigo-500" />
          <div>
            <h1 className="text-lg font-semibold">IdentityShield</h1>
            <p className="text-xs text-slate-500">Identity Threat Detection & Response</p>
          </div>
        </div>
        {params.get("logged_out") && (
          <p className="mb-4 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200">
            You have been signed out. Your session was revoked on the server.
          </p>
        )}
        {error && (
          <p role="alert" className="mb-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">
            {ERRORS[error] ?? `Login failed (${error}).`}
          </p>
        )}
        <Field label="Organisation" hint="Each organisation has its own Keycloak realm.">
          <input className={inputCls} value={tenant} onChange={(e) => setTenant(e.target.value)} required pattern="[a-zA-Z][a-zA-Z0-9-]{1,30}" />
        </Field>
        <Button type="submit" variant="primary" className="mt-5 w-full" busy={busy || status === "loading"}>
          Sign in with Keycloak (OIDC + PKCE)
        </Button>
        <p className="mt-4 text-xs text-slate-500">Access tokens are kept in memory only and expire after 5 minutes.</p>
      </form>
    </div>
  );
}
