import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Spinner } from "../components/ui";

/** Landing page after /api/auth/callback set the HttpOnly refresh cookie. */
export default function AuthComplete() {
  const { status, me, reload } = useAuth();
  const nav = useNavigate();
  useEffect(() => {
    if (status === "signed-in" && me) nav(me.roles.includes("admin") || me.roles.includes("analyst") ? "/" : "/sessions", { replace: true });
    else if (status === "signed-out") void reload().then(() => undefined);
  }, [status, me, nav, reload]);
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (status !== "signed-in") nav("/login?error=login_failed", { replace: true });
    }, 6000);
    return () => window.clearTimeout(t);
  }, [status, nav]);
  return <div className="flex h-screen items-center justify-center"><Spinner label="Completing sign-in…" /></div>;
}
