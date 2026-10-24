import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, configureAuth, logout as apiLogout, msUntilExpiry, refreshSession, wipeTokens, type SessionUser } from "../api/client";

interface Me extends SessionUser {
  session_id: string | null;
  tenant: { id: string; name: string; realm: string };
  lab_mode: boolean;
}

interface AuthState {
  status: "loading" | "signed-in" | "signed-out";
  me: Me | null;
  hasRole: (...roles: string[]) => boolean;
  logout: (everywhere?: boolean) => Promise<void>;
  reload: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthState["status"]>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const timer = useRef<number | undefined>(undefined);

  const signOutLocally = useCallback(() => {
    // SPA state wipe: tokens, user, timers. Nothing sensitive survives in memory or storage.
    wipeTokens();
    window.clearTimeout(timer.current);
    setMe(null);
    setStatus("signed-out");
  }, []);

  const schedule = useCallback(() => {
    window.clearTimeout(timer.current);
    // Refresh 30 s before the 5-minute access token expires (keeps the session alive while active).
    const wait = Math.max(msUntilExpiry() - 30_000, 5_000);
    timer.current = window.setTimeout(async () => {
      const t = await refreshSession();
      if (t) schedule();
      else signOutLocally();
    }, wait);
  }, [signOutLocally]);

  const load = useCallback(async () => {
    const t = await refreshSession();
    if (!t) {
      signOutLocally();
      return;
    }
    try {
      const m = await api<Me>("/auth/me");
      setMe(m);
      setStatus("signed-in");
      schedule();
    } catch {
      signOutLocally();
    }
  }, [schedule, signOutLocally]);

  useEffect(() => {
    configureAuth({ onSessionLost: signOutLocally, onTokens: () => schedule() });
    void load();
    // Back/forward cache: never resurrect an authenticated page from memory after logout.
    const onShow = (e: PageTransitionEvent) => {
      if (e.persisted) window.location.reload();
    };
    window.addEventListener("pageshow", onShow);
    return () => {
      window.removeEventListener("pageshow", onShow);
      window.clearTimeout(timer.current);
    };
  }, [load, schedule, signOutLocally]);

  const logout = useCallback(
    async (everywhere = false) => {
      const url = await apiLogout(everywhere);
      signOutLocally();
      // Replace (not push) so Back does not return to the authenticated page; then Keycloak
      // end-session clears the IdP cookie and redirects to /login.
      window.location.replace(url);
    },
    [signOutLocally],
  );

  const value = useMemo<AuthState>(
    () => ({
      status,
      me,
      hasRole: (...roles: string[]) => !!me && roles.some((r) => me.roles.includes(r)),
      logout,
      reload: load,
    }),
    [status, me, logout, load],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
