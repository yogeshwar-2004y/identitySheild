import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { Spinner } from "../components/ui";

/** Route guard: signed-in + at least one of the roles (UI convenience; the API enforces RBAC). */
export function RequireRole({ roles, children }: { roles?: string[]; children: ReactNode }) {
  const { status, hasRole } = useAuth();
  const loc = useLocation();
  if (status === "loading") return <div className="flex h-screen items-center justify-center"><Spinner /></div>;
  if (status === "signed-out") return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (roles && !hasRole(...roles)) {
    return (
      <div className="p-10 text-center">
        <h2 className="text-lg font-semibold">Access denied</h2>
        <p className="mt-2 text-sm text-slate-500">This page requires one of: {roles.join(", ")}.</p>
      </div>
    );
  }
  return <>{children}</>;
}
