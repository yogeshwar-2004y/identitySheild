import { useEffect } from "react";

/** Re-runs `reload` whenever the layout's SSE stream delivers a new alert. */
export function useLiveReload(reload: () => void): void {
  useEffect(() => {
    const h = () => reload();
    window.addEventListener("is:alert", h);
    return () => window.removeEventListener("is:alert", h);
  }, [reload]);
}
