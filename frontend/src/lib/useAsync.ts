import { useCallback, useEffect, useRef, useState } from "react";

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const alive = useRef(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);
  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await run();
      if (alive.current) setData(v);
    } catch (e) {
      if (alive.current) setError(e);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [run]);
  useEffect(() => {
    alive.current = true;
    void reload();
    return () => {
      alive.current = false;
    };
  }, [reload]);
  return { data, error, loading, reload, setData };
}
