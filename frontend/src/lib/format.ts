export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ago(iso?: string | null): string {
  if (!iso) return "—";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 0) return `in ${fmtDur(-s)}`;
  return `${fmtDur(s)} ago`;
}

export function fmtDur(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

export function shortId(id?: string | null): string {
  return id ? id.slice(0, 8) : "—";
}

export function geoLabel(geo?: { city?: string; country?: string } | null): string {
  if (!geo) return "—";
  return [geo.city, geo.country].filter(Boolean).join(", ");
}
