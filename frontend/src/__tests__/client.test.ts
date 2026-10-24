import { afterEach, describe, expect, it, vi } from "vitest";
import { api, hasToken, logout, refreshSession, wipeTokens } from "../api/client";

const tokenBody = {
  access_token: "at-1",
  expires_at: new Date(Date.now() + 300_000).toISOString(),
  session_id: "s1",
  session_expires_at: new Date(Date.now() + 8 * 3600_000).toISOString(),
  user: { id: "u", email: "a@b", username: "a", full_name: "A", department: "IT", state: "ACTIVE", roles: ["admin"] },
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => {
  vi.restoreAllMocks();
  wipeTokens();
  document.cookie = "is_csrf=; max-age=0";
});

describe("api client", () => {
  it("never writes tokens to web storage", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json(200, tokenBody));
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    await refreshSession();
    expect(hasToken()).toBe(true);
    expect(setItem).not.toHaveBeenCalled();
  });

  it("collapses concurrent refreshes into one request (no self-inflicted reuse)", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockImplementation(async () => json(200, tokenBody));
    await Promise.all([refreshSession(), refreshSession(), refreshSession()]);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("sends the CSRF header on refresh", async () => {
    document.cookie = "is_csrf=tok123"; // jsdom rejects __Host- cookies over http; same parser
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(json(200, tokenBody));
    await refreshSession();
    const init = f.mock.calls[0]![1] as RequestInit;
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("tok123");
  });

  it("refreshes once and retries when the access token expired", async () => {
    const f = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json(200, tokenBody)) // initial refresh
      .mockResolvedValueOnce(json(401, { detail: { code: "token_expired", message: "expired" } }))
      .mockResolvedValueOnce(json(200, { ...tokenBody, access_token: "at-2" }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    await expect(api("/auth/me")).resolves.toEqual({ ok: true });
    expect(new Headers((f.mock.calls[3]![1] as RequestInit).headers).get("Authorization")).toBe("Bearer at-2");
  });

  it("wipes the in-memory token on revoked sessions and on logout", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json(200, tokenBody))
      .mockResolvedValueOnce(json(401, { detail: { code: "token_revoked", message: "revoked" } }));
    await expect(api("/auth/me")).rejects.toThrow("revoked");
    expect(hasToken()).toBe(false);

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(json(200, tokenBody))
      .mockResolvedValueOnce(json(200, { logout_url: "http://kc/logout" }));
    await refreshSession();
    expect(hasToken()).toBe(true);
    await expect(logout(false)).resolves.toBe("http://kc/logout");
    expect(hasToken()).toBe(false);
  });
});
