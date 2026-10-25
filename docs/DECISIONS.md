# Design decisions and deviations

`architecture.md` is the source of truth. This file records where the implementation
deviates or had to choose between options, and why.

## D-1 Backend-for-frontend instead of tokens in the SPA
**Choice:** the API performs the OIDC code flow with PKCE as a confidential client and issues its
own short-lived JWT; the refresh token is an opaque `__Host-` HttpOnly cookie.
**Why:** architecture §11 forbids tokens in `localStorage`; a BFF keeps Keycloak tokens off the
browser entirely, lets the API own rotation + reuse detection (§4), and gives one place to revoke.
The SPA still holds only the 5-minute access token, in memory.

## D-2 Own access token rather than forwarding Keycloak's
**Why:** the token must carry the *application* session id (`sid`), a claims version for
Mover re-issue, and tenant id; revocation is checked against our session registry. Keycloak's
SSO session is kept in lock-step: every refresh also refreshes the Keycloak session, so a session
killed in Keycloak (or a disabled user) ends the app session at the next refresh.

## D-3 Extra columns / tables beyond §9
* `tenant_id` on `user_roles`, `refresh_families`, `hunt_runs` so every tenant table can carry
  a row-level-security policy.
* `refresh_tokens` (hash of every token issued in a family) — needed to recognise *reuse* of an
  already-rotated token rather than an unknown one.
* `api_keys` — the Leaver must revoke "API keys and personal tokens" (§5.3).
* `tenants.settings` — per-tenant session policy (prompt Phase 2 "configurable per tenant").
* `users.last_login_at`, `users.mfa_enrolled`, `lifecycle_events.steps/attempts/access_diff`,
  `alerts.response/dedupe_key`, `events.source/source_id` for idempotent ingestion.

## D-4 Row-level security in addition to query scoping
The runtime role `is_app` is not the table owner, so RLS always applies. Each transaction sets
`app.tenant_id` with `SET LOCAL`; with no tenant bound, every tenant table returns zero rows.
`tenants` has no RLS (login needs to resolve a realm before a tenant is known); it only holds
encrypted secrets. `audit_log` and `events` are append-only for the runtime role.

## D-5 Keycloak calls that trigger back-channel logout run after commit
Disabling a user, deleting a session, logging a user out or ending an SSO session makes Keycloak
call our `/auth/backchannel-logout` synchronously. Doing that while our transaction holds row
locks or the audit advisory lock deadlocked until Keycloak's 5 s timeout (found during testing).
Those calls are queued with `run_after_commit`, and the back-channel handler uses
`FOR UPDATE SKIP LOCKED`.

## D-6 Event ingestion by polling
Keycloak has no built-in webhook. The worker polls the user-events and admin-events APIs every
2 s with the tenant service account (`view-events`); overlap is de-duplicated by the Keycloak
event id (`uq_events_source`). `POST /ingest/keycloak` (HMAC-SHA256) exists for a push-based
event-listener SPI. Admin events produced by IdentityShield's own service account are stored but
not re-detected (the workflow already emitted app events with approval context); out-of-band
grants are mirrored into `user_roles` *before* detection runs.

## D-7 Risk carry is per session
`risk = clamp(weight × confidence + carry)` where carry = contribution of other OPEN alerts on the
same session in the last hour (or same user for session-less alerts). Scoping to the session lets
one compromised session escalate quickly without one noisy day locking a user out.

## D-8 "Force MFA" is scoped to the risky session
The response adds Keycloak's `CONFIGURE_TOTP` required action if the user has no OTP, and marks
the *alert's session* for step-up (its next refresh fails with `step_up_required`). Other sessions
of the user continue. Session-less alerts mark the whole user.

## D-9 Lab mode
To make the attacks reproducible on one laptop, `LAB_MODE=true` adds: `/lab/*` endpoints behind
`LAB_API_KEY`; the `X-Lab-Client-IP` header (synthetic source IP) honoured only together with the
lab key; a password-grant "lab direct grant" flow without OTP on the tenant client; Keycloak
`KC_PROXY_HEADERS=xforwarded` so its events carry the synthetic IP; tenant realms with
`sslRequired=none` (Keycloak otherwise demands HTTPS for the public test-net IPs). All of this is
off when `LAB_MODE=false`.

## D-10 Offline GeoIP
Documentation/test-net ranges map to fixed cities (203.0.113.0/24 = Coimbatore IN,
198.51.100.0/24 = New York US, …); private ranges map to the lab's home office. No external calls.

## D-11 Repository root = `identityshield/`
The layout of §13 is used with the repository root as `identityshield/`. `architecture.md`
stays at the root (as provided) instead of under `docs/`.

## D-12 Elasticsearch not implemented
Optional in the brief; Postgres JSONB with indexes on `(tenant_id, ts)`, `(tenant_id, user_id, ts)`,
`(tenant_id, ip, ts)`, `(tenant_id, type, ts)` covers the lab volume.

## D-13 Separation of duties on approvals
An approval cannot be granted by its requester, and only `admin` can approve. HIGH-sensitivity
roles: `admin`, `analyst`, `eng-prod-access`, `finance-approver`.

## D-14 Dependency scan results (2026-10-25)
* `pip-audit -r backend/requirements.txt`: no known vulnerabilities (after upgrading FastAPI /
  Starlette, python-multipart, cryptography, PyJWT).
* `npm audit --omit=dev`: 2 moderate in `react-router` v6 (fix only in v7, a major upgrade). The
  app only navigates to internal paths, so the open-redirect advisory does not apply.
* Dev-only tooling (Vite dev server, Vitest, Tailwind build) has advisories that need major upgrades;
  they do not ship in the nginx-served production bundle and the Vitest UI server is never started.
* `gitleaks`: the only hits are in the local, git-ignored `.env`; tracked files are clean.

## D-15 Render deployment (free tier)
`render.yaml` deploys the stack to Render with only free instances, which forces these changes:
* **External Postgres and Redis.** A Render workspace gets one free Postgres and one free Key Value,
  already used by other projects, so the Blueprint takes a Neon Postgres URL and an Upstash Redis
  URL instead. The worker poll interval is configurable (`WORKER_POLL_SECONDS`, 10 s on Render) to
  stay inside Upstash's free command quota.
* **One database.** The hosted Postgres gives one database and one owner user. The API start script
  (`deploy/render/api-start.sh`, `app/render_boot.py`) creates the RLS-bound runtime role from the
  owner URL (name `APP_DB_ROLE`, now also used by migration 0002) and runs migrations as the owner;
  the API connects as the runtime role, so row-level security still applies. Keycloak uses the same
  database in schema `keycloak`, created by its connection pool (`new-connection-sql`).
* **No background workers on the free plan.** `EMBED_WORKER=true` runs the worker loop in a daemon
  thread of the API process. `SEED_ON_START=true` seeds the demo tenants once (there is no shell).
* **No private network for free web services.** nginx proxies `/api` to the API's public HTTPS URL,
  and the API calls Keycloak (and Keycloak calls the back-channel logout endpoint) on public URLs.
  The client IP is the leftmost `X-Forwarded-For` entry, which a caller can spoof on this hosted
  setup; acceptable for a lab demo, not for production (use a private network or a signed header).
* **512 MB for Keycloak.** Pre-built image (`kc.sh build`, `start --optimized`), heap capped at 50 %
  of the container, DB pool 8. Measured locally under a 512 MB limit: ~440 MB after seeding.
* **Lab mode stays on** so the Attack Lab works online; `/lab/*` still requires `LAB_API_KEY`.
* `ENCRYPTION_KEY` now accepts URL-safe base64 as well (Render's generated values).
