# Build Prompt: IdentityShield (ITDR SaaS)

You are a senior full-stack and security engineer. Build the entire **IdentityShield** project end to end, following `architecture.md` in this directory as the source of truth. Work in phases, run and test each phase before moving on, and keep the repository in a working state at all times.

## 1. Project Summary

IdentityShield is a multi-tenant SaaS for **Identity Threat Detection & Response (ITDR)**. It combines:

- **IAM**: identity lifecycle (Joiner / Mover / Leaver), proper session management, and safe logout.
- **Threat hunting**: detections, hunt queries, risk scoring, automated response, MITRE ATT&CK mapping.

It is a university project. The IAM evaluation criteria are **session management, identity lifecycle (provisioning and deprovisioning), and safe logout**, so these must be implemented rigorously and be easy to demonstrate.

## 2. Tech Stack (do not substitute without a reason)

- Identity provider: **Keycloak** (one realm per tenant, OIDC + PKCE)
- Backend: **Python 3.12, FastAPI**, SQLAlchemy 2.x, Alembic, Pydantic v2
- Database: **PostgreSQL** (JSONB for events)
- Cache / revocation / rate limit: **Redis**
- Frontend: **React + Vite + TypeScript**, Tailwind CSS, Recharts for charts
- Packaging: **Docker Compose**
- Tests: pytest, httpx; Playwright or Vitest for key UI flows
- Optional: Elasticsearch (behind a feature flag, Postgres is the default event store)

## 3. Deliverables

1. Working code in the layout defined in `architecture.md` section 13.
2. `docker-compose.yml` that starts everything with one command.
3. Keycloak realm export with a demo tenant, roles (`admin`, `analyst`, `hr`, `user`), and a configured event listener.
4. Seed script creating demo tenant, users, roles, role templates and sample events.
5. Attack simulator with five scenarios.
6. Automated tests (target: 70% or more coverage on backend core logic).
7. `README.md` with setup, architecture summary, demo script, and screenshots placeholders.
8. `docs/report/` with a report outline and an **IAM package comparison** (Keycloak vs Auth0 vs Okta vs Entra ID vs Cognito).
9. `scripts/demo.sh` that runs the full demo scenario from `architecture.md` section 14.

## 4. Phases

### Phase 1: Foundation
- Repo scaffold, Docker Compose, env files (`.env.example`), health endpoints.
- Postgres schema and Alembic migrations for all tables in architecture section 9.
- Keycloak realm import; tenant provisioning service that creates a realm per tenant via the Admin API.
- Tenancy middleware: extract `tenant_id` from token, enforce on every query.

**Done when:** `docker compose up` brings up all services and a test user can log in through OIDC.

### Phase 2: Session Management and Safe Logout
- Access token 5 min; refresh token rotation with **reuse detection** (reuse revokes the session family).
- Idle timeout 15 min, absolute timeout 8 h, configurable per tenant.
- Session registry table; record IP, geo, user-agent hash.
- Device/IP drift check; concurrent session cap.
- Redis revocation list checked by middleware on every request (`jti` and `sid`).
- Endpoints: list sessions, kill session, logout, logout-all.
- Safe logout: server-side revoke, Keycloak SSO session end, back-channel logout, cookie clearing, `Cache-Control: no-store`, SPA state wipe.
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`.

**Done when:** tests prove that after logout the old access token, refresh token and back-button navigation all fail.

### Phase 3: Identity Lifecycle
- **Joiner:** create user, role template assignment, required actions (verify email, password, TOTP), state `PENDING -> ACTIVE`.
- **Mover:** access diff, approval for sensitive roles, role update, session re-issue.
- **Leaver:** idempotent workflow (disable, revoke sessions and refresh tokens, revocation list, remove roles, revoke API keys, mark `DEPROVISIONED`), scheduled leaver support, verification step.
- Webhook endpoint for HR-triggered events (HMAC-signed).
- `lifecycle_events` and `audit_log` entries for every step.
- Tamper-evident audit log using a hash chain, plus `GET /audit/verify`.

**Done when:** a leaver run leaves zero active sessions and the account cannot authenticate; tests cover failure and retry mid-workflow.

### Phase 4: Event Pipeline
- Keycloak event ingestion endpoint and listener/poller.
- Normalization to the common event schema (architecture section 6).
- GeoIP enrichment using a local database or a stub for the lab (no external calls required).
- Events stored with indexes for hunting.

**Done when:** login, logout, failure and admin events appear normalized in the database in near real time.

### Phase 5: Detection and Response
- Implement rules D01 to D12 (architecture section 7) as pluggable classes with unit tests that use synthetic event sequences.
- Risk scoring and thresholds; alert creation with evidence.
- Response engine with playbooks, `DRY_RUN` and `ACTIVE` modes, all actions audited.
- Real-time alert push (WebSocket or SSE backed by Redis pub/sub).

**Done when:** each rule has a positive and a negative test, and a high-risk alert triggers the configured response.

### Phase 6: Threat Hunting
- Saved hunts with hypothesis, parameterized query, run history, verdict.
- Ad hoc search API and UI filter builder.
- User timeline combining lifecycle, session, event and alert data.
- At least 8 prebuilt hunts (for example: multi-country logins in 24 h, dormant accounts that suddenly log in, accounts with sessions older than the absolute limit, users with many role grants, deprovisioned users with activity).

**Done when:** every prebuilt hunt returns correct results against seeded data.

### Phase 7: Frontend
Pages: Overview (KPIs and charts), Alerts, Alert detail, Hunt Console, User Timeline, Lifecycle (Joiner/Mover/Leaver forms and request list), Sessions, Rules and Playbooks, Audit Log with verify button, Tenant Settings.
- Auth via OIDC code flow with PKCE; tokens kept in memory; role-based route guards.
- Clean, dark-mode-friendly dashboard; responsive; loading and error states.

**Done when:** the full demo can be performed from the UI only.

### Phase 8: Attack Simulator
CLI in `simulator/` with scenarios: `stolen_session`, `impossible_travel`, `ghost_login`, `brute_force`, `privesc`.
- Each scenario prints what it does and the expected detection ID.
- **Safety:** only allow targets on localhost or the Docker network; refuse anything else; require an explicit `--i-understand-lab-only` flag.

### Phase 9: Hardening, Tests, Docs
- Security headers, CORS, CSRF, rate limiting, input validation.
- Cross-tenant isolation test suite.
- Dependency and secret scan (for example `pip-audit`, `npm audit`, `gitleaks`).
- Finish README, report outline, IAM comparison, architecture diagram export.
- Record the final demo script and verify it runs from a clean clone.

## 5. Engineering Rules

- Follow `architecture.md`; if you must deviate, document why in `docs/DECISIONS.md`.
- Every endpoint: authentication, revocation check, tenant scoping, RBAC, input validation.
- No secrets in the repo; use `.env.example` with placeholders.
- Parameterized queries only; no string-built SQL.
- Lifecycle workflows must be idempotent and safe to retry.
- Write tests alongside code; do not move to the next phase with failing tests.
- Type hints everywhere in Python; strict TypeScript in the frontend.
- Small, meaningful commits with clear messages.
- Keep code readable and commented where security logic is non-obvious, since evaluators will read it.

## 6. Acceptance Criteria (final check)

1. `docker compose up` starts the full system; `scripts/seed.py` loads demo data.
2. Logout invalidates access token, refresh token and SSO session; replay returns 401.
3. Refresh token reuse revokes the whole session family and raises an alert.
4. Leaver workflow results in a disabled account, zero live sessions, removed roles, and an audit trail.
5. Ghost-account login after deprovisioning raises a critical alert.
6. Stolen-session replay is detected and auto-revoked above the risk threshold.
7. Impossible-travel, brute-force, credential-stuffing and privilege-escalation detections all fire from the simulator.
8. Cross-tenant access attempts fail in tests.
9. Audit log verification detects a manually tampered row.
10. Full demo (architecture section 14) runs from the UI and from `scripts/demo.sh`.

## 7. Output Expectations

- After each phase, summarize what was built, how to run it, and test results.
- If a requirement is ambiguous, choose the most reasonable option, state the assumption, and continue.
- At the end, provide: a file tree, run instructions, the demo walkthrough, known limitations, and ideas for future work.

Start with Phase 1 now.
