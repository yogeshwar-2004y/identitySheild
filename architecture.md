# IdentityShield: Architecture

An Identity Threat Detection & Response (ITDR) SaaS that combines **IAM** (identity lifecycle, session management, safe logout) with **threat hunting** (detections, hunt queries, automated response).

---

## 1. Goals

| Goal | How it is met |
|---|---|
| Proper session management | Short-lived access tokens, rotating refresh tokens, idle + absolute timeouts, device/IP binding, active-session list, remote kill |
| Identity lifecycle management | Joiner / Mover / Leaver workflows with audit trail and access diff |
| Safe logout | Server-side revocation, back-channel logout, logout-all-devices, cookie clearing, cache-control |
| Threat hunting | Detection rules, saved hunt queries, risk scoring, user timelines, MITRE ATT&CK mapping |
| Automated response | Revoke sessions, force MFA, lock account, notify admin |
| Multi-tenancy (SaaS) | One Keycloak realm per tenant, `tenant_id` on every row, tenant-scoped queries |

---

## 2. High-Level Architecture

```
                         +---------------------------+
                         |   React Dashboard (SPA)   |
                         | Alerts | Hunt | Lifecycle |
                         +-------------+-------------+
                                       | HTTPS (OIDC login, REST)
                                       v
+-------------------+        +---------------------+        +------------------+
|     Keycloak      |<------>|  IdentityShield API |<------>|   PostgreSQL     |
|  (IdP, realms     | Admin  |      (FastAPI)      |        | tenants, users,  |
|   per tenant)     |  API   |                     |        | sessions, alerts |
+--------+----------+        |  - Lifecycle svc    |        +------------------+
         |                   |  - Session svc      |
         | Event listener /  |  - Detection engine |        +------------------+
         | webhook           |  - Response engine  |<------>|      Redis       |
         v                   |  - Hunt API         |        | revocation list, |
+-------------------+        +----------+----------+        | rate limits,     |
|  Event Ingestor   |-------------------+                   | session cache    |
| (login, admin and |                                       +------------------+
|  logout events)   |        +----------------------+
+-------------------+------->| Elasticsearch / PG   |
                             | event store for hunt |
                             +----------------------+

        +-----------------------------+
        |  Attack Simulator (CLI)     |  -> generates stolen-session, ghost-account,
        |  lab/demo only              |     impossible-travel, brute-force events
        +-----------------------------+
```

---

## 3. Components

### 3.1 Keycloak (Identity Provider)
- One **realm per tenant**; OIDC authorization code flow with PKCE.
- Handles authentication, MFA (TOTP), password policy, brute-force lockout.
- Emits login, logout, admin and error events to the Event Ingestor.
- Realm settings: SSO Session Idle, SSO Session Max, Refresh Token Rotation (revoke refresh token = on), access token lifespan of 5 minutes.

### 3.2 IdentityShield API (FastAPI)
Modular monolith with these services:

| Service | Responsibility |
|---|---|
| `lifecycle` | Joiner, Mover, Leaver workflows via Keycloak Admin API |
| `sessions` | Session registry, device/IP binding, kill session, logout-all |
| `events` | Ingest and normalize Keycloak and app events |
| `detection` | Rule engine, risk scoring, alert creation |
| `response` | Automated actions (revoke, lock, force MFA, notify) |
| `hunt` | Saved queries, ad hoc search, user timeline |
| `audit` | Tamper-evident audit log (hash chain) |
| `tenancy` | Tenant onboarding, realm provisioning, isolation checks |

### 3.3 PostgreSQL
System of record for tenants, users (mirror), roles, sessions, lifecycle events, alerts, rules, hunts and audit log.

### 3.4 Redis
- **Token revocation list** (`revoked:jti:<id>` with TTL = remaining token life)
- **Session cache** and per-user concurrent-session counters
- **Rate limiting** for login and API endpoints
- Pub/sub channel for real-time alert push to the dashboard

### 3.5 Event Store
PostgreSQL JSONB table (default) or Elasticsearch (optional) holding normalized events for hunting.

### 3.6 Dashboard (React)
Pages: Overview, Alerts, Hunt Console, User Timeline, Lifecycle (Joiner/Mover/Leaver), Sessions, Rules, Audit Log, Tenant Settings.

### 3.7 Attack Simulator
CLI that generates labelled attack scenarios against the **local lab only**, used for demos and detection tests.

---

## 4. Session Management Design

| Control | Design |
|---|---|
| Access token | JWT, 5 min lifetime, contains `sid`, `jti`, `tenant_id`, `roles` |
| Refresh token | Opaque or JWT, single-use, rotated on every refresh; reuse of an old refresh token revokes the whole session family and raises an alert |
| Idle timeout | 15 min of inactivity ends the session |
| Absolute timeout | 8 hours maximum regardless of activity |
| Device binding | Session stores user-agent hash and IP/ASN; large drift triggers a risk step-up or revoke |
| Concurrent sessions | Configurable cap per user (for example 3); oldest session evicted or blocked |
| Cookies | `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix |
| Revocation check | API gateway middleware checks `jti` and `sid` against Redis on every request |
| Session fixation | New session ID issued after authentication and after privilege change |
| Visibility | Users see their active sessions and can kill any of them |

### 4.1 Safe Logout Flow
1. User clicks logout; SPA calls `POST /auth/logout`.
2. API revokes the session in Postgres, adds `sid` and current `jti` to the Redis revocation list.
3. API calls Keycloak to end the SSO session and triggers **back-channel logout** to every relying party.
4. Refresh tokens for the session are invalidated.
5. Response clears cookies and sets `Cache-Control: no-store`; SPA wipes in-memory tokens and redirects to the login page.
6. Back button shows no cached authenticated content; any replayed token is rejected by the revocation check.

**Logout all devices:** same flow applied to every session of the user.

---

## 5. Identity Lifecycle Design

### 5.1 Joiner (Provisioning)
1. Admin or HR webhook submits a new-hire request (name, email, department, role template).
2. API validates and creates the user in Keycloak (required actions: verify email, set password, enroll MFA).
3. Roles are assigned from the **role template** for the department (least privilege).
4. Record written to `lifecycle_events` and `audit_log`.
5. Invite email sent; state moves `PENDING -> ACTIVE` on first successful login with MFA.

### 5.2 Mover (Role Change)
1. Change request submitted (new department or role).
2. System computes an **access diff** (roles added and removed).
3. Sensitive additions require approval.
4. Roles updated in Keycloak, all active sessions are re-issued so tokens carry new claims.
5. Detection rule checks for privilege-escalation patterns.

### 5.3 Leaver (Deprovisioning)
1. Termination trigger from admin or HR webhook, optionally scheduled for a date/time.
2. Execute in order, as one idempotent workflow:
   1. Disable the account in Keycloak.
   2. Revoke all sessions and refresh tokens.
   3. Add outstanding `jti` values to the Redis revocation list.
   4. Remove role and group memberships.
   5. Revoke API keys and personal tokens.
   6. Mark user `DEPROVISIONED` and keep the record for audit.
3. Verification step confirms the account cannot authenticate and old tokens are rejected.
4. **Post-leaver watch:** any login attempt or token use by this identity raises a critical alert (ghost account).

### 5.4 User State Machine
```
PENDING -> ACTIVE -> SUSPENDED -> ACTIVE
              |          |
              v          v
        DEPROVISIONED (terminal, retained for audit)
```

---

## 6. Event Pipeline

1. Keycloak event listener (or polling of the admin events API) sends events to `POST /ingest/keycloak`.
2. App events (lifecycle, session kill, role change) are written by the API itself.
3. **Normalization** to a common schema:

```json
{
  "event_id": "uuid",
  "tenant_id": "uuid",
  "ts": "2026-10-23T08:58:00Z",
  "type": "LOGIN | LOGIN_ERROR | LOGOUT | TOKEN_REFRESH | ROLE_GRANT | USER_DISABLE ...",
  "user_id": "uuid",
  "session_id": "uuid",
  "ip": "203.0.113.10",
  "geo": {"country": "IN", "city": "Coimbatore", "lat": 11.0, "lon": 76.9},
  "asn": "AS0000",
  "user_agent_hash": "sha256...",
  "outcome": "SUCCESS | FAILURE",
  "details": {}
}
```

4. Events are stored, then pushed to the detection engine (stream or in-process queue).

---

## 7. Detection Engine

Each rule is a Python class or Sigma-style YAML with: `id`, `name`, `severity`, `attack_technique`, `window`, `threshold`, `logic`.

| ID | Detection | Logic | ATT&CK |
|---|---|---|---|
| D01 | Impossible travel | Two successful logins whose implied speed exceeds 900 km/h | T1078 Valid Accounts |
| D02 | Session replay / hijack | Same `sid` or token seen from new IP/ASN/user-agent | T1539 Steal Web Session Cookie |
| D03 | Refresh token reuse | Rotated refresh token presented again | T1528 / T1550 |
| D04 | Ghost account activity | Any auth or token use by a `DEPROVISIONED` user | T1078 |
| D05 | Orphaned active account | Active account with no login for N days, or owner left | T1078 |
| D06 | Privilege escalation | Admin role granted outside approved workflow, or abnormal role count jump | T1098 Account Manipulation |
| D07 | Brute force | N failures within window from one IP or against one user | T1110.001 |
| D08 | Credential stuffing | One IP failing across many distinct users | T1110.004 |
| D09 | MFA fatigue | Many MFA prompts or denials within a short window | T1621 |
| D10 | Off-hours access | Successful login outside the user's learned working hours | T1078 |
| D11 | Mass access | Abnormal resource access volume after login | T1530 / T1087 |
| D12 | Delayed deprovisioning | Time from leaver trigger to disable exceeds SLA | Process control |

### 7.1 Risk Scoring
`risk = sum(rule_weight * confidence)`, clamped to 0 to 100, kept per session and per user.

| Score | Action |
|---|---|
| 0 to 39 | Log only |
| 40 to 69 | Step-up MFA, create medium alert |
| 70 to 89 | Revoke session, create high alert |
| 90 and above | Lock account, revoke all sessions, notify admin |

### 7.2 Hunting
- **Saved hunts**: parameterized queries such as "accounts with logins from 3 or more countries in 24 hours".
- **Ad hoc**: filter builder over events by user, IP, time, type and outcome.
- **User timeline**: chronological view of lifecycle, session and alert events for one identity.
- **Hypothesis log**: each hunt stores hypothesis, query, result count and verdict.

---

## 8. Response Engine

| Action | Implementation |
|---|---|
| Revoke session | Postgres update + Redis revocation + Keycloak session delete |
| Revoke all sessions | Same, for all sessions of the user |
| Force MFA | Add Keycloak required action `CONFIGURE_TOTP` or step-up flag |
| Lock account | Disable user in Keycloak, state `SUSPENDED` |
| Notify | Email / webhook / dashboard push |
| Playbooks | Rule-to-action mappings per tenant, with a dry-run mode |

Every automated action writes an `audit_log` entry referencing the triggering alert.

---

## 9. Data Model

```
tenants(id, name, realm, status, created_at)
users(id, tenant_id, kc_user_id, email, department, state, created_at, deprovisioned_at)
roles(id, tenant_id, name, sensitivity)
role_templates(id, tenant_id, department, role_ids[])
user_roles(user_id, role_id, granted_by, granted_at, approval_id)
sessions(id, tenant_id, user_id, kc_session_id, ip, geo, ua_hash,
         created_at, last_seen_at, expires_at, revoked_at, revoke_reason)
refresh_families(id, session_id, current_token_hash, reused_at)
events(id, tenant_id, ts, type, user_id, session_id, ip, geo, outcome, details jsonb)
lifecycle_events(id, tenant_id, user_id, kind[JOINER|MOVER|LEAVER], status, requested_by, payload, created_at)
approvals(id, tenant_id, request_type, requested_by, approver, status, decided_at)
detection_rules(id, tenant_id, rule_key, severity, enabled, params jsonb)
alerts(id, tenant_id, rule_key, severity, user_id, session_id, risk, status, evidence jsonb, created_at)
hunt_queries(id, tenant_id, name, hypothesis, query jsonb, created_by)
hunt_runs(id, hunt_id, run_at, result_count, verdict, notes)
response_playbooks(id, tenant_id, rule_key, actions jsonb, mode[DRY_RUN|ACTIVE])
audit_log(id, tenant_id, ts, actor, action, target, detail jsonb, prev_hash, hash)
```

Indexes: `events(tenant_id, ts)`, `events(tenant_id, user_id, ts)`, `sessions(user_id, revoked_at)`, `alerts(tenant_id, status, severity)`.

**Audit hash chain:** `hash = SHA256(prev_hash || canonical_json(entry))`; a verification endpoint recomputes the chain and reports tampering.

---

## 10. API Surface (v1)

| Group | Endpoints |
|---|---|
| Auth | `GET /auth/login`, `GET /auth/callback`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all` |
| Sessions | `GET /sessions`, `DELETE /sessions/{id}`, `GET /users/{id}/sessions` |
| Lifecycle | `POST /lifecycle/joiner`, `POST /lifecycle/mover`, `POST /lifecycle/leaver`, `GET /lifecycle/requests`, `POST /lifecycle/{id}/approve` |
| Users | `GET /users`, `GET /users/{id}`, `GET /users/{id}/timeline` |
| Events | `POST /ingest/keycloak`, `GET /events` |
| Detection | `GET /alerts`, `PATCH /alerts/{id}`, `GET /rules`, `PUT /rules/{id}` |
| Hunt | `GET /hunts`, `POST /hunts`, `POST /hunts/{id}/run`, `POST /hunt/search` |
| Response | `GET /playbooks`, `PUT /playbooks/{id}` |
| Audit | `GET /audit`, `GET /audit/verify` |
| Tenants | `POST /tenants`, `GET /tenants/me` |

All endpoints require a valid access token, a revocation check, tenant scoping, and RBAC (`admin`, `analyst`, `hr`, `user`).

---

## 11. Security Controls

- OIDC with PKCE; tokens are never stored in `localStorage` (memory plus HttpOnly cookies).
- Strict CORS, CSRF protection for cookie flows, security headers (CSP, HSTS, X-Frame-Options).
- Tenant isolation enforced in middleware and in queries; automated test tries cross-tenant access.
- Parameterized queries only; input validation with Pydantic.
- Secrets from environment or a secrets manager; none committed.
- Rate limiting on auth and API endpoints.
- Least-privilege service account for the Keycloak Admin API.
- Idempotent, retry-safe lifecycle workflows with compensating actions.
- Simulator is restricted to the local lab and refuses non-local targets.

---

## 12. Deployment

`docker-compose` stack:

| Service | Image / Build | Port |
|---|---|---|
| keycloak | quay.io/keycloak/keycloak | 8080 |
| postgres | postgres | 5432 |
| redis | redis | 6379 |
| api | ./backend | 8000 |
| web | ./frontend | 5173 |
| elasticsearch (optional) | elasticsearch | 9200 |
| simulator | ./simulator (run on demand) | n/a |

---

## 13. Repository Layout

```
identityshield/
  docker-compose.yml
  README.md
  docs/ (architecture.md, report/)
  keycloak/ (realm-export.json, event-listener config)
  backend/
    app/
      main.py
      core/ (config, security, tenancy, deps)
      auth/
      lifecycle/
      sessions/
      events/
      detection/ (rules/, scoring.py, engine.py)
      response/
      hunt/
      audit/
      models/ schemas/ db/
    tests/
  frontend/
    src/ (pages/, components/, api/, auth/)
  simulator/
    scenarios/ (stolen_session, ghost_login, impossible_travel, brute_force, privesc)
  scripts/ (seed.py, demo.sh)
```

---

## 14. Demo Scenario

1. Create tenant and provision user *Asha* (Joiner) with MFA; log in.
2. Show active session with device/IP binding.
3. Run simulator `stolen_session`: token replayed from another IP.
4. D02 fires, risk crosses 70, session auto-revoked; replay now returns 401.
5. Run `impossible_travel` and show D01 alert and user timeline.
6. Move *Asha* to a new department (Mover), show access diff and re-issued session.
7. Deprovision *Asha* (Leaver); verify sessions dead and old token rejected.
8. Run `ghost_login`; D04 raises a critical alert.
9. Open the audit log and run hash-chain verification.

---

## 15. Evaluation Criteria Mapping

| Expectation | Where it is covered |
|---|---|
| Proper session management | Section 4 |
| Provisioning / deprovisioning | Section 5 |
| Safe logout | Section 4.1 |
| Threat hunting | Section 7 |
| IAM package evaluation | Keycloak as chosen IdP, compared with Auth0, Okta, Entra ID, Cognito in the report |
