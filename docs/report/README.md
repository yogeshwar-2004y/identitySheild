# Report outline — IdentityShield (ITDR)

1. **Introduction**
   - Problem: identity is the new perimeter; stolen sessions, orphaned and ghost accounts.
   - Goals and evaluation criteria (session management, provisioning / deprovisioning, safe logout).
2. **Background**
   - OIDC / OAuth 2.0 (code flow, PKCE, refresh rotation, back-channel logout).
   - Identity lifecycle (Joiner / Mover / Leaver), least privilege, separation of duties.
   - ITDR and threat hunting; MITRE ATT&CK techniques T1078, T1110, T1098, T1539, T1528/T1550, T1621.
3. **IAM package evaluation** → [`iam-comparison.md`](iam-comparison.md)
4. **Architecture** (architecture.md §2–3, diagram in README)
   - Backend-for-frontend authentication, multi-tenancy (realm per tenant + Postgres RLS).
5. **Session management and safe logout**
   - Token design, rotation and reuse detection, idle / absolute timeouts, device binding,
     concurrent cap, revocation list; the 6-step logout flow; back-button handling.
   - Evidence: `tests/test_sessions.py`, demo steps 2–4.
6. **Identity lifecycle**
   - Joiner (templates, required actions), Mover (access diff, approval, session re-issue),
     Leaver (7 idempotent steps + verification, scheduled leavers, HR webhook).
   - Evidence: `tests/test_lifecycle.py`, demo steps 1, 6, 7.
7. **Detection, scoring and response**
   - Event pipeline and normalised schema; rules D01–D12; risk formula and tiers; playbooks.
   - Evidence: `tests/test_rules.py`, `tests/test_detection_pipeline.py`, simulator runs.
8. **Threat hunting**
   - Hypothesis-driven hunts, DSL, 10 prebuilt hunts and their seeded ground truth, timeline.
9. **Security controls and testing**
   - Tenant isolation tests, tamper-evident audit log, scans (pip-audit, npm audit, gitleaks).
10. **Demo walkthrough** (architecture §14, `scripts/demo.sh`) with screenshots.
11. **Limitations and future work** (README).
12. **References**

## Screenshots to capture (`docs/report/screenshots/`)

- [x] Keycloak sign-in (`keycloak-login.jpg`)
- [x] Overview dashboard (`overview.jpg`)
- [ ] Sessions page showing device / IP binding
- [ ] Attack Lab: stolen_session output + D02 alert detail (risk, response actions)
- [ ] User timeline after impossible travel
- [ ] Lifecycle: Mover access diff; Leaver verification checks
- [ ] Alert D04 ghost account
- [ ] Audit log: verified chain and detected tampering
- [ ] Hunt console with a prebuilt hunt result
