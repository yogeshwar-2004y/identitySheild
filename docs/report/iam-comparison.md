# IAM package comparison: Keycloak vs Auth0 vs Okta vs Microsoft Entra ID vs Amazon Cognito

Scope: the capabilities IdentityShield depends on (session control, lifecycle automation, safe
logout, event export for detection, multi-tenancy) plus cost and operability for a university
lab. Vendor features and pricing change frequently; verify against current vendor documentation
before citing figures in the final report.

## Summary

| Criterion | Keycloak | Auth0 (Okta CIC) | Okta Workforce | Entra ID | Cognito |
|---|---|---|---|---|---|
| Hosting | Self-hosted (or managed by third parties) | SaaS | SaaS | SaaS | AWS managed |
| Licence / cost | Open source (Apache 2.0), infra cost only | Free tier, then per-MAU | Per user per month | Free tier; P1/P2 per user for advanced features | Per-MAU, free tier |
| OIDC code flow + PKCE | Yes | Yes | Yes | Yes | Yes |
| Refresh-token rotation + reuse detection | Rotation ("revoke refresh token"); reuse invalidates | Yes, with reuse detection | Yes | Rotation built in; reuse handling largely internal | Rotation optional (newer feature) |
| Idle / absolute session limits | Per realm and per client | Per tenant | Per policy | Conditional Access sign-in frequency (P1) | Token validity limits only |
| Back-channel logout (OIDC) | Yes | Yes | Yes (selected apps) | Front-channel; limited back-channel | No |
| Admin API for lifecycle (JML) | Full REST admin API | Management API | Users / Groups API, Workflows | Microsoft Graph, Lifecycle Workflows (P2/Governance) | User-pool admin APIs |
| SCIM provisioning | Via extensions | Via add-ons | Native | Native | No (custom) |
| MFA (TOTP / WebAuthn) | Built in | Built in, plus push (paid) | Built in, Okta Verify push | Built in, Authenticator push | TOTP, SMS; WebAuthn in newer tiers |
| Login / admin event export | Events + admin events REST API, event-listener SPI | Log streams | System Log API, event hooks | Sign-in and audit logs via Graph / diagnostic settings | CloudTrail + Lambda triggers |
| Built-in threat detection | Brute-force lockout only | Attack protection (bot, breached password, brute force) | ThreatInsight, Identity Threat Protection | Identity Protection (risky users / sign-ins, P2) | Advanced security (adaptive auth, compromised credentials) |
| Multi-tenancy | Realm per tenant (or organisations) | Tenants / Organizations | Orgs (one per customer is costly) | Tenant per org; B2B / External ID | One user pool per tenant |
| Extensibility | Java SPIs (authenticators, event listeners, themes) | Actions (JavaScript) | Inline / event hooks | Custom extensions, Conditional Access | Lambda triggers |
| Vendor lock-in | Low | Medium | Medium–High | High (Microsoft ecosystem) | High (AWS) |
| Runs fully offline in a laptop lab | Yes | No | No | No | No |

## Discussion

**Keycloak (chosen).** The only option that runs entirely inside `docker compose`, which the
project requires (one-command lab, attack simulator against local targets, no external calls).
It exposes everything the ITDR side needs: user and admin events through a REST API, a full admin
API for Joiner/Mover/Leaver, realm-level session idle/max settings, refresh-token revocation, and
OIDC back-channel logout. Realm-per-tenant gives hard isolation for the SaaS model. Trade-offs:
the operator owns patching, HA, backups and TLS; the built-in threat features are limited to
brute-force lockout, which is exactly the gap IdentityShield's detection layer fills.

**Auth0.** Strongest developer experience and good built-in attack protection, refresh-token
rotation with reuse detection, and log streaming. It is a cloud service with per-MAU pricing; the
lab could not simulate attacks fully offline, and many protections are paid features.

**Okta Workforce Identity.** Mature workforce IAM: SCIM, lifecycle management, Workflows,
ThreatInsight, rich System Log. Best fit for an enterprise with many SaaS apps. Cost per user and
the SaaS-only model make it a poor fit for a self-contained student lab.

**Microsoft Entra ID.** Deep integration with Microsoft 365, Conditional Access, Identity
Protection risk scores and Lifecycle Workflows. Several of these require P1/P2 or Governance
licences. Best choice when the organisation already runs on Microsoft; strong lock-in.

**Amazon Cognito.** Cheap and simple for customer identity in AWS apps, with Lambda triggers.
Weaker for workforce IAM: no OIDC back-channel logout, limited session controls, no SCIM, and
admin-event visibility goes through CloudTrail.

## Recommendation

For this project: **Keycloak**, because it is open source, self-hostable in the lab, and exposes
the events and admin APIs the detection and lifecycle engines need. For a production enterprise
deployment the decision would follow the existing ecosystem: Entra ID for Microsoft shops, Okta for
best-of-breed workforce IAM across many SaaS apps, Auth0 for customer identity, Cognito for
AWS-native customer apps. IdentityShield's design (normalised event schema, IdP gateway protocol in
`backend/app/core/keycloak.py`) keeps the IdP replaceable.
