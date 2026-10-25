# Keycloak for Render (free 512 MB web service).
# Pre-built ("kc.sh build") so start-up skips the Quarkus augmentation step and uses less memory.
FROM quay.io/keycloak/keycloak:26.2.5 AS builder
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_FEATURES_DISABLED=impersonation
# Keycloak shares the app's single Render database but keeps its tables in schema "keycloak",
# which it does not create itself: each new pool connection makes sure it exists.
RUN echo 'quarkus.datasource.jdbc.new-connection-sql=CREATE SCHEMA IF NOT EXISTS keycloak' \
      >> /opt/keycloak/conf/quarkus.properties \
 && /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.2.5
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY --chmod=755 deploy/render/keycloak-entrypoint.sh /opt/keycloak/bin/render-entrypoint.sh
ENTRYPOINT ["/opt/keycloak/bin/render-entrypoint.sh"]
