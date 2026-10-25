# Keycloak for Render (free 512 MB web service).
# Pre-built ("kc.sh build") so start-up skips the Quarkus augmentation step and uses less memory.
FROM quay.io/keycloak/keycloak:26.2.5 AS builder
# cache=local: single node, no JGroups cluster stack (saves memory and threads).
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_FEATURES_DISABLED=impersonation KC_CACHE=local
# Keycloak shares the app's single Render database but keeps its tables in schema "keycloak",
# which it does not create itself: each new pool connection makes sure it exists.
RUN echo 'quarkus.datasource.jdbc.new-connection-sql=CREATE SCHEMA IF NOT EXISTS keycloak' \
      >> /opt/keycloak/conf/quarkus.properties \
 && /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.2.5
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# Fit the free 512 MB instance (Render kills the container above that, including first boot):
# small fixed heap, capped metaspace and code cache, C1-only JIT, fewer threads.
ENV KC_CACHE=local \
    JAVA_OPTS_KC_HEAP="-Xms128m -Xmx200m" \
    JAVA_OPTS_APPEND="-XX:MaxMetaspaceSize=160m -XX:ReservedCodeCacheSize=48m -XX:TieredStopAtLevel=1 -XX:CICompilerCount=1 -Xss512k -XX:MaxDirectMemorySize=32m -Djava.security.egd=file:/dev/urandom" \
    KC_HTTP_POOL_MAX_THREADS=16
COPY --chmod=755 deploy/render/keycloak-entrypoint.sh /opt/keycloak/bin/render-entrypoint.sh
ENTRYPOINT ["/opt/keycloak/bin/render-entrypoint.sh"]
