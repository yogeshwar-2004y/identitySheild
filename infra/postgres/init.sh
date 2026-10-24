#!/bin/sh
# Runs once, on first start of the postgres container.
# Creates:
#   - is_app        runtime role for the API (NOT owner, NOT superuser -> row-level security applies)
#   - keycloak      role + database for Keycloak
#   - identityshield_test  database for the pytest suite
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE ROLE is_app LOGIN PASSWORD '${IS_APP_DB_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
  CREATE ROLE keycloak LOGIN PASSWORD '${KEYCLOAK_DB_PASSWORD}';
  CREATE DATABASE keycloak OWNER keycloak;
  CREATE DATABASE identityshield_test OWNER ${POSTGRES_USER};
  GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO is_app;
  GRANT CONNECT ON DATABASE identityshield_test TO is_app;
EOSQL

for db in "$POSTGRES_DB" identityshield_test; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<-EOSQL
    GRANT USAGE ON SCHEMA public TO is_app;
EOSQL
done
