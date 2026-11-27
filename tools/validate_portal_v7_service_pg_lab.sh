#!/usr/bin/env bash
# Integracion real Java/Spring + PostgreSQL16 desechable. No contacta AWS ni BD existentes.
set -Eeuo pipefail
set +x
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE='postgres:16-alpine'
DB='wallet_provider_it'
CONTAINER="mtc-provider-service-it-$(openssl rand -hex 5)"
PASSWORD="$(openssl rand -hex 24)"
TOKEN="$(cat /proc/sys/kernel/random/uuid)"
STARTED=0
cleanup() {
  if [[ "$STARTED" == 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ $EUID -ne 0 ]] || { echo '[BLOQUEADO] No ejecutar como root.' >&2; exit 2; }
for bin in docker openssl mvn; do
  command -v "$bin" >/dev/null 2>&1 || { echo "[BLOQUEADO] Requiere $bin" >&2; exit 2; }
done
[[ -f "$ROOT/src/test/java/pe/gob/mtc/walletprovider/integration/MtcPortalServicePostgresIntegrationTest.java" ]] || {
  echo '[BLOQUEADO] Falta prueba de integracion Java.' >&2; exit 2;
}
[[ -f "$ROOT/src/test/java/pe/gob/mtc/walletprovider/integration/MtcPortalHttpSecurityPostgresIntegrationTest.java" ]] || {
  echo '[BLOQUEADO] Falta prueba HTTP/JWT de integración.' >&2; exit 2;
}
[[ -f "$ROOT/src/main/resources/db/migration/V7__mtc_mesa_partes_dual_control.sql" ]] || {
  echo '[BLOQUEADO] Falta migracion V7.' >&2; exit 2;
}
docker info >/dev/null 2>&1 || { echo '[BLOQUEADO] Docker no disponible.' >&2; exit 2; }
# No reemplazar una base o un servicio preexistentes del desarrollador.
if (echo > /dev/tcp/127.0.0.1/55432) >/dev/null 2>&1; then
  echo '[BLOQUEADO] El puerto local 55432 ya esta ocupado. No se tocara el servicio existente.' >&2
  exit 2
fi

echo '[1/4] Levantando PostgreSQL 16 efimero: puerto SOLO en 127.0.0.1:55432, sin volumenes.'
# La red se utiliza solo para que Maven/JDBC (host) conecte a la base descartable.
docker run --detach --rm --pull=never --name "$CONTAINER" \
  --publish '127.0.0.1:55432:5432' \
  --env "POSTGRES_USER=$DB" --env "POSTGRES_DB=$DB" --env "POSTGRES_PASSWORD=$PASSWORD" \
  --security-opt no-new-privileges "$IMAGE" >/dev/null
STARTED=1
READY=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" pg_isready -U "$DB" -d "$DB" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[ERROR] PostgreSQL aislado no respondio.' >&2; exit 1; }

echo '[2/4] Creando guardia en base desechable y esquema controlado.'
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$DB" -d "$DB" -c '
  CREATE SCHEMA wallet_provider;
  CREATE TABLE public.mtc_integration_test_guard (
      service_name text NOT NULL PRIMARY KEY,
      environment text NOT NULL,
      guard_token text NOT NULL
  );' >/dev/null
[[ "$TOKEN" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo '[BLOQUEADO] token de laboratorio inválido.' >&2; exit 2; }
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U "$DB" -d "$DB" \
  -c "INSERT INTO public.mtc_integration_test_guard (service_name, environment, guard_token)
      VALUES ('wallet-provider', 'LOCAL_INTEGRATION', '$TOKEN');" >/dev/null

echo '[3/4] Flyway V1..V7: transacciones Java, HTTP firmado, RBAC, concurrencia y Excel.'
# Guard de LabPostgresGuard.java valida DB+user+token antes de cualquier INSERT/Flyway.
(
  cd "$ROOT"
  WALLET_PG_IT=true \
  WALLET_PG_JDBC_URL="jdbc:postgresql://127.0.0.1:55432/$DB" \
  WALLET_PG_USER="$DB" \
  WALLET_PG_PASSWORD="$PASSWORD" \
  WALLET_PG_LAB_TOKEN="$TOKEN" \
  WALLET_PG_LAB_ACK='I_CONFIRM_DISPOSABLE_DB_ONLY' \
    mvn --batch-mode -Dtest=MtcPortalServicePostgresIntegrationTest,MtcPortalHttpSecurityPostgresIntegrationTest \
      -Dgpg.skip=true -Dmaven.javadoc.skip=true test
)
echo '[4/4] OK: integración Java/PostgreSQL y seguridad HTTP validada; limpiando contenedor.'
