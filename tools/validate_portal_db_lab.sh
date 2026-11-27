#!/usr/bin/env bash
set -Eeuo pipefail

# NO SE CONECTA A UNA BASE EXTERNA: PostgreSQL se inicia en un contenedor
# efimero sin red, sin puertos publicados y sin volumenes montados.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MIG_DIR="$PROVIDER_DIR/src/main/resources/db/migration"
SMOKE="$SCRIPT_DIR/sql/portal_v3_v4_smoke.sql"
IMAGE='postgres:16-alpine'

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo '[BLOQUEADO] No ejecutar este script como root.' >&2; exit 2
fi
for bin in docker openssl; do
  command -v "$bin" >/dev/null || { echo "[BLOQUEADO] Falta el comando: $bin" >&2; exit 2; }
done
for migration in V1__initial.sql V2__diagnostics_key_sync.sql V3__holder_and_mtc_operators.sql V4__verifier_grants_and_imports.sql; do
  [[ -f "$MIG_DIR/$migration" ]] || { echo "[BLOQUEADO] No existe $MIG_DIR/$migration" >&2; exit 2; }
done
[[ -f "$SMOKE" ]] || { echo "[BLOQUEADO] No existe $SMOKE" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo '[BLOQUEADO] Docker no esta disponible.' >&2; exit 2; }

CONTAINER="mtc-wp-lab-$(openssl rand -hex 6)"
PASSWORD="$(openssl rand -hex 24)"
STARTED=0
cleanup() {
  if [[ "$STARTED" == 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '[1/4] Creando PostgreSQL 16 temporal, sin red, sin puertos, sin volumenes.'
docker run --detach --rm --name "$CONTAINER" \
  --network none \
  --env "POSTGRES_PASSWORD=$PASSWORD" \
  "$IMAGE" >/dev/null
STARTED=1
unset PASSWORD

ready=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo '[ERROR] PostgreSQL temporal no inicia.' >&2; exit 1; }

echo '[2/4] Creando exclusivamente la base de datos temporal.'
docker exec "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c 'CREATE DATABASE wallet_provider_lab;' >/dev/null
docker exec "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'CREATE SCHEMA wallet_provider;' >/dev/null

echo '[3/4] Aplicando SQL V1 -> V4 en la base temporal.'
for migration in V1__initial.sql V2__diagnostics_key_sync.sql V3__holder_and_mtc_operators.sql V4__verifier_grants_and_imports.sql; do
  docker cp "$MIG_DIR/$migration" "$CONTAINER:/tmp/$migration"
  echo "  Ejecutando $migration"
  docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres \
    -d wallet_provider_lab \
    -c 'SET search_path TO wallet_provider, public;' \
    -f "/tmp/$migration" > /dev/null
done

echo '[4/4] Ejecutando pruebas reales de integridad de esquema y restricciones.'
docker cp "$SMOKE" "$CONTAINER:/tmp/portal_v3_v4_smoke.sql"
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres \
  -d wallet_provider_lab \
  -c 'SET search_path TO wallet_provider, public;' \
  -f '/tmp/portal_v3_v4_smoke.sql'
echo '[OK] V1 a V4 y restricciones de identidad/padron verificadas en PostgreSQL 16 aislado.'
echo '[INFO] El contenedor temporal se elimina automaticamente al finalizar.'
