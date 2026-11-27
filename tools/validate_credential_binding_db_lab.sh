#!/usr/bin/env bash
set -Eeuo pipefail

# ÚNICAMENTE PostgreSQL efímero en contenedor. No admite URLs ni DB remotas.
# No se montan directorios del host, no se publican puertos ni se abre red.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MIG_DIR="$PROVIDER_DIR/src/main/resources/db/migration"
SMOKE="$SCRIPT_DIR/sql/credential_binding_v5_smoke.sql"
IMAGE='postgres:16-alpine'
MIGRATIONS=(
  V1__initial.sql
  V2__diagnostics_key_sync.sql
  V3__holder_and_mtc_operators.sql
  V4__verifier_grants_and_imports.sql
  V5__credential_key_issuance_binding.sql
)

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo '[BLOQUEADO] No ejecutar como root.' >&2
  exit 2
fi
for bin in docker openssl; do
  command -v "$bin" >/dev/null || { echo "[BLOQUEADO] Falta $bin." >&2; exit 2; }
done
for name in "${MIGRATIONS[@]}"; do
  [[ -f "$MIG_DIR/$name" ]] || { echo "[BLOQUEADO] Falta migración: $name" >&2; exit 2; }
done
[[ -f "$SMOKE" ]] || { echo '[BLOQUEADO] Falta SQL de prueba V5.' >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo '[BLOQUEADO] Docker no está disponible.' >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "[BLOQUEADO] Imagen $IMAGE ausente. Obtenerla expresamente en un entorno autorizado." >&2
  echo "  docker pull $IMAGE" >&2
  exit 2
}

CONTAINER="mtc-wp-v5-lab-$(openssl rand -hex 6)"
PASSWORD="$(openssl rand -hex 24)"
CREATED=0
cleanup() {
  if [[ "$CREATED" == 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '[1/4] Iniciando PostgreSQL 16 exclusivo del laboratorio (sin red, puertos ni volúmenes).'
docker run --detach --rm --name "$CONTAINER" --pull never \
  --network none --env "POSTGRES_PASSWORD=$PASSWORD" "$IMAGE" >/dev/null
CREATED=1
unset PASSWORD
ready=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo '[ERROR] PostgreSQL temporal no responde.' >&2; exit 1; }

echo '[2/4] Creando base y esquema TEMPORALES dentro del contenedor.'
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c 'CREATE DATABASE wallet_provider_lab;' >/dev/null
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'CREATE SCHEMA wallet_provider;' >/dev/null

echo '[3/4] Aplicando V1 a V5 en el esquema wallet_provider.'
for name in "${MIGRATIONS[@]}"; do
  echo "  $name"
  docker cp "$MIG_DIR/$name" "$CONTAINER:/tmp/$name"
  # PGOPTIONS fija el search_path a nivel de sesión, también para DO y DDL.
  docker exec -e 'PGOPTIONS=-c search_path=wallet_provider,public' "$CONTAINER" \
    psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
    -f "/tmp/$name" >/dev/null
done

echo '[4/4] Verificando 22+ restricciones, accesos, revocaciones y expiración.'
docker cp "$SMOKE" "$CONTAINER:/tmp/credential_binding_v5_smoke.sql"
docker exec -e 'PGOPTIONS=-c search_path=wallet_provider,public' "$CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -f '/tmp/credential_binding_v5_smoke.sql'
echo '[OK] Migración V1–V5 y pruebas SQL V5 completadas en PostgreSQL 16 aislado.'
echo '[INFO] Contenedor y datos temporales eliminados automáticamente al finalizar.'
