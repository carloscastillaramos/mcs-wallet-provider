#!/usr/bin/env bash
set -Eeuo pipefail

# Prueba de esquema PostgreSQL V1..V7 sin tocar servicios o bases existentes.
# Crea un contenedor efimero sin red, puertos publicados ni volumenes.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
MIG_DIR="$PROJECT_DIR/src/main/resources/db/migration"
SMOKE="$SCRIPT_DIR/sql/portal_v7_dual_control_smoke.sql"
IMAGE='postgres:16-alpine'

if (( EUID == 0 )); then
  echo '[BLOQUEADO] Ejecutar como usuario normal, no root.' >&2
  exit 2
fi
for bin in docker openssl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "[BLOQUEADO] Falta $bin" >&2; exit 2; }
done
[[ -f "$SMOKE" ]] || { echo "[BLOQUEADO] Falta $SMOKE" >&2; exit 2; }
for v in {1..7}; do
  files=( "$MIG_DIR/V${v}__"*.sql )
  [[ ${#files[@]} == 1 && -f ${files[0]} ]] || { echo "[BLOQUEADO] Debe existir una unica migracion V$v" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo '[BLOQUEADO] Docker no disponible.' >&2; exit 2; }

CONTAINER="mtc-v7-lab-$(openssl rand -hex 6)"
PASSWORD="$(openssl rand -hex 24)"
STARTED=0
cleanup() {
  if [[ $STARTED == 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo '[1/5] Iniciando PostgreSQL temporal aislado; nunca se publica un puerto.'
docker run --detach --rm --name "$CONTAINER" --network none \
  --env "POSTGRES_PASSWORD=$PASSWORD" "$IMAGE" >/dev/null
STARTED=1
unset PASSWORD
READY=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[ERROR] PostgreSQL temporal no responde.' >&2; exit 1; }

echo '[2/5] Creando base y esquema exclusivos del contenedor.'
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -c 'CREATE DATABASE wallet_provider_lab;' >/dev/null
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'CREATE SCHEMA wallet_provider;' >/dev/null

echo '[3/5] Aplicando migraciones V1 a V6 en orden.'
for v in {1..6}; do
  file=( "$MIG_DIR/V${v}__"*.sql )
  filename="$(basename -- "${file[0]}")"
  docker cp "${file[0]}" "$CONTAINER:/tmp/$filename"
  docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
    -c 'SET search_path TO wallet_provider, public;' -f "/tmp/$filename" >/dev/null
  echo "  OK $filename"
done

echo '[4/5] Preparando operadores historicos; aplicando V7 y backfill.'
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'SET search_path TO wallet_provider, public;' -c "
INSERT INTO wp_mtc_operator(id,issuer,subject,role,status)
VALUES ('00000000-0000-0000-0000-000000000001','https://issuer.invalid','admin-lab','SUPER_ADMIN','ACTIVE'),
       ('00000000-0000-0000-0000-000000000002','https://issuer.invalid','mesa-lab','MESA_DE_PARTES','ACTIVE');
INSERT INTO wp_entity(id,code,name,status)
VALUES ('00000000-0000-0000-0000-000000000003','LAB','Entidad ficticia de ensayo','ACTIVE');
" >/dev/null
file=( "$MIG_DIR/V7__"*.sql )
filename="$(basename -- "${file[0]}")"
docker cp "${file[0]}" "$CONTAINER:/tmp/$filename"
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'SET search_path TO wallet_provider, public;' -f "/tmp/$filename" >/dev/null

echo '[5/5] Comprobando roles, constraints, decision y lote Excel en PostgreSQL real.'
docker cp "$SMOKE" "$CONTAINER:/tmp/portal_v7_dual_control_smoke.sql"
docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 -U postgres -d wallet_provider_lab \
  -c 'SET search_path TO wallet_provider, public;' -f '/tmp/portal_v7_dual_control_smoke.sql'
echo '[OK] DDL V1..V7 y restricciones seleccionadas verificadas en PostgreSQL 16 aislado.'
echo '[ALCANCE] No comprueba OAuth/Cognito, transacciones de servicio Java, concurrencia ni flujos E2E.'
echo '[INFO] El contenedor se borra al finalizar, incluso cuando falla la prueba.'
