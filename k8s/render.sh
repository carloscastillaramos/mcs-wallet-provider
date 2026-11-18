#!/usr/bin/env bash
# Renderización fail-closed. NO escribir la salida si contiene datos sensibles.
set -euo pipefail
if ! command -v envsubst >/dev/null 2>&1; then
  echo 'Se requiere envsubst (gettext-base).' >&2; exit 2
fi
required=(IMAGE_REF OIDC_ISSUER_URI ATTESTATION_ISSUER WALLET_CLIENT_ID ANDROID_PACKAGE ANDROID_CERT_SHA256 PLAY_CLOUD_PROJECT_NUMBER IOS_APP_ID IOS_APP_ATTEST_PRODUCTION SIGNING_KEY_ID SIGNING_KEY_ALIAS)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then echo "Falta variable: $name" >&2; exit 2; fi
  if [[ "${!name}" == *'"'* || "${!name}" == *'\'* || "${!name}" == *$'\n'* || "${!name}" == *$'\r'* || "${!name}" == *'$('* || "${!name}" == *'`'* ]]; then
    echo "Variable con caracteres no permitidos: $name" >&2; exit 2
  fi
done
# No permitir tags mutables ni imágenes públicas, solo ECR y digest SHA-256.
if [[ ! "$IMAGE_REF" =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9_./-]+@sha256:[a-f0-9]{64}$ ]]; then
  echo 'IMAGE_REF debe ser una imagen privada ECR fijada por digest SHA-256.' >&2; exit 2
fi
# Nunca activar sincronizacion sin ambos endpoints autorizados.
: "${WALLET_DIAG_SYNC_ENABLED:=false}"
: "${WALLET_DIAG_SYNC_BASE_URL:=}"
: "${WALLET_DIAG_SYNC_TOKEN_URL:=}"
if [[ "$WALLET_DIAG_SYNC_ENABLED" != 'true' && "$WALLET_DIAG_SYNC_ENABLED" != 'false' ]]; then
  echo 'WALLET_DIAG_SYNC_ENABLED debe ser true/false' >&2; exit 2
fi
if [[ "$WALLET_DIAG_SYNC_ENABLED" == 'true' ]]; then
  [[ "$WALLET_DIAG_SYNC_BASE_URL" == https://* && "$WALLET_DIAG_SYNC_TOKEN_URL" == https://* ]] || {
    echo 'La sincronizacion requiere URLs HTTPS aprobadas' >&2; exit 2; }
fi
if [[ "${MTC_RENDER_PUBLIC_INGRESS:-false}" == 'true' ]]; then
  for name in INGRESS_CLASS PUBLIC_HOST TLS_SECRET_NAME; do
    [[ -n "${!name:-}" ]] || { echo "Falta variable de ingress: $name" >&2; exit 2; }
  done
  [[ "$PUBLIC_HOST" == *.* && "$PUBLIC_HOST" != *' '* ]] || { echo 'PUBLIC_HOST invalido' >&2; exit 2; }
fi
export WALLET_DIAG_SYNC_ENABLED WALLET_DIAG_SYNC_BASE_URL WALLET_DIAG_SYNC_TOKEN_URL
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template_vars='${IMAGE_REF} ${OIDC_ISSUER_URI} ${ATTESTATION_ISSUER} ${WALLET_CLIENT_ID} ${ANDROID_PACKAGE} ${ANDROID_CERT_SHA256} ${PLAY_CLOUD_PROJECT_NUMBER} ${IOS_APP_ID} ${IOS_APP_ATTEST_PRODUCTION} ${SIGNING_KEY_ID} ${SIGNING_KEY_ALIAS} ${INGRESS_CLASS} ${PUBLIC_HOST} ${TLS_SECRET_NAME} ${WALLET_DIAG_SYNC_ENABLED} ${WALLET_DIAG_SYNC_BASE_URL} ${WALLET_DIAG_SYNC_TOKEN_URL}'
for manifest in configmap.yaml deployment.yaml; do
  echo '---'
  envsubst "$template_vars" < "$script_dir/$manifest"
done
if [[ "${MTC_RENDER_PUBLIC_INGRESS:-false}" == 'true' ]]; then
  echo '---'
  envsubst "$template_vars" < "$script_dir/ingress.yaml"
fi
