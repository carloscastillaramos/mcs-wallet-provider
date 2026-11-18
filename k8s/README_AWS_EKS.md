# AWS EKS — Wallet Provider 0.3.0

**NO ejecutar los YAML sin reemplazar image digest, recursos de entorno y verificar el namespace.** Los servicios existentes Mimoto/Certify/Verify usan ClusterIP; Mimoto y Verify tienen sidecar Istio, Certify no. No modificar mTLS global ni políticas de Certify.

## Dependencias de despliegue

- PostgreSQL 16+ en RDS privado, conexión TLS verificable (`sslmode=verify-full`) y CA pública AWS montada en `/run/trust/rds/rds-global-bundle.pem`. `DB_URL` debe incluir `sslrootcert=/run/trust/rds/rds-global-bundle.pem`; no escribir host real en Git.
- Crear por DBA el esquema `wallet_provider`, instalar migraciones con rol DDL e historia `wallet_provider.flyway_schema_history`. En producción, ejecutar Flyway como Job autorizado y desplegar API con `SPRING_FLYWAY_ENABLED=false` y usuario DML limitado. En QA, la ejecución al arranque puede habilitarse con rol apropiado.
- ConfigMap `mcs-wallet-provider-settings`: `OIDC_ISSUER_URI`, `ATTESTATION_ISSUER`, `WALLET_CLIENT_ID`, `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`, `PLAY_CLOUD_PROJECT_NUMBER`, `IOS_APP_ID`, `IOS_APP_ATTEST_PRODUCTION`, `SIGNING_KEY_ID`, `SIGNING_KEY_ALIAS`; opcional `SPRING_FLYWAY_ENABLED`. **Los scopes OAuth2 de trust/revoke siguen exigiéndose en el código**. Istio no reemplaza automáticamente JWT.
- Secret `mcs-wallet-provider-db`: `jdbc-url`, `username`, `password`. Secret `mcs-wallet-provider-signing`: `signing.p12`, `password`.
- Secret `mcs-wallet-provider-google-adc`: `credentials.json` (preferir credencial de configuración para Google Workload Identity Federation con AWS en lugar de clave permanente, una vez acordada integración; el código usa Google ADC).
- ConfigMaps de raíces públicas verificados: `mcs-wallet-provider-android-roots`, `mcs-wallet-provider-apple-roots` con `roots.pem`; `aws-rds-ca-bundle` con `rds-global-bundle.pem`.
- IAM para ECR/secret manager y service account definidos por Infra AWS; solo `ClusterIP`. Publicación selectiva mediante Istio Gateway existente y TLS aprobado, según `istio-virtualservice.template.yaml`. No desplegar VirtualService sin completar placeholders.
- `sidecar.istio.io/inject=true` en este Deployment requiere verificar que el namespace participa de Istio y que las rutas hacia RDS, Google y certificados funcionan; no imponer STRICT universal.
- CloudWatch/OTEL: logs JSON/console en stdout; `LOG_FILE` opcional. Sin datos personales ni tokens en logs.
- Particiones iniciales: mes anterior + 18 meses futuros. Ejecutar `sql/maintenance/ensure_partitions.sql` mensualmente por DBA; monitorizar al menos 3 meses futuros antes de caducidad. Retención/archivado se aprueba antes de borrar datos.
- Hikari por pod: máximo 8 conexiones por defecto; capacidad RDS debe considerar todas las réplicas y servicios. Dos réplicas iniciales, tunear con carga real.

## Build / despliegue

`mvn -B -ntp clean verify` con JDK 21; `docker build -t <repositorio>:<tag> .` tras empaquetar. CI publica digest ECR y reemplaza la imagen placeholder; aplicar ServiceAccount, Service, Deployment y PDB según proceso institucional. No crear secretos en texto plano dentro del repo.

## Pruebas mínimas

Flyway sobre PostgreSQL real, Hibernate validate, prueba concurrencia `FOR UPDATE` para challenge/installation, firma y JWKS, Play Integrity y Apple App Attest con evidencias reales, telemetría CloudWatch, restricción de endpoints administrativos, pruning `EXPLAIN`, rotación de particiones y simulación de caída de DB.
