\set ON_ERROR_STOP on
\echo '[V5] Pruebas de esquema y autorización con datos TOTALMENTE ficticios'
BEGIN;
SET LOCAL search_path TO wallet_provider, public;

-- Las funciones sólo existen durante la sesión de laboratorio.
CREATE FUNCTION pg_temp.check_case(label text, ok boolean) RETURNS void
LANGUAGE plpgsql AS $test$
BEGIN
  IF ok IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'FALLO EN LAB: %', label;
  END IF;
  RAISE NOTICE 'OK: %', label;
END
$test$;

-- Refleja exactamente el predicado de autorización de
-- CredentialKeyBindingRegistry.activeAccreditedBinding; prueba BD, no HTTP/JWT.
CREATE FUNCTION pg_temp.authorized_binding(t text, n bytea) RETURNS boolean
LANGUAGE sql STABLE AS $query$
  SELECT EXISTS (
    SELECT 1 FROM wallet_provider.wp_credential_key_binding b
    JOIN wallet_provider.wp_installation i
      ON i.id=b.installation_id AND i.status='ACTIVE'
    JOIN wallet_provider.wp_installation_holder ih
      ON ih.installation_id=i.id AND ih.status='ACTIVE'
    JOIN wallet_provider.wp_identity_session s
      ON s.id=ih.identity_session_id AND s.installation_id=i.id
      AND s.status='COMPLETED' AND s.purpose='HOLDER_ENROLLMENT'
      AND s.consumed_at IS NOT NULL AND s.evidence_digest IS NOT NULL
    WHERE b.credential_key_thumbprint=t AND b.issuer_nonce_sha256=n
      AND b.expires_at>CURRENT_TIMESTAMP
  )
$query$;

SELECT pg_temp.check_case('01 tabla V5 existente',to_regclass('wallet_provider.wp_credential_key_binding') IS NOT NULL);
SELECT pg_temp.check_case('02 restriccion de unicidad', EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname='wp_credential_key_binding_nonce_key_uq'));
SELECT pg_temp.check_case('03 restriccion TTL', EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname='wp_credential_key_binding_ttl_ck'));
SELECT pg_temp.check_case('04 FK a instalacion', EXISTS (
    SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
    WHERE t.relname='wp_credential_key_binding' AND c.contype='f'));
SELECT pg_temp.check_case('05 indice por instalacion',to_regclass('wallet_provider.wp_credential_key_binding_installation_idx') IS NOT NULL);
SELECT pg_temp.check_case('06 indice por expiracion',to_regclass('wallet_provider.wp_credential_key_binding_expiry_idx') IS NOT NULL);

INSERT INTO wp_installation(id,platform,key_id,public_key,status,assurance,app_identifier,counter_value,created_at,updated_at)
VALUES ('10000000-0000-4000-8000-000000000001','ANDROID','lab-v5-a','LAB-KEY-A','ACTIVE','LAB','mtc.lab',0,now(),now()),
       ('10000000-0000-4000-8000-000000000002','ANDROID','lab-v5-b','LAB-KEY-B','ACTIVE','LAB','mtc.lab',0,now(),now());
INSERT INTO wp_holder(id,document_type,dni_hmac,dni_cipher,key_version,issuer,subject)
VALUES ('20000000-0000-4000-8000-000000000001','DNI',decode(repeat('a1',32),'hex'),decode('cafe','hex'),1,'LAB','lab-subject');
INSERT INTO wp_identity_session(id,installation_id,nonce_hash,purpose,status,expires_at,consumed_at,evidence_digest)
VALUES ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001',decode(repeat('b1',32),'hex'),'HOLDER_ENROLLMENT','COMPLETED',now()+interval '1 hour',now(),decode(repeat('c1',32),'hex'));
INSERT INTO wp_installation_holder(installation_id,holder_id,identity_session_id,verified_at,status)
VALUES ('10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000001',now(),'ACTIVE');

-- C: vinculo caducado con issued_at anterior; no viola expires_at > issued_at.
INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,issued_at,expires_at)
VALUES ('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001',repeat('A',43),decode(repeat('11',32),'hex'),now()-interval '1 minute',now()+interval '10 minutes'),
       ('40000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000002',repeat('B',43),decode(repeat('22',32),'hex'),now()-interval '1 minute',now()+interval '10 minutes'),
       ('40000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000001',repeat('C',43),decode(repeat('33',32),'hex'),now()-interval '2 hours',now()-interval '1 hour');

SELECT pg_temp.check_case('07 vinculo activo y acreditado PERMITIDO',pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));
SELECT pg_temp.check_case('08 nonce incorrecto DENEGADO',NOT pg_temp.authorized_binding(repeat('A',43),decode(repeat('22',32),'hex')));
SELECT pg_temp.check_case('09 clave incorrecta DENEGADA',NOT pg_temp.authorized_binding(repeat('B',43),decode(repeat('11',32),'hex')));
SELECT pg_temp.check_case('10 vinculo de instalacion no acreditada DENEGADO',NOT pg_temp.authorized_binding(repeat('B',43),decode(repeat('22',32),'hex')));
SELECT pg_temp.check_case('11 vinculo caducado DENEGADO',NOT pg_temp.authorized_binding(repeat('C',43),decode(repeat('33',32),'hex')));
SELECT pg_temp.check_case('12 clave desconocida DENEGADA',NOT pg_temp.authorized_binding(repeat('D',43),decode(repeat('11',32),'hex')));

UPDATE wp_installation SET status='REVOKED' WHERE id='10000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('13 instalacion revocada DENEGADA',NOT pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));
UPDATE wp_installation SET status='ACTIVE' WHERE id='10000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('14 rehabilitacion controlada vuelve a consulta positiva',pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));

UPDATE wp_installation_holder SET status='BLOCKED' WHERE installation_id='10000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('15 asociacion bloqueada DENEGADA',NOT pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));
UPDATE wp_installation_holder SET status='ACTIVE' WHERE installation_id='10000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('16 asociacion activa RESTAURA elegibilidad',pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));

UPDATE wp_identity_session SET status='FAILED' WHERE id='30000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('17 sesion fallida DENEGADA',NOT pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));
UPDATE wp_identity_session SET status='COMPLETED' WHERE id='30000000-0000-4000-8000-000000000001';
SELECT pg_temp.check_case('18 sesion completada RESTAURA elegibilidad',pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));

DO $negative$
DECLARE rejected boolean;
BEGIN
  rejected := false;
  BEGIN
    INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,expires_at)
    VALUES ('40000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000001','MAL',decode(repeat('44',32),'hex'),now()+interval '10 min');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('19 huella con longitud invalida RECHAZADA',rejected);

  rejected := false;
  BEGIN
    INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,expires_at)
    VALUES ('40000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000001',repeat('E',43),decode('dead','hex'),now()+interval '10 min');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('20 digest nonce no-SHA256 RECHAZADO',rejected);

  rejected := false;
  BEGIN
    INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,expires_at)
    VALUES ('40000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000001',repeat('F',43),decode(repeat('55',32),'hex'),now()-interval '1 min');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('21 expiracion anterior a creacion RECHAZADA',rejected);

  rejected := false;
  BEGIN
    INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,expires_at)
    VALUES ('40000000-0000-4000-8000-000000000007','10000000-0000-4000-8000-000000000099',repeat('G',43),decode(repeat('66',32),'hex'),now()+interval '10 min');
  EXCEPTION WHEN foreign_key_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('22 instalacion inexistente RECHAZADA',rejected);

  rejected := false;
  BEGIN
    INSERT INTO wp_credential_key_binding(id,installation_id,credential_key_thumbprint,issuer_nonce_sha256,expires_at)
    VALUES ('40000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000002',repeat('A',43),decode(repeat('11',32),'hex'),now()+interval '10 min');
  EXCEPTION WHEN unique_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('23 replay de clave+nonce RECHAZADO',rejected);

  rejected := false;
  BEGIN
    UPDATE wp_identity_session SET evidence_digest=NULL WHERE id='30000000-0000-4000-8000-000000000001';
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('24 COMPLETED sin evidencia RECHAZADO',rejected);

  rejected := false;
  BEGIN
    INSERT INTO wp_installation_holder(installation_id,holder_id,identity_session_id,verified_at,status)
    VALUES ('10000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000001',now(),'ACTIVE');
  EXCEPTION WHEN unique_violation OR foreign_key_violation THEN rejected := true;
  END;
  PERFORM pg_temp.check_case('25 sesion ajena/reutilizada RECHAZADA',rejected);
END
$negative$;

SELECT pg_temp.check_case('26 ningun valor de DNI literal almacenado en binding',NOT EXISTS (
  SELECT 1 FROM information_schema.columns
   WHERE table_schema='wallet_provider' AND table_name='wp_credential_key_binding'
     AND column_name IN ('dni','document_number','dni_cipher','access_token','nonce_plain')));
SELECT pg_temp.check_case('27 sesion activa no depende de datos ficticios externos',pg_temp.authorized_binding(repeat('A',43),decode(repeat('11',32),'hex')));

ROLLBACK;
\echo '[OK] Pruebas V5 finalizadas; cambios de datos de laboratorio revertidos.'
