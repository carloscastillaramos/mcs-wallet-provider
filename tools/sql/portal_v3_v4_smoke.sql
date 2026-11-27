\set ON_ERROR_STOP on
\echo '[SMOKE] Validacion de estructura, FK y reglas de negocio en DB efimera'
BEGIN;
SET LOCAL search_path TO wallet_provider, public;

DO $check$
DECLARE
  expected text[] := ARRAY[
    'wp_challenge','wp_installation','wp_audit','wp_diagnostics_key','wp_diagnostics_outbox',
    'wp_holder','wp_identity_session','wp_installation_holder','wp_entity','wp_mtc_operator',
    'wp_verifier_grant','wp_verifier_installation','wp_import_batch','wp_import_row','wp_admin_audit'
  ];
  missing text;
BEGIN
  SELECT string_agg(x.name, ', ') INTO missing
    FROM unnest(expected) AS x(name)
   WHERE to_regclass('wallet_provider.' || x.name) IS NULL;
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'Faltan relaciones: %', missing;
  END IF;
  RAISE NOTICE 'OK: 15 relaciones base presentes (incluidas 10 nuevas V3/V4)';
END
$check$;

INSERT INTO wp_installation (id,platform,key_id,public_key,status,assurance,app_identifier,counter_value,created_at,updated_at)
VALUES ('10000000-0000-4000-8000-000000000001','ANDROID','lab-device-a','LAB-PUBLIC-KEY','ACTIVE','LAB','mtc.lab',0,now(),now()),
       ('10000000-0000-4000-8000-000000000002','ANDROID','lab-device-b','LAB-PUBLIC-KEY','ACTIVE','LAB','mtc.lab',0,now(),now());

INSERT INTO wp_holder (id,document_type,dni_hmac,dni_cipher,key_version,issuer,subject)
VALUES ('20000000-0000-4000-8000-000000000001','DNI',decode(repeat('01',32),'hex'),decode('cafebabe','hex'),1,'LAB_IDP','lab-subject');

INSERT INTO wp_identity_session (id,installation_id,nonce_hash,purpose,status,expires_at,consumed_at,evidence_digest)
VALUES ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001',decode(repeat('02',32),'hex'),'HOLDER_ENROLLMENT','COMPLETED',now()+interval '10 minutes',now(),decode(repeat('03',32),'hex')),
       ('30000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001',decode(repeat('04',32),'hex'),'HOLDER_ENROLLMENT','COMPLETED',now()+interval '10 minutes',now(),decode(repeat('05',32),'hex'));

INSERT INTO wp_installation_holder (installation_id,holder_id,identity_session_id,verified_at,status)
VALUES ('10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000001',now(),'ACTIVE');

INSERT INTO wp_entity (id,code,name,status,max_devices)
VALUES ('40000000-0000-4000-8000-000000000001','LAB','Entidad ficticia de laboratorio','ACTIVE',1);
INSERT INTO wp_mtc_operator (id,issuer,subject,role,status)
VALUES ('50000000-0000-4000-8000-000000000001','LAB_OIDC','lab-admin','SUPER_ADMIN','ACTIVE');

INSERT INTO wp_verifier_grant (id,entity_id,document_type,dni_hmac,dni_cipher,key_version,holder_id,profile,status,valid_from,valid_until)
VALUES ('60000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001','DNI',decode(repeat('01',32),'hex'),decode('cafebabe','hex'),1,'20000000-0000-4000-8000-000000000001','VERIFICADOR','ACTIVE',now()-interval '1 day',now()+interval '1 day');

INSERT INTO wp_verifier_installation (grant_id, installation_id, status)
VALUES ('60000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','ACTIVE');

DO $checks$
DECLARE
  rejected boolean;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM wp_verifier_installation vi JOIN wp_verifier_grant g ON g.id=vi.grant_id
                 JOIN wp_installation_holder ih ON ih.installation_id=vi.installation_id AND ih.holder_id=g.holder_id
                 WHERE vi.status='ACTIVE' AND ih.status='ACTIVE' AND g.status='ACTIVE') THEN
    RAISE EXCEPTION 'Fallo en vínculo positivo de identidad y permiso';
  END IF;
  RAISE NOTICE 'OK: titular e instalacion con permiso activo referenciados';

  rejected := false;
  BEGIN
    INSERT INTO wp_installation_holder(installation_id,holder_id,identity_session_id,verified_at,status)
    VALUES ('10000000-0000-4000-8000-000000000002','20000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000002',now(),'ACTIVE');
  EXCEPTION WHEN foreign_key_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto una sesion de identidad de otra instalacion'; END IF;
  RAISE NOTICE 'OK: sesion de identidad no permite cruce entre instalaciones';

  rejected := false;
  BEGIN
    INSERT INTO wp_identity_session (id, installation_id, nonce_hash,purpose,status,expires_at)
    VALUES ('30000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000002',decode(repeat('06',32),'hex'),'HOLDER_ENROLLMENT','COMPLETED',now()+interval '1 hour');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto COMPLETED sin evidencia y consumo'; END IF;
  RAISE NOTICE 'OK: COMPLETED exige evidencia y consumo';

  rejected := false;
  BEGIN
    INSERT INTO wp_holder(id,document_type,dni_hmac,dni_cipher,key_version,issuer)
    VALUES ('20000000-0000-4000-8000-000000000002','DNI',decode(repeat('01',32),'hex'),decode('cafebabe','hex'),1,'LAB_IDP');
  EXCEPTION WHEN unique_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto DNI protegido duplicado'; END IF;
  RAISE NOTICE 'OK: titular unico por documento/HMAC';

  rejected := false;
  BEGIN
    UPDATE wp_verifier_grant SET valid_until=valid_from WHERE id='60000000-0000-4000-8000-000000000001';
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto periodo sin vigencia'; END IF;
  RAISE NOTICE 'OK: grant requiere fechas consistentes';

  rejected := false;
  BEGIN
    UPDATE wp_verifier_installation SET status='REVOKED'
     WHERE grant_id='60000000-0000-4000-8000-000000000001';
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto revocacion sin timestamp'; END IF;
  RAISE NOTICE 'OK: vinculo revocado requiere revoked_at';

  rejected := false;
  BEGIN
    INSERT INTO wp_mtc_operator(id,issuer,subject,role,status)
    VALUES ('50000000-0000-4000-8000-000000000002','LAB_OIDC','lab-operator','EXTERNAL_ADMIN','ACTIVE');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto un rol externo no autorizado'; END IF;
  RAISE NOTICE 'OK: roles limitados al MTC';

  rejected := false;
  BEGIN
    INSERT INTO wp_mtc_operator(id,issuer,subject,role,status)
    VALUES ('50000000-0000-4000-8000-000000000003','LAB_OIDC','lab-admin','MESA_DE_PARTES','ACTIVE');
  EXCEPTION WHEN unique_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'Se acepto identidad administrativa duplicada'; END IF;
  RAISE NOTICE 'OK: operador Cognito unico por issuer/sub';
END
$checks$;

ROLLBACK;
\echo '[OK] Transaccion de datos ficticios revertida; sin datos de ejemplo persistidos.'
