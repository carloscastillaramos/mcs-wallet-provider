-- DATOS FICTICIOS EXCLUSIVOS DEL CONTENEDOR DE PRUEBAS.
DO $$
DECLARE
  super_id uuid := '00000000-0000-0000-0000-000000000001';
  mesa_id uuid := '00000000-0000-0000-0000-000000000002';
  ent_id uuid := '00000000-0000-0000-0000-000000000003';
  req_id uuid := '00000000-0000-0000-0000-000000000004';
  batch_id uuid := '00000000-0000-0000-0000-000000000005';
  got int;
  rejected boolean;
BEGIN
  -- Backfill: nunca conceder permiso de aprobar al rol antiguo de mesa.
  SELECT count(*) INTO got FROM wp_mtc_operator_role
  WHERE (operator_id=super_id AND role='SUPER_ADMIN')
     OR (operator_id=mesa_id AND role='MESA_PARTES_REGISTRADOR');
  IF got <> 2 THEN RAISE EXCEPTION 'V7: backfill de roles incorrecto (%).', got; END IF;
  SELECT count(*) INTO got FROM wp_mtc_operator_role
  WHERE operator_id=mesa_id AND role='MESA_PARTES_APROBADOR';
  IF got <> 0 THEN RAISE EXCEPTION 'V7: escalamiento accidental de privilegios.'; END IF;

  -- Asignacion acumulable de roles a una sola identidad.
  INSERT INTO wp_mtc_operator_role (operator_id,role)
  VALUES (mesa_id,'MESA_PARTES_APROBADOR');
  SELECT count(*) INTO got FROM wp_mtc_operator_role WHERE operator_id=mesa_id;
  IF got <> 2 THEN RAISE EXCEPTION 'V7: roles no acumulables.'; END IF;

  -- Rol no definido debe rechazarse.
  rejected := false;
  BEGIN
    INSERT INTO wp_mtc_operator_role (operator_id,role) VALUES (mesa_id,'ENTIDAD_EXTERNA');
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'V7: roles fuera de lista aceptados.'; END IF;

  -- El padrón efectivo no cambia con una solicitud PENDING.
  INSERT INTO wp_mtc_work_request
      (id,entity_id,action,resource_id,payload_cipher,requested_by,request_key)
  VALUES (req_id,ent_id,'GRANT_CREATE',NULL,decode(repeat('ab',29),'hex'),mesa_id,'laboratorio-v7-001');
  SELECT count(*) INTO got FROM wp_mtc_work_request
  WHERE id=req_id AND status='PENDING' AND decided_by IS NULL AND decided_at IS NULL;
  IF got <> 1 THEN RAISE EXCEPTION 'V7: pending incorrecto.'; END IF;
  SELECT count(*) INTO got FROM wp_verifier_grant WHERE entity_id=ent_id;
  -- No se insertan verificadores en el escenario de prueba.
  IF got <> 0 THEN RAISE EXCEPTION 'V7: alta efectiva inesperada.'; END IF;

  -- Aprobacion sin actor o sin fecha debe rechazarse.
  rejected := false;
  BEGIN
    UPDATE wp_mtc_work_request SET status='APPROVED' WHERE id=req_id;
  EXCEPTION WHEN check_violation THEN rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'V7: decision sin actor/fecha aceptada.'; END IF;

  -- Una decision completa se almacena de manera consistente.
  UPDATE wp_mtc_work_request
  SET status='APPROVED',decided_by=mesa_id,decided_at=clock_timestamp(),applied_resource_id='prueba'
  WHERE id=req_id;
  SELECT count(*) INTO got FROM wp_mtc_work_request
  WHERE id=req_id AND status='APPROVED' AND decided_by=mesa_id AND decided_at IS NOT NULL;
  IF got <> 1 THEN RAISE EXCEPTION 'V7: persistencia de decision fallida.'; END IF;

  -- Un lote Excel puede transicionar a REJECTED con sus nuevas columnas de auditoria.
  INSERT INTO wp_import_batch
      (id,entity_id,actor_issuer,actor_sub,mode,schema_version,file_hash,idempotency_key,status)
  VALUES (batch_id,ent_id,'https://issuer.invalid','mesa-lab','ALTA','1.0',
      decode(repeat('cd',32),'hex'),'laboratorio-v7-batch','VALIDATED');
  UPDATE wp_import_batch
  SET status='REJECTED',decided_by=mesa_id,decided_at=clock_timestamp(),
      decision_reason='Registro de prueba sin efectos externos'
  WHERE id=batch_id;
  SELECT count(*) INTO got FROM wp_import_batch
  WHERE id=batch_id AND status='REJECTED' AND decided_by=mesa_id
    AND decided_at IS NOT NULL;
  IF got <> 1 THEN RAISE EXCEPTION 'V7: rechazo de lote Excel fallido.'; END IF;

  RAISE NOTICE 'OK V7: backfill, roles acumulables, CHECK, pending, decision y lote Excel.';
END;
$$;
