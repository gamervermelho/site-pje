-- PJe Simulado: petição inicial em PDF, distribuição e situações processuais.
-- Executar depois do schema inicial e de pje_permissoes_sigilo_migration.sql.
BEGIN;

-- Advogados podem autuar novos processos mediante petição inicial.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
JOIN public.permissions p ON p.permission_key = 'cases.create'
WHERE LOWER(r.name) = 'advogado'
ON CONFLICT DO NOTHING;

-- Garante catálogo inicial de classes para os tribunais já cadastrados.
INSERT INTO public.case_classes (tribunal_id, name, code)
SELECT t.id, x.name, x.code
FROM public.tribunals t
CROSS JOIN (VALUES
  ('Procedimento Comum Cível', '7'),
  ('Mandado de Segurança', '120'),
  ('Ação Civil Pública', '65'),
  ('Ação Popular', '66'),
  ('Habeas Corpus', '307'),
  ('Reclamação', '123'),
  ('Ação Direta de Inconstitucionalidade', 'ADI'),
  ('Arguição de Descumprimento de Preceito Fundamental', 'ADPF'),
  ('Ação Declaratória de Constitucionalidade', 'ADC'),
  ('Agravo de Instrumento', '202'),
  ('Apelação', '198'),
  ('Execução Fiscal', '1116')
) AS x(name, code)
ON CONFLICT (tribunal_id, name) DO UPDATE
SET code = EXCLUDED.code, active = TRUE;

-- A data de distribuição só é preenchida pela função distribute_case.
CREATE OR REPLACE FUNCTION public.keep_case_undistributed_on_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.distribution_date := NULL;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_keep_case_undistributed_on_insert ON public.cases;
CREATE TRIGGER trg_keep_case_undistributed_on_insert
BEFORE INSERT ON public.cases
FOR EACH ROW EXECUTE FUNCTION public.keep_case_undistributed_on_insert();

-- Situações exibidas no acompanhamento processual.
ALTER TABLE public.cases DROP CONSTRAINT IF EXISTS cases_status_check;
ALTER TABLE public.cases DROP CONSTRAINT IF EXISTS cases_status_workflow_check;
ALTER TABLE public.cases ADD CONSTRAINT cases_status_workflow_check
CHECK (status IN (
  'em_cadastro', 'autuado', 'distribuido', 'em_tramite', 'ativo',
  'suspenso', 'arquivado', 'baixado', 'cancelado', 'transitado_em_julgado'
));

CREATE OR REPLACE FUNCTION public.is_case_workflow_server(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.cases c
    JOIN public.user_court_roles ucr ON ucr.tribunal_id = c.tribunal_id AND ucr.user_id = auth.uid()
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE c.id = p_case_id AND LOWER(r.name) = 'servidor'
  );
$$;

CREATE OR REPLACE FUNCTION public.can_manage_case_workflow(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.can_access_case(p_case_id) AND (public.is_platform_admin() OR public.is_case_workflow_server(p_case_id));
$$;

-- Registro transacional da petição inicial: habilita o advogado, grava o PDF,
-- registra a juntada e altera a situação para autuado.
CREATE OR REPLACE FUNCTION public.register_initial_petition(
  p_case_id UUID,
  p_storage_path TEXT,
  p_file_name TEXT,
  p_file_size BIGINT
)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_confidentiality TEXT;
  v_movement UUID;
  v_document UUID;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'É necessário estar autenticado.'; END IF;
  SELECT tribunal_id, confidentiality INTO v_tribunal, v_confidentiality
  FROM public.cases WHERE id = p_case_id AND created_by = auth.uid() AND class_id IS NOT NULL;
  IF v_tribunal IS NULL THEN RAISE EXCEPTION 'Processo não encontrado, não criado por você ou sem classe processual.'; END IF;
  IF NOT public.is_active_tribunal_lawyer(auth.uid(), v_tribunal) THEN
    RAISE EXCEPTION 'A petição inicial deve ser protocolada por advogado vinculado ao tribunal.';
  END IF;
  IF LOWER(COALESCE(p_file_name, '')) NOT LIKE '%.pdf' OR p_file_size IS NULL OR p_file_size <= 0 OR p_file_size > 20971520 THEN
    RAISE EXCEPTION 'Anexe um arquivo PDF válido de até 20 MB.';
  END IF;
  IF p_storage_path NOT LIKE ('initial/' || auth.uid()::text || '/%') THEN
    RAISE EXCEPTION 'Caminho de armazenamento inválido.';
  END IF;

  INSERT INTO public.case_lawyers (case_id, user_id, added_by, active)
  VALUES (p_case_id, auth.uid(), auth.uid(), TRUE)
  ON CONFLICT (case_id, user_id) DO UPDATE SET active = TRUE;

  INSERT INTO public.case_movements (case_id, movement_type, description, visibility, created_by)
  VALUES (
    p_case_id, 'Petição inicial', 'Petição inicial protocolada pelo advogado.',
    CASE WHEN v_confidentiality = 'sigiloso' THEN 'sigilosa' WHEN v_confidentiality = 'restrito' THEN 'restrita' ELSE 'publica' END,
    auth.uid()
  ) RETURNING id INTO v_movement;

  INSERT INTO public.case_documents (
    case_id, movement_id, title, document_type, file_name, storage_path,
    mime_type, file_size, visibility, uploaded_by
  ) VALUES (
    p_case_id, v_movement, 'Petição inicial', 'Petição inicial', p_file_name,
    p_storage_path, 'application/pdf', p_file_size,
    CASE WHEN v_confidentiality = 'sigiloso' THEN 'sigilosa' WHEN v_confidentiality = 'restrito' THEN 'restrita' ELSE 'publica' END,
    auth.uid()
  ) RETURNING id INTO v_document;

  UPDATE public.cases SET status = 'autuado', distribution_date = NULL, updated_at = NOW() WHERE id = p_case_id;
  INSERT INTO public.case_movements (case_id, movement_type, description, visibility, created_by)
  VALUES (p_case_id, 'Autuado', 'Processo autuado após o protocolo da petição inicial.',
    CASE WHEN v_confidentiality = 'sigiloso' THEN 'sigilosa' WHEN v_confidentiality = 'restrito' THEN 'restrita' ELSE 'publica' END,
    auth.uid());
  RETURN v_document;
END;
$$;

-- Distribuição: servidor do próprio tribunal registra unidade e magistrado.
CREATE OR REPLACE FUNCTION public.distribute_case(
  p_case_id UUID,
  p_assigned_user_id UUID,
  p_assigned_unit_id UUID,
  p_notes TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_confidentiality TEXT;
BEGIN
  SELECT tribunal_id, confidentiality INTO v_tribunal, v_confidentiality
  FROM public.cases WHERE id = p_case_id;
  IF v_tribunal IS NULL THEN RAISE EXCEPTION 'Processo não encontrado.'; END IF;
  IF NOT public.can_access_case(p_case_id) THEN RAISE EXCEPTION 'Você não possui autorização para acessar este processo.'; END IF;
  IF NOT (public.is_platform_admin() OR public.is_case_workflow_server(p_case_id)) THEN
    RAISE EXCEPTION 'Somente servidor do próprio tribunal pode distribuir este processo.';
  END IF;
  IF p_assigned_unit_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.court_units WHERE id = p_assigned_unit_id AND tribunal_id = v_tribunal AND active = TRUE
  ) THEN RAISE EXCEPTION 'A unidade selecionada não pertence ao tribunal do processo.'; END IF;
  IF p_assigned_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.user_court_roles ucr JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = p_assigned_user_id AND ucr.tribunal_id = v_tribunal
      AND LOWER(r.name) IN ('juiz','desembargador','ministro')
  ) THEN RAISE EXCEPTION 'O magistrado precisa estar vinculado ao mesmo tribunal.'; END IF;

  UPDATE public.cases SET
    unit_id = COALESCE(p_assigned_unit_id, unit_id),
    judge_id = COALESCE(p_assigned_user_id, judge_id),
    distribution_date = NOW(), status = 'distribuido', updated_at = NOW()
  WHERE id = p_case_id;

  INSERT INTO public.case_assignments (case_id, assigned_user_id, assigned_unit_id, assigned_by, assignment_type, notes)
  VALUES (p_case_id, p_assigned_user_id, p_assigned_unit_id, auth.uid(), 'distribuição', NULLIF(TRIM(COALESCE(p_notes,'')),''));

  INSERT INTO public.case_movements (case_id, movement_type, description, visibility, created_by)
  VALUES (p_case_id, 'Distribuído', 'Processo distribuído' ||
    CASE WHEN p_assigned_user_id IS NOT NULL THEN ' ao magistrado responsável' ELSE '' END ||
    CASE WHEN p_assigned_unit_id IS NOT NULL THEN ' e à unidade judicial selecionada.' ELSE '.' END,
    CASE WHEN v_confidentiality = 'sigiloso' THEN 'sigilosa' WHEN v_confidentiality = 'restrito' THEN 'restrita' ELSE 'publica' END,
    auth.uid());
END;
$$;

-- Situação administrativa: servidor do tribunal pode atualizar e gerar histórico.
CREATE OR REPLACE FUNCTION public.update_case_status(p_case_id UUID, p_status TEXT, p_notes TEXT DEFAULT NULL)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_confidentiality TEXT;
  v_label TEXT;
BEGIN
  SELECT tribunal_id, confidentiality INTO v_tribunal, v_confidentiality
  FROM public.cases WHERE id = p_case_id;
  IF v_tribunal IS NULL THEN RAISE EXCEPTION 'Processo não encontrado.'; END IF;
  IF NOT public.can_access_case(p_case_id) THEN RAISE EXCEPTION 'Você não possui autorização para acessar este processo.'; END IF;
  IF NOT (public.is_platform_admin() OR public.is_case_workflow_server(p_case_id)) THEN
    RAISE EXCEPTION 'Somente servidor do próprio tribunal pode alterar a situação processual.';
  END IF;
  IF p_status NOT IN ('autuado','distribuido','em_tramite','arquivado','transitado_em_julgado','suspenso','baixado','cancelado') THEN
    RAISE EXCEPTION 'Situação processual inválida.';
  END IF;
  v_label := CASE p_status
    WHEN 'autuado' THEN 'Autuado' WHEN 'distribuido' THEN 'Distribuído'
    WHEN 'em_tramite' THEN 'Em trâmite' WHEN 'arquivado' THEN 'Arquivado'
    WHEN 'transitado_em_julgado' THEN 'Transitado em julgado'
    WHEN 'suspenso' THEN 'Suspenso' WHEN 'baixado' THEN 'Baixado' WHEN 'cancelado' THEN 'Cancelado'
  END;
  UPDATE public.cases SET status = p_status, updated_at = NOW() WHERE id = p_case_id;
  INSERT INTO public.case_movements (case_id, movement_type, description, visibility, created_by)
  VALUES (p_case_id, v_label, COALESCE(NULLIF(TRIM(COALESCE(p_notes,'')),''), 'Situação processual atualizada para: ' || v_label || '.'),
    CASE WHEN v_confidentiality = 'sigiloso' THEN 'sigilosa' WHEN v_confidentiality = 'restrito' THEN 'restrita' ELSE 'publica' END,
    auth.uid());
END;
$$;


-- O servidor pode efetivar a distribuição e indicar o magistrado do mesmo tribunal.
CREATE OR REPLACE FUNCTION public.guard_case_sensitive_fields()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.tribunal_id IS DISTINCT FROM OLD.tribunal_id
       OR NEW.case_number IS DISTINCT FROM OLD.case_number THEN
      RAISE EXCEPTION 'O tribunal e a numeração CNJ do processo não podem ser alterados.';
    END IF;
    IF NEW.judge_id IS DISTINCT FROM OLD.judge_id
       AND NOT public.is_platform_admin()
       AND NOT public.is_case_magistrate(OLD.id)
       AND NOT public.is_case_workflow_server(OLD.id) THEN
      RAISE EXCEPTION 'Somente o magistrado responsável, servidor autorizado na distribuição ou administrador pode alterar a atribuição.';
    END IF;
    IF NEW.confidentiality IS DISTINCT FROM OLD.confidentiality
       AND NOT public.is_platform_admin()
       AND NOT public.is_case_magistrate(OLD.id) THEN
      RAISE EXCEPTION 'Somente o magistrado responsável pode alterar o nível de sigilo do processo.';
    END IF;
  END IF;
  IF NEW.judge_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = NEW.judge_id AND ucr.tribunal_id = NEW.tribunal_id
      AND LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
  ) THEN RAISE EXCEPTION 'O magistrado responsável precisa possuir vínculo ativo com o mesmo tribunal.'; END IF;
  IF NEW.confidentiality = 'sigiloso' AND NEW.judge_id IS NULL THEN
    RAISE EXCEPTION 'Processos em segredo de justiça precisam ter magistrado responsável definido.';
  END IF;
  RETURN NEW;
END;
$$;

-- Upload inicial só na pasta temporária própria do usuário; o registro do documento
-- no processo continua condicionado à validação da função register_initial_petition.
DROP POLICY IF EXISTS "Advogado envia petição inicial própria" ON storage.objects;
CREATE POLICY "Advogado envia petição inicial própria"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'pje-documentos'
  AND name LIKE ('initial/' || auth.uid()::text || '/%')
  AND EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = auth.uid() AND LOWER(r.name) = 'advogado'
  )
);


DROP POLICY IF EXISTS "Advogado remove upload inicial sem registro" ON storage.objects;
CREATE POLICY "Advogado remove upload inicial sem registro"
ON storage.objects FOR DELETE TO authenticated
USING (
  bucket_id = 'pje-documentos'
  AND name LIKE ('initial/' || auth.uid()::text || '/%')
  AND NOT EXISTS (SELECT 1 FROM public.case_documents d WHERE d.storage_path = storage.objects.name)
  AND EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = auth.uid() AND LOWER(r.name) = 'advogado'
  )
);

REVOKE ALL ON FUNCTION public.register_initial_petition(UUID,TEXT,TEXT,BIGINT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.register_initial_petition(UUID,TEXT,TEXT,BIGINT) TO authenticated;
REVOKE ALL ON FUNCTION public.distribute_case(UUID,UUID,UUID,TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.distribute_case(UUID,UUID,UUID,TEXT) TO authenticated;
REVOKE ALL ON FUNCTION public.update_case_status(UUID,TEXT,TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_case_status(UUID,TEXT,TEXT) TO authenticated;
REVOKE ALL ON FUNCTION public.is_case_workflow_server(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_case_workflow_server(UUID) TO authenticated;
REVOKE ALL ON FUNCTION public.can_manage_case_workflow(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.can_manage_case_workflow(UUID) TO authenticated;

COMMIT;
NOTIFY pgrst, 'reload schema';
