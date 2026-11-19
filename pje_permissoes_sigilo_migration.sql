-- PJe Simulado - Permissões por ato, vínculo de magistrado e segredo de justiça
-- Executar no Supabase SQL Editor depois do banco inicial.

BEGIN;

-- 1) Permissões granulares.
INSERT INTO public.permissions (permission_key, description)
VALUES
  ('cases.manage_access', 'Conceder e revogar acesso individual a processo sigiloso'),
  ('cases.manage_lawyers', 'Vincular advogados habilitados a processos'),
  ('petitions.interlocutory', 'Protocolar petições interlocutórias em processos nos quais o advogado esteja habilitado'),
  ('movements.judicial', 'Publicar atos judiciais em processos sob responsabilidade do magistrado'),
  ('movements.administrative', 'Registrar expedientes e atos administrativos do tribunal')
ON CONFLICT (permission_key) DO NOTHING;

-- Corrige o seed anterior que comparava "administrador" com "Administrador".
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE LOWER(r.name) = 'administrador'
ON CONFLICT DO NOTHING;

-- Advogados podem consultar processos públicos do tribunal e protocolar petições
-- somente quando estiverem formalmente habilitados no processo.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
JOIN public.permissions p ON p.permission_key IN (
  'cases.view', 'petitions.interlocutory'
)
WHERE LOWER(r.name) = 'advogado'
ON CONFLICT DO NOTHING;

-- Magistrados recebem poderes de decisão e gestão de acesso, mas a função abaixo
-- exige também que sejam o magistrado especificamente vinculado ao processo.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
JOIN public.permissions p ON p.permission_key IN (
  'cases.view', 'cases.edit', 'cases.manage_access',
  'cases.restricted.view', 'movements.judicial', 'movements.administrative', 'documents.upload'
)
WHERE LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
ON CONFLICT DO NOTHING;

-- Servidores atuam apenas no próprio tribunal e não recebem permissão judicial.
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
JOIN public.permissions p ON p.permission_key IN (
  'cases.create', 'cases.view', 'cases.edit', 'cases.restricted.view',
  'movements.administrative', 'documents.upload'
)
WHERE LOWER(r.name) = 'servidor'
ON CONFLICT DO NOTHING;

-- 2) Advogados habilitados em cada processo.
CREATE TABLE IF NOT EXISTS public.case_lawyers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  party_id UUID REFERENCES public.parties(id) ON DELETE SET NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  added_by UUID NOT NULL REFERENCES public.profiles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (case_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_case_lawyers_user ON public.case_lawyers(user_id, active);
ALTER TABLE public.case_lawyers ENABLE ROW LEVEL SECURITY;

-- 3) Autorizações individuais para processos sigilosos.
CREATE TABLE IF NOT EXISTS public.case_access_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  granted_by UUID NOT NULL REFERENCES public.profiles(id),
  reason TEXT,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  UNIQUE (case_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_case_access_grants_user
  ON public.case_access_grants(user_id, case_id)
  WHERE revoked_at IS NULL;
ALTER TABLE public.case_access_grants ENABLE ROW LEVEL SECURITY;

-- 4) Funções de autorização. SECURITY DEFINER permite consultar as relações
-- internas sem abrir as tabelas ao usuário final.
CREATE OR REPLACE FUNCTION public.is_case_magistrate(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.cases c
    JOIN public.user_court_roles ucr
      ON ucr.user_id = auth.uid()
     AND ucr.tribunal_id = c.tribunal_id
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles prof ON prof.id = ucr.user_id AND prof.active = TRUE
    WHERE c.id = p_case_id
      AND c.judge_id = auth.uid()
      AND LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
  );
$$;

CREATE OR REPLACE FUNCTION public.can_access_case(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.cases c
    WHERE c.id = p_case_id
      AND CASE c.confidentiality
        WHEN 'publico' THEN TRUE
        WHEN 'restrito' THEN
          public.has_tribunal_permission(c.tribunal_id, 'cases.view')
          AND public.has_tribunal_permission(c.tribunal_id, 'cases.restricted.view')
        WHEN 'sigiloso' THEN
          public.is_case_magistrate(c.id)
          OR EXISTS (
            SELECT 1
            FROM public.case_access_grants g
            JOIN public.profiles p ON p.id = g.user_id AND p.active = TRUE
            WHERE g.case_id = c.id
              AND g.user_id = auth.uid()
              AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
          )
        ELSE FALSE
      END
  );
$$;

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
       AND NOT public.is_case_magistrate(OLD.id) THEN
      RAISE EXCEPTION 'Somente o magistrado responsável ou o administrador da plataforma pode alterar a atribuição do processo.';
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
    WHERE ucr.user_id = NEW.judge_id
      AND ucr.tribunal_id = NEW.tribunal_id
      AND LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
  ) THEN
    RAISE EXCEPTION 'O magistrado responsável precisa possuir vínculo ativo com o mesmo tribunal.';
  END IF;

  IF NEW.confidentiality = 'sigiloso' AND NEW.judge_id IS NULL THEN
    RAISE EXCEPTION 'Processos em segredo de justiça precisam ter magistrado responsável definido.';
  END IF;

  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_guard_case_sensitive_fields ON public.cases;
CREATE TRIGGER trg_guard_case_sensitive_fields
BEFORE INSERT OR UPDATE ON public.cases
FOR EACH ROW EXECUTE FUNCTION public.guard_case_sensitive_fields();

-- 5) Somente o magistrado responsável pode conceder ou revogar acesso sigiloso.
CREATE OR REPLACE FUNCTION public.guard_case_access_grant()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_confidentiality TEXT;
  v_is_member BOOLEAN;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF NOT public.is_case_magistrate(OLD.case_id) THEN
      RAISE EXCEPTION 'Somente o magistrado responsável pode revogar acessos deste processo.';
    END IF;
    RETURN OLD;
  END IF;

  IF NOT public.is_case_magistrate(NEW.case_id) THEN
    RAISE EXCEPTION 'Somente o magistrado responsável pode administrar os acessos deste processo.';
  END IF;

  SELECT tribunal_id, confidentiality INTO v_tribunal, v_confidentiality
  FROM public.cases WHERE id = NEW.case_id;
  IF v_confidentiality <> 'sigiloso' THEN
    RAISE EXCEPTION 'A concessão individual de acesso é exclusiva dos processos em segredo de justiça.';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.case_id IS DISTINCT FROM OLD.case_id OR NEW.user_id IS DISTINCT FROM OLD.user_id) THEN
    RAISE EXCEPTION 'Não é permitido trocar o processo ou o usuário de uma concessão existente.';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = NEW.user_id AND ucr.tribunal_id = v_tribunal
  ) INTO v_is_member;

  IF NOT v_is_member THEN
    RAISE EXCEPTION 'O usuário autorizado precisa possuir vínculo ativo com o mesmo tribunal.';
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.granted_by := auth.uid();
    NEW.granted_at := NOW();
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_guard_case_access_grant ON public.case_access_grants;
CREATE TRIGGER trg_guard_case_access_grant
BEFORE INSERT OR UPDATE OR DELETE ON public.case_access_grants
FOR EACH ROW EXECUTE FUNCTION public.guard_case_access_grant();

-- 6) Um advogado só pode protocolar petição interlocutória se estiver habilitado.
CREATE OR REPLACE FUNCTION public.can_edit_case(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
BEGIN
  IF NOT public.can_access_case(p_case_id) THEN RETURN FALSE; END IF;
  IF public.is_platform_admin() OR public.is_case_magistrate(p_case_id) THEN RETURN TRUE; END IF;
  SELECT tribunal_id INTO v_tribunal FROM public.cases WHERE id = p_case_id;
  RETURN EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = auth.uid() AND ucr.tribunal_id = v_tribunal
      AND LOWER(r.name) = 'servidor'
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.can_access_case_content(
  p_case_id UUID,
  p_visibility TEXT
)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.cases c
    WHERE c.id = p_case_id
      AND public.can_access_case(c.id)
      AND CASE p_visibility
        WHEN 'publica' THEN TRUE
        WHEN 'restrita' THEN
          CASE WHEN c.confidentiality = 'sigiloso' THEN TRUE
               ELSE public.has_tribunal_permission(c.tribunal_id, 'cases.restricted.view') END
        WHEN 'sigilosa' THEN
          CASE WHEN c.confidentiality = 'sigiloso' THEN TRUE
               ELSE public.has_tribunal_permission(c.tribunal_id, 'cases.confidential.view') END
        ELSE FALSE
      END
  );
$$;

CREATE OR REPLACE FUNCTION public.can_file_interlocutory_petition(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.cases c
    JOIN public.case_lawyers cl ON cl.case_id = c.id
      AND cl.user_id = auth.uid() AND cl.active = TRUE
    JOIN public.user_court_roles ucr ON ucr.user_id = auth.uid()
      AND ucr.tribunal_id = c.tribunal_id
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE c.id = p_case_id AND LOWER(r.name) = 'advogado'
  );
$$;

-- 7) Regras para atos processuais. Magistrado responsável pode publicar atos
-- judiciais. Servidor pode registrar expedientes administrativos no próprio
-- tribunal, mas nunca sentença, decisão, despacho ou acórdão.
CREATE OR REPLACE FUNCTION public.can_create_case_movement(
  p_case_id UUID,
  p_movement_type TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_type TEXT := LOWER(TRIM(COALESCE(p_movement_type, '')));
BEGIN
  SELECT tribunal_id INTO v_tribunal FROM public.cases WHERE id = p_case_id;
  IF v_tribunal IS NULL THEN RETURN FALSE; END IF;

  IF v_type IN ('petição interlocutória', 'peticao interlocutoria', 'peticao_interlocutoria') THEN
    RETURN public.can_file_interlocutory_petition(p_case_id);
  END IF;

  IF v_type IN ('despacho', 'decisão', 'decisao', 'sentença', 'sentenca', 'acórdão', 'acordao', 'voto') THEN
    RETURN public.is_case_magistrate(p_case_id)
      AND public.has_tribunal_permission(v_tribunal, 'movements.judicial');
  END IF;

  IF v_type IN (
    'intimação', 'intimacao', 'ofício', 'oficio', 'certidão', 'certidao',
    'juntada', 'expediente', 'publicação', 'publicacao', 'remessa',
    'conclusão', 'conclusao', 'distribuição', 'distribuicao'
  ) THEN
    RETURN public.has_tribunal_permission(v_tribunal, 'movements.administrative')
      OR public.is_case_magistrate(p_case_id);
  END IF;

  -- Tipos não catalogados não podem ser usados para contornar as regras.
  RETURN FALSE;
END;
$$;

-- Edição de processo: servidor atua no próprio tribunal; magistrado apenas no
-- processo atribuído a ele. A autorização nunca abre processo sigiloso por cargo.
DROP POLICY IF EXISTS "Editar processos autorizados" ON public.cases;
CREATE POLICY "Editar processos autorizados"
ON public.cases FOR UPDATE TO authenticated
USING (public.can_edit_case(id))
WITH CHECK (public.can_edit_case(id));

DROP POLICY IF EXISTS "Vincular partes autorizadas" ON public.case_parties;
CREATE POLICY "Vincular partes autorizadas"
ON public.case_parties FOR INSERT TO authenticated
WITH CHECK (public.can_edit_case(case_id));

DROP POLICY IF EXISTS "Vincular assuntos autorizados" ON public.case_subject_links;
CREATE POLICY "Vincular assuntos autorizados"
ON public.case_subject_links FOR INSERT TO authenticated
WITH CHECK (public.can_edit_case(case_id));

DROP POLICY IF EXISTS "Criar distribuições autorizadas" ON public.case_assignments;
CREATE POLICY "Criar distribuições autorizadas"
ON public.case_assignments FOR INSERT TO authenticated
WITH CHECK (assigned_by = auth.uid() AND public.can_edit_case(case_id));

DROP POLICY IF EXISTS "Consultar distribuições autorizadas" ON public.case_assignments;
CREATE POLICY "Consultar distribuições autorizadas"
ON public.case_assignments FOR SELECT TO authenticated
USING (public.can_access_case(case_id) AND (
  public.is_platform_admin()
  OR EXISTS (SELECT 1 FROM public.cases c WHERE c.id = case_id
    AND public.has_tribunal_permission(c.tribunal_id, 'cases.view'))
));

-- 8) RLS: acesso ao processo sigiloso não decorre de cargo genérico no tribunal.
DROP POLICY IF EXISTS "Consultar processos públicos ou autorizados" ON public.cases;
CREATE POLICY "Consultar processos públicos ou autorizados"
ON public.cases FOR SELECT TO anon, authenticated
USING ((confidentiality = 'publico' AND status <> 'cancelado') OR public.can_access_case(id));

-- Dados de partes e vínculos seguem exatamente o acesso ao processo.
DROP POLICY IF EXISTS "Consultar partes com autorização" ON public.parties;
CREATE POLICY "Consultar partes com autorização"
ON public.parties FOR SELECT TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.case_parties cp
    WHERE cp.party_id = parties.id AND public.can_access_case(cp.case_id)
  )
);

DROP POLICY IF EXISTS "Consultar partes vinculadas autorizadas" ON public.case_parties;
CREATE POLICY "Consultar partes vinculadas autorizadas"
ON public.case_parties FOR SELECT TO authenticated
USING (public.can_access_case(case_id));

DROP POLICY IF EXISTS "Consultar assuntos de processos autorizados" ON public.case_subject_links;
CREATE POLICY "Consultar assuntos de processos autorizados"
ON public.case_subject_links FOR SELECT TO anon, authenticated
USING (public.can_access_case(case_id));

-- Movimentações: atos só aparecem a quem pode consultar o processo.
DROP POLICY IF EXISTS "Consultar movimentações autorizadas" ON public.case_movements;
CREATE POLICY "Consultar movimentações autorizadas"
ON public.case_movements FOR SELECT TO anon, authenticated
USING (public.can_access_case_content(case_id, visibility));

DROP POLICY IF EXISTS "Criar movimentações autorizadas" ON public.case_movements;
CREATE POLICY "Criar movimentações autorizadas"
ON public.case_movements FOR INSERT TO authenticated
WITH CHECK (
  created_by = auth.uid()
  AND public.can_create_case_movement(case_id, movement_type)
  AND public.can_access_case(case_id)
);

CREATE OR REPLACE FUNCTION public.can_upload_case_document(
  p_case_id UUID,
  p_document_type TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_type TEXT := LOWER(TRIM(COALESCE(p_document_type, '')));
BEGIN
  SELECT tribunal_id INTO v_tribunal FROM public.cases WHERE id = p_case_id;
  IF v_tribunal IS NULL OR NOT public.can_access_case(p_case_id) THEN RETURN FALSE; END IF;

  IF v_type IN ('petição interlocutória', 'peticao interlocutoria', 'peticao_interlocutoria') THEN
    RETURN public.can_file_interlocutory_petition(p_case_id);
  END IF;

  RETURN public.is_case_magistrate(p_case_id)
    OR EXISTS (
      SELECT 1 FROM public.user_court_roles ucr
      JOIN public.roles r ON r.id = ucr.role_id
      JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
      WHERE ucr.user_id = auth.uid() AND ucr.tribunal_id = v_tribunal
        AND LOWER(r.name) = 'servidor'
    );
END;
$$;

-- 9) Documentos: uma peça marcada pública pode ser consultada isoladamente,
-- mesmo quando o processo principal é sigiloso. Os demais arquivos continuam
-- protegidos pelo acesso ao processo e pelo nível de visibilidade.
DROP POLICY IF EXISTS "Consultar documentos autorizados" ON public.case_documents;
CREATE POLICY "Consultar documentos autorizados"
ON public.case_documents FOR SELECT TO anon, authenticated
USING (
  visibility = 'publica'
  OR public.can_access_case_content(case_id, visibility)
);

DROP POLICY IF EXISTS "Registrar documentos autorizados" ON public.case_documents;
CREATE POLICY "Registrar documentos autorizados"
ON public.case_documents FOR INSERT TO authenticated
WITH CHECK (
  uploaded_by = auth.uid()
  AND public.can_upload_case_document(case_id, document_type)
);

CREATE OR REPLACE FUNCTION public.is_active_tribunal_lawyer(
  p_user_id UUID,
  p_tribunal_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = p_user_id
      AND ucr.tribunal_id = p_tribunal_id
      AND LOWER(r.name) = 'advogado'
  );
$$;

CREATE OR REPLACE FUNCTION public.can_manage_case_document(p_case_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_tribunal UUID;
  v_confidentiality TEXT;
BEGIN
  SELECT tribunal_id, confidentiality INTO v_tribunal, v_confidentiality
  FROM public.cases WHERE id = p_case_id;
  IF v_tribunal IS NULL THEN RETURN FALSE; END IF;
  IF public.is_case_magistrate(p_case_id) THEN RETURN TRUE; END IF;
  IF v_confidentiality = 'sigiloso' THEN RETURN FALSE; END IF;
  IF public.is_platform_admin() THEN RETURN TRUE; END IF;
  RETURN EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
    WHERE ucr.user_id = auth.uid() AND ucr.tribunal_id = v_tribunal
      AND LOWER(r.name) = 'servidor'
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.guard_case_document_visibility()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_confidentiality TEXT;
BEGIN
  SELECT confidentiality INTO v_confidentiality
  FROM public.cases WHERE id = NEW.case_id;

  IF v_confidentiality = 'sigiloso' AND NEW.visibility = 'publica'
     AND NOT public.is_case_magistrate(NEW.case_id) THEN
    RAISE EXCEPTION 'Somente o magistrado responsável pode liberar um documento de processo sigiloso para consulta pública.';
  END IF;

  IF TG_OP = 'UPDATE' AND NEW.visibility IS DISTINCT FROM OLD.visibility THEN
    IF v_confidentiality = 'sigiloso' AND NOT public.is_case_magistrate(NEW.case_id) THEN
      RAISE EXCEPTION 'Somente o magistrado responsável pode liberar ou restringir documentos de processo sigiloso.';
    END IF;
    IF v_confidentiality <> 'sigiloso' AND NOT public.can_manage_case_document(NEW.case_id) THEN
      RAISE EXCEPTION 'Você não possui autorização para alterar a visibilidade deste documento.';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_guard_case_document_visibility ON public.case_documents;
CREATE TRIGGER trg_guard_case_document_visibility
BEFORE INSERT OR UPDATE ON public.case_documents
FOR EACH ROW EXECUTE FUNCTION public.guard_case_document_visibility();

DROP POLICY IF EXISTS "Gerenciar visibilidade de documentos" ON public.case_documents;
CREATE POLICY "Gerenciar visibilidade de documentos"
ON public.case_documents FOR UPDATE TO authenticated
USING (public.can_manage_case_document(case_id))
WITH CHECK (public.can_manage_case_document(case_id));

-- Só o magistrado responsável ou servidor autorizado do tribunal pode habilitar
-- advogado no processo. O próprio advogado não pode se auto-habilitar.
DROP POLICY IF EXISTS "Consultar advogados habilitados" ON public.case_lawyers;
CREATE POLICY "Consultar advogados habilitados"
ON public.case_lawyers FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_case_magistrate(case_id) OR EXISTS (
  SELECT 1 FROM public.cases c WHERE c.id = case_id
    AND public.is_platform_admin()
));

DROP POLICY IF EXISTS "Habilitar advogado no processo" ON public.case_lawyers;
CREATE POLICY "Habilitar advogado no processo"
ON public.case_lawyers FOR INSERT TO authenticated
WITH CHECK (
  added_by = auth.uid()
  AND EXISTS (
    SELECT 1 FROM public.cases c
    WHERE c.id = case_id
      AND (
        public.is_case_magistrate(c.id)
        OR public.has_tribunal_permission(c.tribunal_id, 'cases.manage_lawyers')
      )
  )
  AND public.is_active_tribunal_lawyer(
    user_id,
    (SELECT tribunal_id FROM public.cases WHERE id = case_id)
  )
);

DROP POLICY IF EXISTS "Alterar habilitação de advogado" ON public.case_lawyers;
CREATE POLICY "Alterar habilitação de advogado"
ON public.case_lawyers FOR UPDATE TO authenticated
USING (public.is_case_magistrate(case_id) OR public.is_platform_admin())
WITH CHECK (public.is_case_magistrate(case_id) OR public.is_platform_admin());

-- Somente o responsável gerencia a lista de acessos do processo sigiloso.
DROP POLICY IF EXISTS "Consultar concessões próprias ou do processo" ON public.case_access_grants;
CREATE POLICY "Consultar concessões próprias ou do processo"
ON public.case_access_grants FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_case_magistrate(case_id));

DROP POLICY IF EXISTS "Magistrado concede acesso" ON public.case_access_grants;
CREATE POLICY "Magistrado concede acesso"
ON public.case_access_grants FOR INSERT TO authenticated
WITH CHECK (public.is_case_magistrate(case_id) AND granted_by = auth.uid());

DROP POLICY IF EXISTS "Magistrado altera acesso" ON public.case_access_grants;
CREATE POLICY "Magistrado altera acesso"
ON public.case_access_grants FOR UPDATE TO authenticated
USING (public.is_case_magistrate(case_id))
WITH CHECK (public.is_case_magistrate(case_id));

DROP POLICY IF EXISTS "Magistrado revoga acesso" ON public.case_access_grants;
CREATE POLICY "Magistrado revoga acesso"
ON public.case_access_grants FOR DELETE TO authenticated
USING (public.is_case_magistrate(case_id));

-- 10) Bucket privado: permitir download de arquivo marcado público sem liberar
-- os demais arquivos do processo. O frontend nunca recebe service_role.
DROP POLICY IF EXISTS "Leitura de documentos públicos do PJe" ON storage.objects;
CREATE POLICY "Leitura de documentos públicos do PJe"
ON storage.objects FOR SELECT TO anon, authenticated
USING (
  bucket_id = 'pje-documentos'
  AND EXISTS (
    SELECT 1 FROM public.case_documents d
    WHERE d.storage_path = storage.objects.name
      AND d.visibility = 'publica'
  )
);

DROP POLICY IF EXISTS "Leitura de documentos privados autorizados do PJe" ON storage.objects;
CREATE POLICY "Leitura de documentos privados autorizados do PJe"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'pje-documentos'
  AND EXISTS (
    SELECT 1 FROM public.case_documents d
    WHERE d.storage_path = storage.objects.name
      AND d.visibility <> 'publica'
      AND public.can_access_case_content(d.case_id, d.visibility)
  )
);

-- 11) Auditoria das novas relações.
DROP TRIGGER IF EXISTS trg_audit_case_lawyers ON public.case_lawyers;
CREATE TRIGGER trg_audit_case_lawyers
AFTER INSERT OR UPDATE OR DELETE ON public.case_lawyers
FOR EACH ROW EXECUTE FUNCTION public.audit_row_change();

DROP TRIGGER IF EXISTS trg_audit_case_access_grants ON public.case_access_grants;
CREATE TRIGGER trg_audit_case_access_grants
AFTER INSERT OR UPDATE OR DELETE ON public.case_access_grants
FOR EACH ROW EXECUTE FUNCTION public.audit_row_change();



-- 12) Numeração CNJ e cadastro transacional de processos.
CREATE TABLE IF NOT EXISTS public.case_number_counters (
  tribunal_id UUID NOT NULL REFERENCES public.tribunals(id) ON DELETE CASCADE,
  filing_year INTEGER NOT NULL,
  next_number INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (tribunal_id, filing_year)
);
ALTER TABLE public.case_number_counters ENABLE ROW LEVEL SECURITY;

-- Evita colisões caso já existam processos cadastrados antes desta migração.
INSERT INTO public.case_number_counters (tribunal_id, filing_year, next_number)
SELECT c.tribunal_id,
       EXTRACT(YEAR FROM c.filing_date)::INTEGER,
       MAX(SUBSTRING(c.case_number FROM '^([0-9]{7})-')::INTEGER) + 1
FROM public.cases c
WHERE c.case_number ~ '^[0-9]{7}-[0-9]{2}\.[0-9]{4}\.[0-9]\.[0-9]{2}\.[0-9]{4}$'
GROUP BY c.tribunal_id, EXTRACT(YEAR FROM c.filing_date)::INTEGER
ON CONFLICT (tribunal_id, filing_year)
DO UPDATE SET next_number = GREATEST(
  public.case_number_counters.next_number,
  EXCLUDED.next_number
);

CREATE OR REPLACE FUNCTION public.next_case_number(p_tribunal_id UUID)
RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_acronym TEXT;
  v_year INTEGER := EXTRACT(YEAR FROM NOW())::INTEGER;
  v_sequence INTEGER;
  v_j TEXT;
  v_tr TEXT;
  v_origin TEXT;
  v_base TEXT;
  v_dv INTEGER;
BEGIN
  IF NOT public.has_tribunal_permission(p_tribunal_id, 'cases.create') THEN
    RAISE EXCEPTION 'Você não possui permissão para cadastrar processos neste tribunal.';
  END IF;

  SELECT acronym INTO v_acronym FROM public.tribunals
  WHERE id = p_tribunal_id AND active = TRUE;
  IF v_acronym IS NULL THEN RAISE EXCEPTION 'Tribunal inválido ou inativo.'; END IF;

  CASE UPPER(v_acronym)
    WHEN 'STF' THEN v_j := '1'; v_tr := '00'; v_origin := '0000';
    WHEN 'TRF3' THEN v_j := '4'; v_tr := '03'; v_origin := '6100';
    WHEN 'TJSP' THEN v_j := '8'; v_tr := '26'; v_origin := '0100';
    ELSE RAISE EXCEPTION 'Não existe regra de numeração cadastrada para este tribunal.';
  END CASE;

  INSERT INTO public.case_number_counters (tribunal_id, filing_year, next_number)
  VALUES (p_tribunal_id, v_year, 2)
  ON CONFLICT (tribunal_id, filing_year)
  DO UPDATE SET next_number = public.case_number_counters.next_number + 1
  RETURNING next_number - 1 INTO v_sequence;

  IF v_sequence > 9999999 THEN RAISE EXCEPTION 'Limite de numeração anual atingido.'; END IF;

  v_base := LPAD(v_sequence::TEXT, 7, '0') || v_year::TEXT || v_j || v_tr || v_origin;
  v_dv := 98 - MOD((v_base || '00')::NUMERIC, 97)::INTEGER;

  RETURN LPAD(v_sequence::TEXT, 7, '0') || '-' || LPAD(v_dv::TEXT, 2, '0') || '.' ||
    v_year::TEXT || '.' || v_j || '.' || v_tr || '.' || v_origin;
END;
$$;
REVOKE ALL ON FUNCTION public.next_case_number(UUID) FROM PUBLIC, anon, authenticated;

-- Catálogo inicial para permitir cadastro sem depender de carga manual prévia.
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
ON CONFLICT (tribunal_id, name) DO NOTHING;

INSERT INTO public.case_subjects_catalog (tribunal_id, name)
SELECT t.id, x.name
FROM public.tribunals t
CROSS JOIN (VALUES
  ('Direito Constitucional'),
  ('Direito Administrativo'),
  ('Direito Civil'),
  ('Direito Processual Civil'),
  ('Direito Penal'),
  ('Direito Processual Penal'),
  ('Direito Tributário'),
  ('Direito do Consumidor'),
  ('Direito Previdenciário'),
  ('Direito do Trabalho'),
  ('Direitos Humanos')
) AS x(name)
WHERE NOT EXISTS (
  SELECT 1 FROM public.case_subjects_catalog s
  WHERE s.tribunal_id = t.id AND s.name = x.name AND s.active = TRUE
);

-- Retorna magistrados vinculados ao tribunal sem expor a tabela profiles inteira.
CREATE OR REPLACE FUNCTION public.list_tribunal_judges(p_tribunal_id UUID)
RETURNS TABLE (user_id UUID, full_name TEXT, role_name TEXT)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT public.has_tribunal_permission(p_tribunal_id, 'cases.create')
     AND NOT public.has_tribunal_permission(p_tribunal_id, 'cases.view') THEN
    RAISE EXCEPTION 'Sem permissão para consultar magistrados deste tribunal.';
  END IF;

  RETURN QUERY
  SELECT p.id, p.full_name::TEXT, r.name::TEXT
  FROM public.user_court_roles ucr
  JOIN public.profiles p ON p.id = ucr.user_id AND p.active = TRUE
  JOIN public.roles r ON r.id = ucr.role_id
  WHERE ucr.tribunal_id = p_tribunal_id
    AND LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
  ORDER BY p.full_name;
END;
$$;

-- Cadastro atômico: gera número CNJ, cria processo, partes e assuntos.
CREATE OR REPLACE FUNCTION public.create_case_with_parties(
  p_tribunal_id UUID,
  p_unit_id UUID,
  p_class_id UUID,
  p_title TEXT,
  p_description TEXT,
  p_confidentiality TEXT,
  p_judge_id UUID,
  p_subject_ids UUID[],
  p_parties JSONB
)
RETURNS TABLE (case_id UUID, case_number TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_case_id UUID;
  v_case_number TEXT;
  v_party JSONB;
  v_party_id UUID;
  v_role TEXT;
  v_party_type TEXT;
BEGIN
  IF NOT public.has_tribunal_permission(p_tribunal_id, 'cases.create') THEN
    RAISE EXCEPTION 'Você não possui permissão para cadastrar processos neste tribunal.';
  END IF;
  IF NULLIF(TRIM(p_title), '') IS NULL THEN
    RAISE EXCEPTION 'O título do processo é obrigatório.';
  END IF;
  IF p_confidentiality NOT IN ('publico', 'restrito', 'sigiloso') THEN
    RAISE EXCEPTION 'Nível de sigilo inválido.';
  END IF;
  IF p_confidentiality = 'sigiloso' AND p_judge_id IS NULL THEN
    RAISE EXCEPTION 'Processos em segredo de justiça precisam ter magistrado responsável definido.';
  END IF;
  IF p_unit_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.court_units u WHERE u.id = p_unit_id AND u.tribunal_id = p_tribunal_id
  ) THEN RAISE EXCEPTION 'A unidade informada pertence a outro tribunal.'; END IF;
  IF p_class_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.case_classes cc WHERE cc.id = p_class_id
      AND (cc.tribunal_id = p_tribunal_id OR cc.tribunal_id IS NULL) AND cc.active = TRUE
  ) THEN RAISE EXCEPTION 'A classe processual não pertence ao tribunal selecionado.'; END IF;
  IF p_judge_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.user_court_roles ucr
    JOIN public.roles r ON r.id = ucr.role_id
    JOIN public.profiles pr ON pr.id = ucr.user_id AND pr.active = TRUE
    WHERE ucr.user_id = p_judge_id AND ucr.tribunal_id = p_tribunal_id
      AND LOWER(r.name) IN ('juiz', 'desembargador', 'ministro')
  ) THEN RAISE EXCEPTION 'O magistrado selecionado não possui vínculo válido com este tribunal.'; END IF;

  v_case_number := public.next_case_number(p_tribunal_id);
  INSERT INTO public.cases (
    tribunal_id, unit_id, class_id, case_number, title, description,
    status, confidentiality, filing_date, distribution_date, judge_id, created_by
  ) VALUES (
    p_tribunal_id, p_unit_id, p_class_id, v_case_number, TRIM(p_title),
    NULLIF(TRIM(COALESCE(p_description, '')), ''), 'ativo', p_confidentiality,
    NOW(), CASE WHEN p_judge_id IS NULL THEN NULL ELSE NOW() END,
    p_judge_id, auth.uid()
  ) RETURNING id INTO v_case_id;

  IF COALESCE(array_length(p_subject_ids, 1), 0) > 0 THEN
    INSERT INTO public.case_subject_links (case_id, subject_id, is_primary)
    SELECT v_case_id, s.id, ordinality = 1
    FROM unnest(p_subject_ids) WITH ORDINALITY AS selected(subject_id, ordinality)
    JOIN public.case_subjects_catalog s ON s.id = selected.subject_id
      AND (s.tribunal_id = p_tribunal_id OR s.tribunal_id IS NULL) AND s.active = TRUE;
  END IF;

  FOR v_party IN SELECT value FROM jsonb_array_elements(COALESCE(p_parties, '[]'::JSONB))
  LOOP
    IF NULLIF(TRIM(v_party->>'name'), '') IS NULL THEN CONTINUE; END IF;
    v_role := LOWER(COALESCE(v_party->>'role', 'outro'));
    v_party_type := LOWER(COALESCE(v_party->>'party_type', 'outro'));
    IF v_role NOT IN ('autor','reu','requerente','requerido','impetrante','impetrado','interessado','terceiro','outro') THEN
      RAISE EXCEPTION 'Papel de parte inválido.';
    END IF;
    IF v_party_type NOT IN ('pessoa_fisica','pessoa_juridica','orgao_publico','outro') THEN
      RAISE EXCEPTION 'Tipo de parte inválido.';
    END IF;
    INSERT INTO public.parties (party_type, name, document_number, email)
    VALUES (v_party_type, TRIM(v_party->>'name'), NULLIF(TRIM(v_party->>'document_number'), ''), NULLIF(TRIM(v_party->>'email'), ''))
    RETURNING id INTO v_party_id;
    INSERT INTO public.case_parties (case_id, party_id, role)
    VALUES (v_case_id, v_party_id, v_role);
  END LOOP;

  RETURN QUERY SELECT v_case_id, v_case_number;
END;
$$;
REVOKE ALL ON FUNCTION public.create_case_with_parties(UUID, UUID, UUID, TEXT, TEXT, TEXT, UUID, UUID[], JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_case_with_parties(UUID, UUID, UUID, TEXT, TEXT, TEXT, UUID, UUID[], JSONB) TO authenticated;
REVOKE ALL ON FUNCTION public.list_tribunal_judges(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.list_tribunal_judges(UUID) TO authenticated;

COMMIT;
