-- PJe Simulado: exclusão permanente de processos pelo administrador da plataforma.
-- Execute no SQL Editor do Supabase.
-- A função retorna os caminhos dos arquivos para que o frontend também remova
-- os objetos do bucket privado usando a API oficial do Supabase Storage.

BEGIN;

CREATE OR REPLACE FUNCTION public.admin_delete_case(p_case_id UUID)
RETURNS TEXT[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_paths TEXT[];
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'É necessário estar autenticado.';
  END IF;

  IF NOT public.is_platform_admin() THEN
    RAISE EXCEPTION 'Somente o administrador da plataforma pode excluir processos.';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.cases WHERE id = p_case_id
  ) THEN
    RAISE EXCEPTION 'Processo não encontrado.';
  END IF;

  SELECT COALESCE(array_agg(storage_path), ARRAY[]::TEXT[])
  INTO v_paths
  FROM public.case_documents
  WHERE case_id = p_case_id;

  -- O gatilho trg_audit_cases registra a exclusão e os dados anteriores.
  -- Os vínculos com ON DELETE CASCADE removem partes do processo,
  -- assuntos, movimentações, documentos e demais relações dependentes.
  DELETE FROM public.cases
  WHERE id = p_case_id;

  RETURN v_paths;
END;
$$;

REVOKE ALL ON FUNCTION public.admin_delete_case(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.admin_delete_case(UUID) TO authenticated;

-- Permite que o administrador remova arquivos do bucket privado pelo Storage API.
DROP POLICY IF EXISTS "Administrador exclui arquivos do PJe" ON storage.objects;
CREATE POLICY "Administrador exclui arquivos do PJe"
ON storage.objects FOR DELETE TO authenticated
USING (
  bucket_id = 'pje-documentos'
  AND public.is_platform_admin()
);

COMMIT;
NOTIFY pgrst, 'reload schema';
