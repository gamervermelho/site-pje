
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const respond = (body: object, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") {
    return respond({ error: "Método não permitido." }, 405);
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const authorization = req.headers.get("Authorization");

    if (!authorization) {
      return respond({ error: "Não autenticado." }, 401);
    }

    const userClient = createClient(supabaseUrl, anonKey, {
      global: {
        headers: { Authorization: authorization },
      },
    });

    const {
      data: { user },
      error: authError,
    } = await userClient.auth.getUser();

    if (authError || !user) {
      return respond({ error: "Sessão inválida." }, 401);
    }

    const { data: profile, error: profileError } = await userClient
      .from("profiles")
      .select("is_platform_admin, active")
      .eq("id", user.id)
      .single();

    if (
      profileError ||
      !profile ||
      !profile.is_platform_admin ||
      !profile.active
    ) {
      return respond({ error: "Acesso restrito ao administrador." }, 403);
    }

    const body = await req.json();
    const email = String(body.email ?? "").trim().toLowerCase();
    const fullName = String(body.full_name ?? "").trim();

    if (!email || !fullName) {
      return respond({ error: "Nome e e-mail são obrigatórios." }, 400);
    }

    if (
      fullName.length > 120 ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return respond({ error: "Dados inválidos." }, 400);
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data, error } =
      await adminClient.auth.admin.inviteUserByEmail(email, {
        data: { full_name: fullName },
      });

    if (error) {
      return respond({ error: error.message }, 400);
    }

    return respond({
      success: true,
      message: "Convite enviado com sucesso.",
      user_id: data.user?.id,
    });
  } catch (error) {
    console.error("Erro ao cadastrar usuário:", error);
    return respond({ error: "Erro interno ao cadastrar usuário." }, 500);
  }
});
