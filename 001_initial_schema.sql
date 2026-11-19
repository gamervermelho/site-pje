-- Schema inicial multi-tribunal do PJe Simulado. Execute no SQL Editor do Supabase.
create extension if not exists pgcrypto;
create table if not exists public.tribunals (
 id uuid primary key default gen_random_uuid(), acronym text not null unique, name text not null,
 region text, is_active boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade, full_name text not null default '', email text,
 role text not null default 'public' check(role in ('admin','magistrate','clerk','lawyer','public')),
 tribunal_id uuid references public.tribunals(id), is_active boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.cases (
 id uuid primary key default gen_random_uuid(), case_number text not null, tribunal_id uuid not null references public.tribunals(id),
 case_class text not null, subject text, status text not null default 'Em tramitação',
 secrecy_level text not null default 'public' check(secrecy_level in ('public','restricted','secret')),
 plaintiff text, defendant text, assigned_judge text, filed_at timestamptz not null default now(),
 created_by uuid references auth.users(id), created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique(tribunal_id,case_number)
);
create table if not exists public.case_movements (
 id uuid primary key default gen_random_uuid(), case_id uuid not null references public.cases(id) on delete cascade,
 movement_type text not null, description text not null,
 visibility text not null default 'public' check(visibility in ('public','restricted')),
 occurred_at timestamptz not null default now(), created_by uuid references auth.users(id), created_at timestamptz not null default now()
);
create table if not exists public.audit_logs (
 id uuid primary key default gen_random_uuid(), actor_id uuid references auth.users(id), tribunal_id uuid references public.tribunals(id),
 entity_type text not null, entity_id uuid, action text not null, details jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists cases_number_idx on public.cases(case_number);
create index if not exists cases_tribunal_idx on public.cases(tribunal_id);
create index if not exists movements_case_date_idx on public.case_movements(case_id,occurred_at desc);
insert into public.tribunals(acronym,name,region) values
 ('STF','Supremo Tribunal Federal','Nacional'),
 ('TRF3','Tribunal Regional Federal da 3ª Região','São Paulo e Mato Grosso do Sul'),
 ('TJSP','Tribunal de Justiça do Estado de São Paulo','São Paulo') on conflict(acronym) do nothing;
alter table public.tribunals enable row level security;
alter table public.profiles enable row level security;
alter table public.cases enable row level security;
alter table public.case_movements enable row level security;
alter table public.audit_logs enable row level security;
create policy "Anyone can read active tribunals" on public.tribunals for select using(is_active=true);
create policy "Users can read own profile" on public.profiles for select to authenticated using(auth.uid()=id);
create policy "Public can read public cases" on public.cases for select to anon,authenticated using(secrecy_level='public');
create policy "Public can read public movements" on public.case_movements for select to anon,authenticated using(
 visibility='public' and exists(select 1 from public.cases c where c.id=case_id and c.secrecy_level='public')
);
-- Não há policies de escrita nesta primeira migração: inserção/edição será adicionada com autorização por papel e tribunal.
-- Nunca exponha a chave service_role no frontend.
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path='' as $$
begin
 insert into public.profiles(id,full_name,email,role) values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''),new.email,'public');
 return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
