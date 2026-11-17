# PJe Simulado
Protótipo inicial de plataforma judicial fictícia para STF, TRF3 e TJSP.

## Tecnologias
React + TypeScript + Vite; Supabase Auth/PostgreSQL/Storage/Realtime; GitHub para versionamento e GitHub Pages para frontend estático.

## Executar
1. Instale Node.js LTS.
2. Execute `npm install`.
3. Copie `.env.example` para `.env.local` e preencha URL e chave anon/public do Supabase.
4. Execute `npm run dev`.

## Banco
No Supabase, abra SQL Editor e execute `supabase/migrations/001_initial_schema.sql`. A migração cria tribunais, perfis, processos, movimentações e auditoria. A primeira versão permite leitura pública apenas de registros públicos e não libera escrita; políticas de escrita devem ser criadas junto do fluxo de autorização por papel/tribunal.

## Publicação
GitHub hospeda o código e pode publicar a interface pelo GitHub Pages. O GitHub Pages não executa backend nem banco de dados: o Supabase continua hospedando os dados. Configure os secrets `VITE_SUPABASE_URL` e `VITE_SUPABASE_ANON_KEY` no repositório para o workflow.

## Segurança e escopo
Nunca coloque `service_role` no navegador. Projeto fictício, sem vínculo com órgãos oficiais; não insira dados pessoais reais. O protótipo ainda usa registros demonstrativos locais na tela principal; a conexão de leitura ao Supabase é testável pelo botão no rodapé.
