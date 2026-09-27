-- Enable Row Level Security across all tables (security fix, 2026-09-27).
--
-- None of the tables created in 001/002/003 ever enabled RLS. Supabase's
-- PostgREST API exposes every public-schema table by default; without RLS,
-- the public anon key -- which ships in the browser bundle at
-- src/lib/supabaseClient.js and is therefore extractable by anyone who
-- loads the deployed site -- has full read/write/delete access to every
-- row in every table here, including oauth_tokens (real Fitbit/Strava
-- access and refresh tokens).
--
-- Verified before writing this migration, by reading every `.from(...)`
-- call site in the repo:
--   - The ONLY code that ever queries these tables with the anon key is
--     src/lib/healthDataApi.js (browser-side), and every call there is a
--     read-only .select() against exactly six tables: daily_health_summary,
--     health_sync_imports, sleep_sessions, heart_metrics,
--     body_measurements, exercise_sessions.
--   - Every insert/update/upsert/delete anywhere in the repo
--     (src/apiHandlers/*, src/apiLib/*) goes through supabaseAdmin
--     (src/apiLib/supabaseServer.js), a separate service-role client that
--     bypasses RLS entirely regardless of policy. Enabling RLS here cannot
--     break any of those server-side code paths.
--
-- So: the six browser-read tables get a read-only policy (this app has no
-- Supabase Auth / auth.uid() -- user_id is a plain hardcoded string,
-- 'local-user' by default -- so this is not per-row multi-tenant scoping,
-- it only removes the anon key's default write/delete capability while
-- preserving the app's existing read-only dashboard behaviour). Every
-- other table (oauth_tokens, health_sources, strava_activities,
-- strava_webhook_events, daily_context_tags) gets RLS enabled with zero
-- policies, i.e. complete deny-all to anon/authenticated -- nothing in the
-- app ever needed anon access to them, so this only removes an
-- unauthenticated read/write path that should never have existed.

alter table daily_health_summary enable row level security;
alter table health_sync_imports enable row level security;
alter table sleep_sessions enable row level security;
alter table heart_metrics enable row level security;
alter table body_measurements enable row level security;
alter table exercise_sessions enable row level security;
alter table oauth_tokens enable row level security;
alter table health_sources enable row level security;
alter table strava_activities enable row level security;
alter table strava_webhook_events enable row level security;
alter table daily_context_tags enable row level security;

create policy "read_only_daily_health_summary" on daily_health_summary
  for select to anon, authenticated using (true);

create policy "read_only_health_sync_imports" on health_sync_imports
  for select to anon, authenticated using (true);

create policy "read_only_sleep_sessions" on sleep_sessions
  for select to anon, authenticated using (true);

create policy "read_only_heart_metrics" on heart_metrics
  for select to anon, authenticated using (true);

create policy "read_only_body_measurements" on body_measurements
  for select to anon, authenticated using (true);

create policy "read_only_exercise_sessions" on exercise_sessions
  for select to anon, authenticated using (true);

-- oauth_tokens, health_sources, strava_activities, strava_webhook_events,
-- and daily_context_tags intentionally get NO policies: RLS enabled with
-- zero policies means anon/authenticated get zero access (read or write),
-- and supabaseAdmin (service_role) is unaffected since RLS never applies
-- to that role.
