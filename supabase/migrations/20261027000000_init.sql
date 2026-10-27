-- EFT4UA Library: schema, access rules (RLS) and file storage.
-- Everyone can sign in, but only profiles with status 'member' can read the library.
-- New sign-ins become 'pending' applicants unless their email is in public.invites.

-- ---------- Tables ----------

create table public.invites (
  email text primary key,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  name text not null default '',
  initials text not null default '',
  role text not null default '',
  bio text not null default '',
  avatar jsonb not null default '{"mode":"color"}',
  photo_url text,
  status text not null default 'pending' check (status in ('pending', 'member', 'declined', 'removed')),
  is_admin boolean not null default false,
  note text not null default '',
  reason text not null default '',
  applied_at timestamptz not null default now(),
  joined_at timestamptz,
  decided_at timestamptz,
  decided_by uuid,
  last_active timestamptz
);

create table public.articles (
  id text primary key,
  author_id uuid not null references public.profiles on delete cascade,
  status text not null default 'draft' check (status in ('draft', 'online', 'offline')),
  data jsonb not null default '{}',
  created_at timestamptz not null default now(),
  published_at timestamptz,
  updated_at timestamptz not null default now()
);

create table public.comments (
  id text primary key,
  article_id text not null references public.articles on delete cascade,
  author_id uuid not null references public.profiles on delete cascade,
  parent_id text references public.comments on delete cascade,
  text text not null,
  created_at timestamptz not null default now()
);

create table public.likes (
  article_id text not null references public.articles on delete cascade,
  user_id uuid not null references public.profiles on delete cascade,
  primary key (article_id, user_id)
);

create table public.comment_likes (
  comment_id text not null references public.comments on delete cascade,
  user_id uuid not null references public.profiles on delete cascade,
  primary key (comment_id, user_id)
);

create table public.bookmarks (
  user_id uuid not null references public.profiles on delete cascade,
  article_id text not null references public.articles on delete cascade,
  primary key (user_id, article_id)
);

-- Reports and notifications keep article ids without a foreign key,
-- so the moderation history survives when a post is deleted.
create table public.reports (
  id text primary key,
  article_id text not null,
  reporter_id uuid not null references public.profiles on delete cascade,
  reason text not null,
  text text not null,
  created_at timestamptz not null default now(),
  status text not null default 'open' check (status in ('open', 'ignored', 'returned', 'deleted')),
  resolved_at timestamptz,
  resolution text not null default '',
  snapshot jsonb
);

create table public.notifications (
  id text primary key,
  to_user uuid references public.profiles on delete cascade,
  to_admin boolean not null default false,
  type text not null,
  article_id text,
  report_id text,
  applicant_id uuid,
  title text,
  reason text,
  created_at timestamptz not null default now(),
  read boolean not null default false
);

create index on public.articles (author_id);
create index on public.comments (article_id);
create index on public.notifications (to_user);

-- ---------- Helpers ----------

create function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and status = 'member');
$$;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and status = 'member' and is_admin);
$$;

-- New auth user -> profile. Invited emails are members right away.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  inv invites%rowtype;
  nm text := coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', '');
begin
  select * into inv from invites where lower(email) = lower(new.email);
  insert into profiles (id, email, name, photo_url, status, is_admin, joined_at)
  values (
    new.id, new.email, nm, new.raw_user_meta_data->>'avatar_url',
    case when inv.email is not null then 'member' else 'pending' end,
    coalesce(inv.is_admin, false),
    case when inv.email is not null then now() end
  );
  if inv.email is null then
    insert into notifications (id, to_admin, type, applicant_id, created_at)
    values ('n-' || new.id, true, 'applicant', new.id, now());
  end if;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Members may edit their own profile, but only admins can change status or admin rights.
create function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.id := old.id;
  new.email := old.email;
  new.applied_at := old.applied_at;
  if not is_admin() then
    new.status := old.status;
    new.is_admin := old.is_admin;
    new.reason := old.reason;
    new.decided_at := old.decided_at;
    new.decided_by := old.decided_by;
    new.joined_at := old.joined_at;
  elsif new.status = 'member' and old.status <> 'member' then
    new.joined_at := coalesce(old.joined_at, now());
  end if;
  return new;
end;
$$;

create trigger guard_profile
  before update on public.profiles
  for each row execute function public.guard_profile();

-- Authors can't change who wrote a post or reassign comments.
create function public.guard_author() returns trigger
language plpgsql as $$
begin
  new.author_id := old.author_id;
  return new;
end;
$$;

create trigger guard_article_author before update on public.articles
  for each row execute function public.guard_author();
create trigger guard_comment_author before update on public.comments
  for each row execute function public.guard_author();

-- ---------- Row Level Security ----------

alter table public.invites enable row level security;
alter table public.profiles enable row level security;
alter table public.articles enable row level security;
alter table public.comments enable row level security;
alter table public.likes enable row level security;
alter table public.comment_likes enable row level security;
alter table public.bookmarks enable row level security;
alter table public.reports enable row level security;
alter table public.notifications enable row level security;

create policy "admins manage invites" on public.invites
  for all using (is_admin()) with check (is_admin());

create policy "read own profile" on public.profiles
  for select using (id = auth.uid());
create policy "members read members" on public.profiles
  for select using (is_member() and status in ('member', 'removed'));
create policy "admins read all profiles" on public.profiles
  for select using (is_admin());
create policy "update own profile" on public.profiles
  for update using (id = auth.uid()) with check (id = auth.uid());
create policy "admins update profiles" on public.profiles
  for update using (is_admin()) with check (is_admin());

create policy "members read online posts" on public.articles
  for select using (is_member() and (status = 'online' or author_id = auth.uid() or is_admin()));
create policy "members write own posts" on public.articles
  for insert with check (is_member() and author_id = auth.uid());
create policy "authors and admins update posts" on public.articles
  for update using (is_member() and (author_id = auth.uid() or is_admin()));
create policy "authors and admins delete posts" on public.articles
  for delete using (is_member() and (author_id = auth.uid() or is_admin()));

create policy "members read comments" on public.comments
  for select using (is_member());
create policy "members write own comments" on public.comments
  for insert with check (is_member() and author_id = auth.uid());
create policy "authors update comments" on public.comments
  for update using (is_member() and author_id = auth.uid());
create policy "authors and admins delete comments" on public.comments
  for delete using (is_member() and (author_id = auth.uid() or is_admin()));

create policy "members read likes" on public.likes
  for select using (is_member());
create policy "members like" on public.likes
  for insert with check (is_member() and user_id = auth.uid());
create policy "members unlike" on public.likes
  for delete using (user_id = auth.uid());

create policy "members read comment likes" on public.comment_likes
  for select using (is_member());
create policy "members like comments" on public.comment_likes
  for insert with check (is_member() and user_id = auth.uid());
create policy "members unlike comments" on public.comment_likes
  for delete using (user_id = auth.uid());

create policy "own bookmarks" on public.bookmarks
  for all using (user_id = auth.uid()) with check (is_member() and user_id = auth.uid());

create policy "read own or all reports as admin" on public.reports
  for select using (is_member() and (reporter_id = auth.uid() or is_admin()));
create policy "members report" on public.reports
  for insert with check (is_member() and reporter_id = auth.uid());
create policy "admins resolve reports" on public.reports
  for update using (is_admin());

create policy "read own notifications" on public.notifications
  for select using (to_user = auth.uid() or (to_admin and is_admin()));
create policy "members notify" on public.notifications
  for insert with check (is_member() and (to_admin or is_admin()));
create policy "mark own notifications read" on public.notifications
  for update using (to_user = auth.uid() or (to_admin and is_admin()));

-- ---------- File storage ----------
-- One private bucket. Files live under <user id>/..., only members can read them.

insert into storage.buckets (id, name, public, file_size_limit)
values ('files', 'files', false, 52428800)
on conflict (id) do nothing;

create policy "members read files" on storage.objects
  for select using (bucket_id = 'files' and public.is_member());
create policy "members upload own files" on storage.objects
  for insert with check (bucket_id = 'files' and public.is_member() and (storage.foldername(name))[1] = auth.uid()::text);
create policy "owners delete files" on storage.objects
  for delete using (bucket_id = 'files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
