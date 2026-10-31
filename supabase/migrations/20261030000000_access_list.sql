-- Access = being on the invite list (no application form).
-- Each email can have an end date, so access ends when a membership isn't renewed.

alter table public.invites add column expires_on date;
update public.invites set email = lower(trim(email));

create function public.normalize_invite() returns trigger
language plpgsql as $$
begin
  new.email := lower(trim(new.email));
  return new;
end;
$$;

create trigger normalize_invite before insert or update on public.invites
  for each row execute function public.normalize_invite();

create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from profiles p join invites i on i.email = lower(p.email)
    where p.id = auth.uid() and (i.expires_on is null or i.expires_on >= current_date)
  );
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from profiles p join invites i on i.email = lower(p.email)
    where p.id = auth.uid() and i.is_admin and (i.expires_on is null or i.expires_on >= current_date)
  );
$$;

-- Everyone can see their own entry (to know whether and until when they have access).
create policy "read own invite" on public.invites
  for select using (email = lower(auth.jwt() ->> 'email'));

-- Members see every profile, so authors of older posts keep their names after leaving.
drop policy "members read members" on public.profiles;
create policy "members read profiles" on public.profiles
  for select using (is_member());

-- New sign-ins just get a profile; no applicant notifications any more.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email, name, photo_url, status)
  values (
    new.id, new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', ''),
    new.raw_user_meta_data->>'avatar_url',
    case when exists (select 1 from invites where email = lower(new.email)) then 'member' else 'pending' end
  );
  return new;
end;
$$;

delete from public.notifications where type = 'applicant';
