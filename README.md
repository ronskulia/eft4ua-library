# EFT4UA Library

Members-only library for the EFT4UA community, based on the designer's prototype.

- `index.html` – public landing page
- `app.html` – the library app (sign-in, posts, shelf, comments, dashboard, moderation, members)
- `config.js` – public Supabase URL + publishable key
- `supabase/migrations/` – database tables, access rules (RLS) and file storage

Hosting: static files on GitHub Pages. Data, sign-in and files: Supabase.
Nothing is readable without signing in **and** being approved by an admin.

## Setup

1. Apply the database schema (asks for the database password from Supabase → Project Settings → Database):
   `supabase db push`
2. Add the first admin(s) in Supabase → SQL Editor:
   `insert into invites (email, is_admin) values ('mom@example.com', true);`
   Members can also be invited in advance with `is_admin = false`; anyone else who signs in becomes an applicant that an admin approves under *Members*.
3. Supabase → Authentication → URL Configuration: set *Site URL* to the app URL (e.g. `https://ronskulia.github.io/eft4ua-library/app.html`) and add the same URL under *Redirect URLs*.
4. Email: Supabase's built-in mailer only sends to the project team and a few emails per hour. For real members either
   - set up custom SMTP (Authentication → Emails → SMTP, e.g. Resend's free tier), or
   - enable Google sign-in (Authentication → Sign In / Providers → Google) and set `google: true` in `config.js`.

## Local development

`supabase start`, then serve the folder with a `config.js` that points at `http://127.0.0.1:54321` and the local anon key.
