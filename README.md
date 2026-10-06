# Login App

A small Flask app with email/password sign-in, a choice of two-factor
verification methods, and a shared file upload/download area for signed-in
users.

## Features

- **Accounts:** register and sign in with email and password (hashed with
  Werkzeug).
- **Two-factor sign-in:** after the password check, the user picks one method:
  - **Email OTP:** a 6-digit code sent by email, valid for 5 minutes. It is on
    by default for every account.
  - **SMS OTP:** a code texted via [Twilio Verify](https://www.twilio.com/docs/verify).
  - **Authenticator app:** TOTP codes (Google Authenticator, Authy,
    1Password, etc.), set up by scanning a QR code.
- **Profile:** change password, and enable or disable each 2FA method. At
  least one method must stay enabled.
- **Files:** upload one or more files (up to 500 MB per request), browse
  them, and download them. The dashboard shows file count, total size, and
  recent uploads.
- **Structured logging:** auth and 2FA events are logged as `key=value` lines,
  with email addresses and phone numbers masked.

## Requirements

- Python 3.11+

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: copy env defaults (loaded automatically via python-dotenv)
cp .env.example .env

python app.py
```

The app starts on http://localhost:5000. If `PORT` is unset and 5000 is busy,
it picks the next free port. The SQLite database (`users.db`) is created
automatically on first run.

You don't need SMTP or Twilio credentials locally. When they're unset, email
and SMS codes are printed to the server console, for example:

```
[DEV] Email OTP for you@example.com: 123456
```

## Running the tests

```bash
python -m unittest discover -s tests
```

## Sign-in flow

1. `/login`: email and password are checked.
2. `/two-factor/choose`: the user picks Email, SMS, or Authenticator.
   - **Email:** a code is sent and checked at `/two-factor/email`.
   - **SMS:** if the account has a verified phone, a code is sent straight
     away. Otherwise the user enters a number at `/two-factor/sms`, and it is
     saved only after the texted code is confirmed.
   - **Authenticator:** first-time users scan a QR code at
     `/two-factor/setup`. Returning users enter a code at `/two-factor/verify`.
3. On success the user lands on `/dashboard`.

Email OTP codes are stored only as a hash with an expiry in the session.
Twilio generates and checks SMS codes, so the app never stores them.

## Configuration

All configuration is via environment variables. A `.env` file in the project
root is loaded automatically, and real environment variables take precedence.
See [.env.example](.env.example) for a commented template.

### Core

| Variable       | Default                         | Description                                                                               |
| -------------- | ------------------------------- | ----------------------------------------------------------------------------------------- |
| `SECRET_KEY`   | `dev-insecure-secret-change-me` | **Set this in production.** Signs session cookies.                                        |
| `DATABASE_URL` | _(unset)_                       | SQLAlchemy connection string for Postgres in production. Takes precedence over `DATABASE`. |
| `DATABASE`     | `users.db`                      | SQLite file path, used only when `DATABASE_URL` is unset (local dev / tests).              |
| `PORT`         | `5000`                          | Port to bind. Most PaaS platforms inject this automatically.                              |
| `FLASK_DEBUG`  | `1`                             | Only affects `python app.py`. Set to `0` outside local dev.                               |
| `LOG_LEVEL`    | `INFO`                          | Python logging level (`DEBUG`, `INFO`, `WARNING`, ...).                                    |

### Email OTP (SMTP)

| Variable        | Default                              | Description                                                         |
| --------------- | ------------------------------------ | ------------------------------------------------------------------- |
| `SMTP_HOST`     | _(unset)_                            | Enables real email delivery. When unset, codes print to the console. |
| `SMTP_PORT`     | `587`                                | SMTP port. The app always uses STARTTLS.                            |
| `SMTP_USER`     | _(unset)_                            | SMTP username (for Gmail, your address).                            |
| `SMTP_PASSWORD` | _(unset)_                            | SMTP password (for Gmail, an [app password](https://support.google.com/accounts/answer/185833)). |
| `SMTP_FROM`     | `SMTP_USER` or `no-reply@login-app.local` | Sender address.                                                |

### SMS OTP (Twilio Verify)

| Variable                                           | Default   | Description                                                                                  |
| -------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------- |
| `TWILIO_ACCOUNT_SID` / `TWILIO_VERIFY_SERVICE_SID` | _(unset)_ | Enables SMS codes via Twilio Verify. When unset, SMS codes are printed to the console.        |
| `TWILIO_API_KEY_SID` / `TWILIO_API_KEY_SECRET`     | _(unset)_ | Recommended credentials (restrictable, revocable). Takes precedence over the Auth Token.     |
| `TWILIO_AUTH_TOKEN`                                | _(unset)_ | Alternative credential, used only when no API Key is set.                                    |

Create a Verify service in the Twilio console (**Verify → Services**) and copy
its SID. Phone numbers are entered in E.164 format (e.g. `+14155552671`).
Users can also add or change their number under **Profile → SMS Verification**.

### File storage

Uploads are saved to `~/Downloads/upload_login_app/`, which is created on
startup. Filenames are sanitized, and a suffix is added when a name already
exists. All signed-in users share this folder, so every user can see and
download every file.

### Database backend

The app uses SQLAlchemy and runs on either backend with no code change:

- **Local / tests:** SQLite (zero setup), the default.
- **Production:** Postgres. Set `DATABASE_URL`. Render and Heroku inject this
  automatically when you attach a managed Postgres. The app rewrites their
  `postgres://` and `postgresql://` prefixes to use the `psycopg` driver, so
  you can paste the value as-is.

New columns are added to an existing `users` table automatically on startup.

Generate a strong secret key with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Deployment

The app exposes a WSGI callable at `app:app` and is served with
[gunicorn](https://gunicorn.org/) in production.

### Any platform (Render / Railway / Heroku / Fly.io)

A `Procfile` is included:

```
web: gunicorn app:app --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 60
```

Set `SECRET_KEY`, plus any SMTP or Twilio variables you need, in the
platform's environment settings, then deploy.

### Docker

```bash
docker build -t login-app .
docker run -p 5000:5000 \
  -e SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  --env-file .env \
  -v login-app-data:/data \
  login-app
```

The container stores the database at `/data/users.db` and exposes `/data` as a
volume, so accounts persist across restarts and redeploys. Uploaded files go
to `/root/Downloads/upload_login_app` inside the container, which is **not**
on that volume. To keep uploads, mount a volume there too, for example with
`-v login-app-files:/root/Downloads/upload_login_app`.

### Manual (systemd, bare VM, etc.)

```bash
pip install -r requirements.txt
export SECRET_KEY="...your-random-value..."
gunicorn app:app --bind 0.0.0.0:5000 --workers 2 --timeout 60
```

## Notes

- **Persistence:** SQLite (the default) and the uploads folder both live on
  the local filesystem. That filesystem is ephemeral on most PaaS platforms, so
  data is wiped on restart and can't be shared across instances. For durable
  accounts, attach a managed Postgres and set `DATABASE_URL`. Uploaded files
  need persistent disk or object storage.
- Put the app behind HTTPS in production (through the platform's load balancer
  or a reverse proxy). Otherwise session cookies and OTP codes are sent in
  cleartext.
- Never commit `.env`. It holds real SMTP and Twilio credentials.
