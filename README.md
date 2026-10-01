# Login App

A small Flask app with email/password auth and TOTP two-factor authentication
(compatible with Google Authenticator, Authy, 1Password, etc.).

## Requirements

- Python 3.11+

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: copy env defaults
cp .env.example .env

python app.py
```

The app starts on http://localhost:5000 (it auto-selects a free port if 5000 is
busy). The SQLite database (`users.db`) is created automatically on first run.

## Running the tests

```bash
python -m unittest discover -s tests
```

## Configuration

All configuration is via environment variables:

| Variable       | Default                         | Description                                                                                 |
| -------------- | ------------------------------- | ------------------------------------------------------------------------------------------- |
| `SECRET_KEY`   | `dev-insecure-secret-change-me` | **Set this in production.** Signs session cookies.                                           |
| `DATABASE_URL` | _(unset)_                       | SQLAlchemy connection string for Postgres in production. Takes precedence over `DATABASE`.   |
| `DATABASE`     | `users.db`                      | SQLite file path, used only when `DATABASE_URL` is unset (local dev / tests).                |
| `PORT`         | `5000`                          | Port to bind. Most PaaS platforms inject this automatically.                                |
| `FLASK_DEBUG`  | `1`                             | Only affects `python app.py`. Set to `0` outside local dev.                                 |
| `TWILIO_ACCOUNT_SID` / `TWILIO_VERIFY_SERVICE_SID` | _(unset)_ | Enables SMS login codes via Twilio Verify. When unset, SMS codes are printed to the console. |
| `TWILIO_API_KEY_SID` / `TWILIO_API_KEY_SECRET` | _(unset)_ | Recommended Twilio credentials (restrictable, revocable). Takes precedence over the Auth Token. |
| `TWILIO_AUTH_TOKEN` | _(unset)_ | Alternative Twilio credential, used only when no API Key is set. |

### SMS verification (Twilio Verify)

Users add a phone number from **Profile → SMS Verification**; the number must
be confirmed with a texted code before it can be used at login. Numbers are
entered in E.164 format (e.g. `+14155552671`). Twilio generates, delivers, and
checks the codes, so no SMS code is stored by the app.

### Database backend

The app uses SQLAlchemy and runs on either backend with no code change:

- **Local / tests:** SQLite (zero setup) — the default.
- **Production:** Postgres — set `DATABASE_URL`. Render and Heroku inject this
  automatically when you attach a managed Postgres. The `postgres://` and
  `postgresql://` prefixes they use are normalized to the `psycopg` driver
  automatically, so you can paste the value as-is.

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

Set `SECRET_KEY` (and any other overrides) in the platform's environment
settings, then deploy.

### Docker

```bash
docker build -t login-app .
docker run -p 5000:5000 \
  -e SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  -v login-app-data:/data \
  login-app
```

The container stores the database at `/data/users.db` and exposes `/data` as a
volume so accounts persist across restarts and redeploys.

### Manual (systemd, bare VM, etc.)

```bash
pip install -r requirements.txt
export SECRET_KEY="...your-random-value..."
gunicorn app:app --bind 0.0.0.0:5000 --workers 2 --timeout 60
```

## Notes

- **Persistence:** SQLite (the default) lives on the local filesystem, which is
  ephemeral on most PaaS platforms — the database is wiped on restart, and it
  cannot be shared across multiple instances. For durable accounts and horizontal
  scaling, attach a managed Postgres and set `DATABASE_URL`.
- Put the app behind HTTPS in production (via the platform's load balancer or a
  reverse proxy) so session cookies and TOTP codes are not sent in cleartext.
