# MediDesk Deployment Guide

MediDesk is a Flask application for synthetic clinic data. Use a managed PostgreSQL database and private object storage for a real deployment; SQLite and local uploads are suitable only for a local/demo run.

## Build and run

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DATABASE_URL="sqlite:///$(pwd)/medidesk.db" # replace with PostgreSQL in production
export COOKIE_SECURE=1
export FORCE_HTTPS=1
gunicorn --chdir src --workers 2 --bind 0.0.0.0:8000 app:app
```

The health check is `GET /health`. Do not run `flask seed` during production startup because it intentionally resets the database.

## Required configuration

| Variable | Required | Purpose |
|---|---:|---|
| `SECRET_KEY` | Yes | Long random value used to sign sessions and CSRF tokens |
| `DATABASE_URL` | Yes in production | Durable SQLAlchemy database URL |
| `COOKIE_SECURE` | Yes over HTTPS | Set to `1` so session cookies are HTTPS-only |
| `FORCE_HTTPS` | Yes behind HTTPS | Enables HTTPS redirects and HSTS |
| `UPLOAD_FOLDER` | Optional | Private writable attachment directory |
| `OPENAI_API_KEY` | Optional | Server-only optional AI provider credential |
| `OPENAI_MODEL` | Optional | Model name; only used when the API key is set |

Never put secrets in source control, templates, browser JavaScript, logs, or `.env.example`. Use HTTPS and a private upload store in production. All patient information in this repository is synthetic.
