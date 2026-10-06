# MediDesk Final Release Report

**Release:** BUILD SECURE 2026 polished secure demo
**Domain:** HealthTech
**Status:** Ready for hackathon demonstration and controlled deployment review
**Data policy:** Synthetic/demo patient data only

## Project overview

MediDesk is a server-rendered Flask clinic platform with patient, doctor and administrator workspaces. It supports registration/login, appointment booking and status management, private synthetic records, authorized attachments, notifications, support workflow, audit visibility, a Security Center and a bounded navigation/FAQ assistant.

## Architecture and UI

- Flask + Jinja server-rendered UI
- SQLAlchemy ORM over SQLite locally or `DATABASE_URL` in deployment
- Flask-WTF CSRF protection and Flask-Talisman headers
- Private upload directory with UUID filenames
- Responsive healthcare SaaS visual system: navy navigation, clinical blue/cyan accents, accessible forms, dashboard cards, mobile breakpoints, public landing/auth/help pages
- Added a polished 500 page and deployment/security documentation

## Security changes in this release

- **Authentication security:** scrypt password hashing, session clear-and-reissue on login, secure cookie configuration, permanent session timeout, failed-login audit events.
- **RBAC:** patient, doctor and admin decorators enforce permissions on the server. Patients cannot access doctor/admin routes; doctors cannot access admin routes.
- **IDOR/BOLA:** patient ownership is checked for appointment changes and files; doctor assignment is checked before record writes and doctor record views are scoped by doctor; unauthorized object access returns non-disclosing 404 responses.
- **CSRF:** all form state changes use Flask-WTF; JSON AI calls use the CSRF header; missing-token rejection is tested.
- **XSS:** Jinja autoescaping is retained and a stored XSS regression test confirms escaped support content.
- **SQL injection:** SQLAlchemy ORM queries and a login injection regression test are used; no user-controlled raw SQL was found.
- **File security:** 5 MB limit, extension allowlist, magic-byte/content check, UUID storage names, path-safe private location, download authorization, and rejection of executable/fake files.
- **Session security:** HttpOnly, SameSite=Lax, optional Secure cookie and configurable HTTPS/HSTS production mode.
- **Headers:** CSP, frame denial, nosniff, strict referrer policy and permissions policy verified at runtime.
- **Secrets:** no committed `.env`; placeholders only in `.env.example`; optional AI key is read only from environment and never sent to the browser or logs.
- **AI security:** fixed `api.openai.com` HTTPS connection with timeout; local safe fallback; no diagnosis, prescribing, arbitrary URLs, or record access.
- **Audit logging:** login success/failure, logout, registration, unauthorized access, appointments, records, uploads, role changes, contacts and AI usage are recorded without secrets or unnecessary medical content.

## Verification results

| Check | Evidence | Result |
|---|---|---|
| Automated security tests | `pytest -q` | **8 passed** |
| SAST | `bandit -r src` | **PASS** |
| Dependency/SCA | `pip-audit -r requirements.txt` | **PASS** after pinning patched Flask 3.1.3 and python-dotenv 1.2.2 |
| Secrets scan | `security_check.py` high-confidence patterns | **PASS** |
| DAST smoke | public, health, 404 and unauthenticated admin boundary checks | **PASS** |
| Runtime smoke | Gunicorn on port 5050 | `/`, `/health`, `/doctors`, `/faq`, `/security`, `/contact` = 200; missing page = 404; unauthenticated `/admin` = 302 |
| Header verification | `curl -I /health` | CSP, DENY framing and nosniff observed |

OWASP ZAP was not installed in the sandbox, so `security-reports/zap-report.html` records that limitation and the release uses the included DAST smoke check instead. No known critical or high findings remain in the recorded scan; practical medium findings from the first scan were fixed.

## Remaining limitations

This is not a claim of 100% security. Before real patient data or production healthcare use, add MFA, rate limiting/lockout, centralized secrets management, PostgreSQL migrations/backups, object-storage encryption and malware scanning, centralized audit retention/alerting, dependency update automation, TLS termination review, privacy/legal controls, and an authenticated OWASP ZAP scan against a staging deployment.

## Deployment commands

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DATABASE_URL="postgresql+psycopg://user:password@host/medidesk" # production example
export COOKIE_SECURE=1
export FORCE_HTTPS=1
gunicorn --chdir src --workers 2 --bind 0.0.0.0:8000 app:app
```

Required variables are documented in `DEPLOYMENT.md` and `.env.example`. Do not run `flask seed` in production.
