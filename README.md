# MediDesk — Secure Clinic & Appointment Management

BUILD SECURE 2026 • Team Cyber Sentials • Team 15

MediDesk is a Flask-based clinic and appointment management demo with Patient, Doctor and Admin workspaces. The application uses synthetic/demo patient data only.

## Core features

- Patient registration, profile, appointments and history
- Doctor dashboard, assigned appointments and synthetic records
- Admin management and audit/security overview
- Protected medical-record attachments
- Server-side RBAC and object ownership checks
- CSRF protection, secure sessions and security headers
- Audit logging and bounded AI assistance

## Local run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m flask --app src.app run --host 127.0.0.1 --port 5000
```

Health check: `GET /health`

## Demo accounts

All data and accounts are synthetic. Demo credentials are documented in `deployment/README.md`; change/remove them before any real deployment.

## Security validation

```bash
python security_check.py
```

Reports are written to `security-reports/`. The recorded release evidence includes security regression tests, Bandit SAST, pip-audit SCA, secrets scanning and DAST smoke checks. OWASP ZAP is used automatically when available.

## Production

See `DEPLOYMENT.md` and `SECURITY.md`. Set a strong `SECRET_KEY`, enable secure cookies over HTTPS, and use durable managed database/object storage for real production data. This hackathon release is restricted to synthetic data.
