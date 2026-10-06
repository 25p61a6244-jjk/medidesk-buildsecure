# MediDesk Security Final Report

## Scope and conclusion

This report covers the secure-demo release of MediDesk. The application was audited, hardened, tested, rescanned, and smoke-tested under Gunicorn. The evidence shows **no known critical or high findings in the recorded run**. This is not a claim of 100% security and the application is limited to synthetic data.

## Controls verified

Server-side role and object authorization protect patient, doctor, admin, appointment, medical-record, notification and attachment boundaries. Patients are scoped to their own objects; doctors are scoped to assigned patients; admin routes require admin role. CSRF tokens are required for state changes, Jinja autoescaping is retained, and normal data access uses SQLAlchemy ORM.

Attachments are limited to 5 MB, allow only PDF/PNG/JPG content, verify magic bytes, use UUID names, are kept outside static assets, and require authorization on download. Sessions use HttpOnly/SameSite settings with configurable Secure cookies and strong environment-driven secrets. Flask-Talisman provides CSP, frame denial, nosniff, referrer policy, and optional HSTS. Audit events cover authentication, unauthorized access, appointments, records, uploads, roles, support messages and AI use.

The optional AI provider is bounded to a fixed HTTPS host, uses a timeout, reads the API key only from the server environment, and falls back safely. It cannot diagnose, prescribe, browse arbitrary URLs, or access records.

## Automated evidence

| Area | Result | Evidence |
|---|---|---|
| Security regression tests | PASS | 8 pytest tests: RBAC, IDOR, CSRF, XSS, SQLi, uploads, self-demotion |
| SAST | PASS | `security-reports/bandit.txt` |
| SCA | PASS | `security-reports/pip-audit.txt`; patched Flask 3.1.3 and python-dotenv 1.2.2 |
| Secrets scan | PASS | `security-reports/secrets-scan.txt` |
| DAST smoke | PASS | `security-reports/dast-smoke.txt` |
| Runtime | PASS | Gunicorn route and header smoke checks |

OWASP ZAP was unavailable in the sandbox; `security-reports/zap-report.html` documents that fact. The release pipeline will use ZAP automatically when `zap-baseline.py` is available.

## Residual limitations

Before real clinical deployment, add MFA, rate limiting, centralized secrets and audit retention, durable PostgreSQL migrations/backups, encrypted object storage with malware scanning, authenticated staging ZAP coverage, privacy/legal review, and operational monitoring. Local SQLite/filesystem storage is for demo use only.
