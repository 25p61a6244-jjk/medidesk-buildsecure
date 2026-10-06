# MediDesk Security Notes

MediDesk uses OWASP ASVS-inspired verification for this hackathon demo. It is not a claim of perfect or certified security.

## Implemented controls

- **Authentication:** Werkzeug scrypt password hashes; login session reset; failed-login audit events; 30-minute permanent session lifetime.
- **Authorization:** server-side `login_required` and role checks for PATIENT, DOCTOR, and ADMIN; object ownership checks for appointments, records, and attachments; doctors are limited to patients linked through an appointment.
- **CSRF/XSS:** Flask-WTF protects state-changing routes; Jinja autoescaping remains enabled; no template uses `|safe` for user content; AI requests carry the CSRF token.
- **Injection:** normal persistence uses SQLAlchemy ORM and validated enum-like inputs; SQL injection regression coverage is included.
- **Uploads:** 5 MB global request limit; PDF/PNG/JPG allowlist; magic-byte validation; UUID filenames; private storage outside static assets; authorization on download; no client filename reuse.
- **Headers:** CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, referrer policy, permissions policy and optional production HSTS through Flask-Talisman.
- **Auditability:** authentication, unauthorized access, appointments, profile updates, contact workflow, role changes, records, uploads and AI use are logged without passwords, tokens, or clinical payloads.
- **AI safety:** optional provider uses a fixed HTTPS host, short timeout, server-side key only, and a bounded system prompt. Local fallback refuses diagnosis/prescribing requests and does not access records.
- **Error handling:** polished 403/404/413/500 responses avoid stack traces and internal details.

## Automated evidence

Run:

```bash
python3 security_check.py
```

Reports are written to `security-reports/` for pytest security tests, Bandit SAST, pip-audit SCA, secrets scanning, and DAST smoke checks. OWASP ZAP is attempted when `zap-baseline.py` is installed; the included report records when it is unavailable.

## Known limitations

- This is a hackathon demo with synthetic data, not a clinical system.
- Local SQLite and filesystem uploads are not sufficient for high-availability production.
- Rate limiting, MFA, centralized secrets management, malware scanning and managed object storage should be added before handling real data.
- The scan report is evidence for the recorded run and must be refreshed whenever dependencies or deployment configuration change.
