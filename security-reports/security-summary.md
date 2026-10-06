# MediDesk Security Summary

Generated: 2026-10-06T05:33:45.596066+00:00

| Check | Result | Evidence |
|---|---|---|
| Automated security tests | PASS | `pytest: RBAC, IDOR, CSRF, XSS, SQLi, upload validation` |
| Bandit SAST | PASS | `bandit -r src` |
| pip-audit SCA | PASS | `pip-audit -r requirements.txt` |
| Secrets scan | PASS | `high-confidence patterns` |
| DAST smoke | PASS | `Flask test-client public/error/auth boundary checks` |

- OWASP ZAP was not available in this sandbox; the included DAST smoke check ran instead.
- Review any SCA advisories before production deployment.
- This report is evidence for this run, not a claim of perfect security.
