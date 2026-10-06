#!/usr/bin/env python3
"""Run MediDesk release security checks and save evidence under security-reports/."""
from __future__ import annotations

import datetime as dt
import html
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "security-reports"
REPORTS.mkdir(exist_ok=True)


def run(name: str, command: list[str], output: str) -> tuple[int, str]:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    text = result.stdout + ("\n" + result.stderr if result.stderr else "")
    (REPORTS / output).write_text(text, encoding="utf-8")
    return result.returncode, text


def secrets_scan() -> tuple[int, str]:
    patterns = [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
        re.compile(r"(?:api[_-]?key|secret[_-]?key|token)\s*[:=]\s*[\"'][A-Za-z0-9_+/=-]{20,}[\"']", re.I),
    ]
    findings = []
    ignored = {"security-reports", ".git", ".venv", "__pycache__"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in ignored for part in path.parts):
            continue
        if path.suffix in {".db", ".pyc", ".png", ".jpg", ".pdf", ".zip"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in patterns:
            if pattern.search(content):
                findings.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")
    text = "No high-confidence secret patterns found.\n" if not findings else "\n".join(findings) + "\n"
    (REPORTS / "secrets-scan.txt").write_text(text, encoding="utf-8")
    return (0 if not findings else 1), text


def main() -> int:
    checks: list[tuple[str, int, str]] = []
    code, _ = run("pytest", [sys.executable, "-m", "pytest", "-q"], "security-tests.txt")
    checks.append(("Automated security tests", code, "pytest: RBAC, IDOR, CSRF, XSS, SQLi, upload validation"))
    if shutil.which("bandit"):
        code, _ = run("bandit", ["bandit", "-r", "src", "-f", "txt"], "bandit.txt")
        checks.append(("Bandit SAST", code, "bandit -r src"))
    else:
        (REPORTS / "bandit.txt").write_text("Bandit not installed; install requirements used by the release workflow.\n", encoding="utf-8")
        checks.append(("Bandit SAST", 2, "tool unavailable"))
    if shutil.which("pip-audit"):
        code, _ = run("pip-audit", ["pip-audit", "-r", "requirements.txt"], "pip-audit.txt")
        checks.append(("pip-audit SCA", code, "pip-audit -r requirements.txt"))
    else:
        (REPORTS / "pip-audit.txt").write_text("pip-audit not installed.\n", encoding="utf-8")
        checks.append(("pip-audit SCA", 2, "tool unavailable"))
    code, _ = secrets_scan()
    checks.append(("Secrets scan", code, "high-confidence patterns"))
    dast_code, dast_text = run("dast", [sys.executable, "-c", "from src.app import app; c=app.test_client(); checks=[c.get('/').status_code==200, c.get('/health').status_code==200, c.get('/missing').status_code==404, c.get('/admin').status_code in (302,403)]; print('DAST smoke checks:', checks); raise SystemExit(0 if all(checks) else 1)"], "dast-smoke.txt")
    checks.append(("DAST smoke", dast_code, "Flask test-client public/error/auth boundary checks"))
    zap = shutil.which("zap-baseline.py")
    zap_note = "OWASP ZAP was not available in this sandbox; the included DAST smoke check ran instead."
    if zap:
        zcode, _ = run("OWASP ZAP", [zap, "-t", os.environ.get("DAST_URL", "http://127.0.0.1:5000"), "-r", str(REPORTS / "zap-report.html")], "zap-output.txt")
        zap_note = f"OWASP ZAP executed with exit code {zcode}."
    else:
        (REPORTS / "zap-report.html").write_text(f"<html><body><h1>OWASP ZAP</h1><p>{html.escape(zap_note)}</p></body></html>", encoding="utf-8")
    lines = ["# MediDesk Security Summary", "", f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}", "", "| Check | Result | Evidence |", "|---|---|---|"]
    for name, code, detail in checks:
        result = "PASS" if code == 0 else "REVIEW"
        lines.append(f"| {name} | {result} | `{detail}` |" )
    lines += ["", f"- {zap_note}", "- Review any SCA advisories before production deployment.", "- This report is evidence for this run, not a claim of perfect security."]
    (REPORTS / "security-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(f"{name}: {'PASS' if code == 0 else 'REVIEW'}" for name, code, _ in checks))
    return 0 if all(code == 0 for _, code, _ in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
