# MediDesk Deployment

## Local development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m flask --app src.app run --host 127.0.0.1 --port 5000
```

The application automatically creates the synthetic demo accounts on startup if they do not already exist. The destructive `flask seed` command remains available for local reset/testing but should not be used as a production startup command.

Health check: `GET /health`

## Demo credentials

- Patient: `patient@medidesk.local` / `Demo@12345`
- Doctor: `doctor@medidesk.local` / `Demo@12345`
- Doctor 2: `doctor2@medidesk.local` / `Demo@12345`
- Admin: `admin@medidesk.local` / `Demo@12345`

All demo information is synthetic.

## Optional AI integration

MediDesk includes a privacy-first AI assistant for navigation, FAQs, security guidance and explanations of synthetic demo records. It never intentionally provides diagnosis or prescribing advice.

Without an API key, the application uses its local safe-response assistant. To enable live model responses, set these environment variables on the deployment platform without committing them to Git:

```text
OPENAI_API_KEY=<secret>
OPENAI_MODEL=gpt-6-luna
```

The integration uses the OpenAI Responses API. No API key is included in this repository.

## Render / production checklist

1. Connect the team's GitHub repository to the selected web-service host.
2. Build command: `pip install -r requirements.txt`
3. Start command: `gunicorn --chdir src app:app`
4. Set a strong random `SECRET_KEY`.
5. Set `COOKIE_SECURE=1` when the service is served over HTTPS.
6. Prefer a persistent `DATABASE_URL` such as PostgreSQL for production persistence. SQLite is suitable for local/demo use but should not be treated as durable production storage on an ephemeral filesystem.
7. Keep uploaded files outside public static assets.
8. Confirm `GET /health` returns HTTP 200.
9. Run SAST/SCA/DAST and manual authorization tests before the final frozen commit.
10. Record the live deployment URL and final frozen commit SHA in `metadata/submission.yaml`.
