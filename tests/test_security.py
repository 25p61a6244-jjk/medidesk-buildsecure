import os
import sys
from io import BytesIO
from pathlib import Path

import pytest

TEST_DB = Path("/tmp/medidesk-security-tests.db")
TEST_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["SECRET_KEY"] = "test-only-not-for-deployment"
os.environ["COOKIE_SECURE"] = "0"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.app import app, db  # noqa: E402
from src.models import Appointment, MedicalRecord, PatientProfile, User  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def clean_database():
    with app.app_context():
        db.drop_all()
        db.create_all()
        from src.app import ensure_demo_data
        ensure_demo_data()
    yield
    with app.app_context():
        db.session.remove()
        db.drop_all()
    TEST_DB.unlink(missing_ok=True)


@pytest.fixture
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app.test_client()


def login(client, email, password="Demo@12345"):
    response = client.post("/login", data={"email": email, "password": password})
    assert response.status_code == 302
    return response


def test_public_smoke_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert client.get("/health").json["status"] == "ok"
    assert client.get("/missing-page").status_code == 404


def test_role_boundaries(client):
    login(client, "patient@medidesk.local")
    assert client.get("/doctor").status_code == 403
    assert client.get("/admin").status_code == 403
    client.post("/logout")
    login(client, "doctor@medidesk.local")
    assert client.get("/admin").status_code == 403


def test_patient_a_cannot_access_patient_b_appointment_record_or_attachment(client, tmp_path):
    with app.app_context():
        patient_b = User(name="Patient B", email="patient-b@test.local", role="patient")
        patient_b.set_password("PatientB-password-123")
        db.session.add(patient_b)
        db.session.flush()
        db.session.add(PatientProfile(user_id=patient_b.id))
        doctor = User.query.filter_by(email="doctor@medidesk.local").first()
        appointment = Appointment(patient_id=patient_b.id, doctor_id=doctor.id, date="2099-01-01", time="09:00", reason="synthetic")
        db.session.add(appointment)
        db.session.flush()
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(exist_ok=True)
        filename = "idor-test.pdf"
        (upload_dir / filename).write_bytes(b"%PDF-1.7 synthetic")
        record = MedicalRecord(patient_id=patient_b.id, doctor_id=doctor.id, diagnosis="private synthetic", attachment_name=filename)
        db.session.add(record)
        db.session.commit()
        appointment_id, record_id = appointment.id, record.id

    login(client, "patient@medidesk.local")
    assert client.post(f"/patient/appointments/{appointment_id}/status", data={"status": "Cancelled"}).status_code == 404
    assert client.get(f"/files/{record_id}").status_code == 404
    assert b"private synthetic" not in client.get("/patient").data


def test_doctor_cannot_write_unassigned_patient_record(client):
    with app.app_context():
        patient_b = User.query.filter_by(email="patient-b@test.local").first()
        assert patient_b is not None
        patient_id = patient_b.id
    login(client, "doctor2@medidesk.local")
    response = client.post("/doctor/records", data={"patient_id": patient_id, "diagnosis": "unauthorized"})
    assert response.status_code == 403


def test_csrf_rejects_state_change_without_token(client):
    app.config["WTF_CSRF_ENABLED"] = True
    response = client.post("/login", data={"email": "patient@medidesk.local", "password": "Demo@12345"})
    app.config["WTF_CSRF_ENABLED"] = False
    assert response.status_code == 400


def test_xss_is_escaped_and_sqli_does_not_authenticate(client):
    xss = '<script>alert("x")</script>'
    response = client.post("/contact", data={"name": xss, "email": "safe@example.com", "subject": xss, "message": xss})
    assert response.status_code == 302
    with app.app_context():
        admin = app.test_client()
        login(admin, "admin@medidesk.local")
        page = admin.get("/admin").data.decode()
        assert xss not in page
        assert "&lt;script&gt;" in page
    failed = client.post("/login", data={"email": "' OR 1=1 --", "password": "anything"})
    assert failed.status_code == 401


def test_upload_magic_bytes_and_private_filename(client):
    with app.app_context():
        patient = User.query.filter_by(email="patient@medidesk.local").first()
        doctor = User.query.filter_by(email="doctor@medidesk.local").first()
        assert Appointment.query.filter_by(patient_id=patient.id, doctor_id=doctor.id).first()
    login(client, "doctor@medidesk.local")
    fake = client.post("/doctor/records", data={"patient_id": patient.id, "diagnosis": "fake", "attachment": (BytesIO(b"MZ-not-a-pdf"), "../../evil.pdf")}, content_type="multipart/form-data")
    assert fake.status_code == 400
    valid = client.post("/doctor/records", data={"patient_id": patient.id, "diagnosis": "valid synthetic note", "attachment": (BytesIO(b"%PDF-1.7 synthetic"), "../../safe.pdf")}, content_type="multipart/form-data")
    assert valid.status_code == 302
    with app.app_context():
        record = MedicalRecord.query.filter_by(diagnosis="valid synthetic note").first()
        assert record.attachment_name and ".." not in record.attachment_name and "/" not in record.attachment_name


def test_admin_cannot_demote_self(client):
    login(client, "admin@medidesk.local")
    with app.app_context():
        admin_id = User.query.filter_by(email="admin@medidesk.local").first().id
    response = client.post(f"/admin/users/{admin_id}/role", data={"role": "patient"})
    assert response.status_code == 400
