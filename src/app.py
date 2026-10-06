import json
import http.client
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, date
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError

import filetype
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

try:
    from .config import Config
    from .models import AuditLog, Appointment, ContactMessage, MedicalRecord, Notification, PatientProfile, User, db
except ImportError:
    from config import Config
    from models import AuditLog, Appointment, ContactMessage, MedicalRecord, Notification, PatientProfile, User, db

load_dotenv()
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("medidesk")
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.from_object(Config)
# Render and similar platforms terminate TLS at a trusted reverse proxy.
# Trust only one proxy hop for the HTTPS scheme/host used by Flask-Talisman.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)

CSP = {
    "default-src": ["'self'"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "script-src": ["'self'"],
    "img-src": ["'self'", "data:"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}
Talisman(
    app,
    content_security_policy=CSP,
    force_https=os.environ.get("FORCE_HTTPS", "0").lower() in {"1", "true", "yes"},
    frame_options="DENY",
    strict_transport_security=os.environ.get("FORCE_HTTPS", "0").lower() in {"1", "true", "yes"},
    referrer_policy="strict-origin-when-cross-origin",
)

ALLOWED_TYPES = {"pdf": "application/pdf", "jpg": "image/jpeg", "png": "image/png"}
MAGIC = {"pdf": (b"%PDF-",), "png": (b"\x89PNG\r\n\x1a\n",), "jpg": (b"\xff\xd8\xff",)}
ROLE_VALUES = {"patient", "doctor", "admin"}
APPOINTMENT_STATUSES = {"Confirmed", "Completed", "Cancelled", "Reschedule Requested"}
logger.info("MediDesk started with database=%s", app.config["SQLALCHEMY_DATABASE_URI"].split(":", 1)[0])


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user.role not in roles:
                audit("UNAUTHORIZED_ROLE", f"endpoint:{request.endpoint}", commit=True)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return deco


def audit(action, target="", commit=True):
    user = current_user()
    db.session.add(AuditLog(actor_id=user.id if user else None, action=action[:180], target=target[:180], ip=request.remote_addr))
    if commit:
        db.session.commit()


def notify(user_id, title, message, kind="info"):
    db.session.add(Notification(user_id=user_id, title=title[:160], message=message[:500], kind=kind[:30]))


def valid_email(value):
    return bool(re.fullmatch(r"[^@\s]{1,80}@[^@\s]{1,80}\.[^@\s]{2,24}", value or ""))


def valid_slot(slot_date, slot_time):
    try:
        parsed_date = date.fromisoformat(slot_date)
        datetime.strptime(slot_time, "%H:%M")
        return parsed_date >= date.today()
    except (TypeError, ValueError):
        return False


def valid_attachment(file_storage):
    if not file_storage or not file_storage.filename:
        return None, ""
    original = secure_filename(file_storage.filename)
    if not original or "." not in original:
        return None, "Only PDF, PNG or JPG files are accepted."
    extension = original.rsplit(".", 1)[1].lower()
    if extension == "jpeg":
        extension = "jpg"
    if extension not in ALLOWED_TYPES:
        return None, "Only PDF, PNG or JPG files are accepted."
    header = file_storage.stream.read(32)
    file_storage.stream.seek(0)
    if not any(header.startswith(signature) for signature in MAGIC[extension]):
        return None, "The file content does not match its extension."
    detected = filetype.guess(header)
    if detected and detected.extension not in {extension, "jpeg"}:
        return None, "The file content does not match its extension."
    return (extension, original), ""


@app.context_processor
def inject_user():
    user = current_user()
    unread = Notification.query.filter_by(user_id=user.id, is_read=False).count() if user else 0
    return {"current_user": user, "unread_notifications": unread}


@app.get("/health")
def health():
    return {"status": "ok", "service": "medidesk"}, 200


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if current_user() else render_template("landing.html")


@app.get("/doctors")
def doctors():
    return render_template("doctors.html", doctors=User.query.filter_by(role="doctor").order_by(User.name).all())


@app.get("/faq")
def faq():
    return render_template("faq.html")


@app.get("/security")
def security():
    return render_template("security.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:120]
        email = request.form.get("email", "").strip().lower()[:160]
        subject = request.form.get("subject", "").strip()[:180]
        message = request.form.get("message", "").strip()[:2000]
        if not name or not valid_email(email) or not subject or len(message) < 5:
            flash("Please complete all contact fields with valid information.", "danger")
            return render_template("contact.html"), 400
        db.session.add(ContactMessage(name=name, email=email, subject=subject, message=message))
        db.session.commit()
        audit("CONTACT_MESSAGE", "support")
        flash("Message received. Our clinic support team will review it shortly.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:120]
        email = request.form.get("email", "").strip().lower()[:160]
        password = request.form.get("password", "")
        if len(name) < 2 or not valid_email(email) or len(password) < 12:
            flash("Use a valid name, email and password of at least 12 characters.", "danger")
            return render_template("register.html"), 400
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "danger")
            return render_template("register.html"), 409
        user = User(name=name, email=email, role="patient")
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        db.session.add(PatientProfile(user_id=user.id))
        db.session.commit()
        audit("REGISTER", f"user:{user.id}")
        flash("Registration complete. Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:160]
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            audit("LOGIN_FAILED", "credentials")
            flash("Invalid credentials.", "danger")
            return render_template("login.html"), 401
        session.clear()
        session["user_id"] = user.id
        session["session_nonce"] = secrets.token_urlsafe(24)
        session.permanent = True
        audit("LOGIN", f"user:{user.id}")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    audit("LOGOUT", f"user:{current_user().id}")
    session.clear()
    return redirect(url_for("index"))


@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return redirect(url_for({"patient": "patient_dashboard", "doctor": "doctor_dashboard", "admin": "admin_dashboard"}[user.role]))


@app.get("/notifications")
@login_required
def notifications():
    items = Notification.query.filter_by(user_id=current_user().id).order_by(Notification.created_at.desc()).limit(30).all()
    for item in items:
        item.is_read = True
    db.session.commit()
    return render_template("notifications.html", notifications=items)


@app.post("/notifications/read")
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user().id, is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))


@app.get("/patient")
@role_required("patient")
def patient_dashboard():
    user = current_user()
    appointments = Appointment.query.filter_by(patient_id=user.id).order_by(Appointment.date, Appointment.time).all()
    doctors_list = User.query.filter_by(role="doctor").order_by(User.name).all()
    records = MedicalRecord.query.filter_by(patient_id=user.id).order_by(MedicalRecord.created_at.desc()).all()
    return render_template("patient_dashboard.html", appointments=appointments, doctors=doctors_list, records=records, today=date.today().isoformat())


@app.post("/patient/profile")
@role_required("patient")
def update_profile():
    user = current_user()
    profile = user.patient_profile or PatientProfile(user_id=user.id)
    profile.phone = request.form.get("phone", "").strip()[:30]
    profile.dob = request.form.get("dob", "").strip()[:20]
    profile.address = request.form.get("address", "").strip()[:250]
    profile.emergency_contact = request.form.get("emergency_contact", "").strip()[:120]
    db.session.add(profile)
    db.session.commit()
    audit("UPDATE_PROFILE", f"patient:{user.id}")
    flash("Profile updated.", "success")
    return redirect(url_for("patient_dashboard"))


@app.post("/patient/appointments/book")
@role_required("patient")
def book_appointment():
    doctor_id = request.form.get("doctor_id", type=int)
    slot_date = request.form.get("date", "").strip()
    slot_time = request.form.get("time", "").strip()
    reason = request.form.get("reason", "").strip()[:250]
    doctor = db.session.get(User, doctor_id)
    if not doctor or doctor.role != "doctor" or not valid_slot(slot_date, slot_time):
        flash("Choose a valid future doctor/date/time slot.", "danger")
        return redirect(url_for("patient_dashboard"))
    exists = Appointment.query.filter_by(doctor_id=doctor.id, date=slot_date, time=slot_time).filter(Appointment.status.in_(["Confirmed", "Pending", "Reschedule Requested"])).first()
    if exists:
        flash("That slot is already booked.", "danger")
        return redirect(url_for("patient_dashboard"))
    appointment = Appointment(patient_id=current_user().id, doctor_id=doctor.id, date=slot_date, time=slot_time, reason=reason, status="Confirmed")
    db.session.add(appointment)
    db.session.flush()
    notify(doctor.id, "New appointment", f"A patient booked {slot_date} at {slot_time}.", "appointment")
    db.session.commit()
    audit("BOOK_APPOINTMENT", f"appointment:{appointment.id}")
    flash("Appointment booked.", "success")
    return redirect(url_for("patient_dashboard"))


@app.post("/patient/appointments/<int:appointment_id>/status")
@role_required("patient")
def patient_appointment_status(appointment_id):
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or appointment.patient_id != current_user().id:
        audit("UNAUTHORIZED_OBJECT_ACCESS", f"appointment:{appointment_id}")
        abort(404)
    status = request.form.get("status")
    if status not in {"Cancelled", "Reschedule Requested"}:
        abort(400)
    appointment.status = status
    notify(appointment.doctor_id, "Appointment updated", f"Appointment on {appointment.date} at {appointment.time} is {status.lower()}.", "appointment")
    db.session.commit()
    audit("APPOINTMENT_STATUS", f"appointment:{appointment.id}:{status}")
    flash("Appointment updated.", "success")
    return redirect(url_for("patient_dashboard"))


@app.get("/doctor")
@role_required("doctor")
def doctor_dashboard():
    user = current_user()
    appointments = Appointment.query.filter_by(doctor_id=user.id).order_by(Appointment.date, Appointment.time).all()
    patient_ids = {item.patient_id for item in appointments}
    patients = User.query.filter(User.id.in_(patient_ids)).all() if patient_ids else []
    records = MedicalRecord.query.filter_by(doctor_id=user.id).order_by(MedicalRecord.created_at.desc()).all()
    return render_template("doctor_dashboard.html", appointments=appointments, patients=patients, records=records)


@app.post("/doctor/appointments/<int:appointment_id>/status")
@role_required("doctor")
def doctor_appointment_status(appointment_id):
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment or appointment.doctor_id != current_user().id:
        audit("UNAUTHORIZED_OBJECT_ACCESS", f"appointment:{appointment_id}")
        abort(404)
    status = request.form.get("status")
    if status not in APPOINTMENT_STATUSES:
        abort(400)
    appointment.status = status
    notify(appointment.patient_id, "Appointment updated", f"Your appointment on {appointment.date} at {appointment.time} is {status.lower()}.", "appointment")
    db.session.commit()
    audit("DOCTOR_APPOINTMENT_STATUS", f"appointment:{appointment.id}:{status}")
    flash("Appointment status updated.", "success")
    return redirect(url_for("doctor_dashboard"))


@app.post("/doctor/records")
@role_required("doctor")
def add_record():
    patient_id = request.form.get("patient_id", type=int)
    diagnosis = request.form.get("diagnosis", "").strip()[:500]
    prescription = request.form.get("prescription", "").strip()[:1000]
    patient = db.session.get(User, patient_id)
    assigned = Appointment.query.filter_by(patient_id=patient_id, doctor_id=current_user().id).first() if patient else None
    if not patient or patient.role != "patient" or not assigned or not diagnosis:
        audit("UNAUTHORIZED_RECORD_WRITE", f"patient:{patient_id}")
        abort(403 if patient else 404)
    attachment_name = None
    upload = request.files.get("attachment")
    if upload and upload.filename:
        valid, error = valid_attachment(upload)
        if error:
            flash(error, "danger")
            return redirect(url_for("doctor_dashboard")), 400
        _, original = valid
        final_name = f"{uuid.uuid4().hex}.{valid[0]}"
        destination = (Path(app.config["UPLOAD_FOLDER"]) / final_name).resolve()
        upload.save(destination)
        if destination.parent != Path(app.config["UPLOAD_FOLDER"]).resolve():
            destination.unlink(missing_ok=True)
            abort(400)
        attachment_name = final_name
        audit("FILE_UPLOAD", f"record:pending:{original}", commit=False)
    record = MedicalRecord(patient_id=patient.id, doctor_id=current_user().id, diagnosis=diagnosis, prescription=prescription, attachment_name=attachment_name)
    db.session.add(record)
    db.session.flush()
    notify(patient.id, "Medical record updated", "A synthetic medical record was added to your secure portal.", "record")
    db.session.commit()
    audit("CREATE_MEDICAL_RECORD", f"record:{record.id}")
    flash("Synthetic medical record saved.", "success")
    return redirect(url_for("doctor_dashboard"))


@app.get("/files/<int:record_id>")
@login_required
def protected_file(record_id):
    record = db.session.get(MedicalRecord, record_id)
    user = current_user()
    if not record or not record.attachment_name:
        abort(404)
    authorized = (user.role == "patient" and record.patient_id == user.id) or (user.role == "doctor" and record.doctor_id == user.id)
    if not authorized:
        audit("UNAUTHORIZED_FILE_ACCESS", f"record:{record_id}")
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], record.attachment_name, as_attachment=True, max_age=0)


@app.get("/admin")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", users=User.query.order_by(User.created_at.desc()).all(), appointments=Appointment.query.order_by(Appointment.created_at.desc()).all(), audits=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all(), contacts=ContactMessage.query.order_by(ContactMessage.created_at.desc()).limit(50).all())


@app.post("/admin/users/<int:user_id>/role")
@role_required("admin")
def admin_role(user_id):
    user = db.session.get(User, user_id)
    role = request.form.get("role")
    if not user:
        abort(404)
    if role not in ROLE_VALUES:
        abort(400)
    if user.id == current_user().id and role != "admin":
        flash("You cannot remove your own administrator access.", "danger")
        return redirect(url_for("admin_dashboard")), 400
    old_role = user.role
    user.role = role
    if role == "patient" and not user.patient_profile:
        db.session.add(PatientProfile(user_id=user.id))
    db.session.commit()
    audit("CHANGE_ROLE", f"user:{user.id}:{old_role}->{role}")
    flash("Role updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/contact/<int:message_id>/status")
@role_required("admin")
def admin_contact_status(message_id):
    item = db.session.get(ContactMessage, message_id)
    if not item:
        abort(404)
    status = request.form.get("status")
    if status not in {"New", "In Review", "Resolved"}:
        abort(400)
    item.status = status
    db.session.commit()
    audit("CONTACT_STATUS", f"message:{item.id}:{status}")
    flash("Contact message status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.post("/ai")
@login_required
def ai_assistant():
    payload = request.get_json(silent=True) or {}
    question = str(payload.get("message", "")).strip()[:1000]
    if not question:
        return jsonify(answer="Please ask me a question about MediDesk."), 400
    user = current_user()
    answer = local_ai_answer(question, user)
    if os.environ.get("OPENAI_API_KEY") and os.environ.get("OPENAI_MODEL"):
        try:
            answer = openai_answer(question, user, answer)
        except (HTTPError, URLError, TimeoutError, ValueError, KeyError):
            logger.warning("Optional AI provider unavailable; using local answer")
    audit("AI_ASSISTANT", f"role:{user.role}")
    return jsonify(answer=answer)


def local_ai_answer(question, user):
    q = question.lower()
    if any(k in q for k in ["diagnos", "disease", "what do i have", "prescribe", "medicine should"]):
        return "MediDesk AI cannot diagnose conditions or prescribe treatment. I can explain synthetic demo records and help you navigate MediDesk or manage appointments."
    if "another patient" in q or "someone else" in q or "other patient" in q:
        return "Access denied by design. MediDesk limits patient records to authorized users and enforces the rule on the server, not just in the interface."
    if any(k in q for k in ["book", "appointment", "schedule"]):
        return "To book an appointment, open Appointments, select a doctor, future date and time, enter an optional reason, and confirm. MediDesk checks for an existing booking in that slot."
    if any(k in q for k in ["cancel", "reschedule"]):
        return "Open Appointment History, choose the appointment, and select Cancelled or Reschedule Requested. The doctor receives an in-app notification."
    if any(k in q for k in ["record", "medical"]):
        return "Your Medical Records section contains only records linked to your patient account. Doctors can access relevant records only for patients assigned through appointments."
    if any(k in q for k in ["security", "secure", "protect", "privacy", "rbac"]):
        return "MediDesk uses role-based authorization, CSRF protection, secure password hashing, protected sessions, security headers/CSP, server-side ownership checks, safe file validation and audit logging."
    if any(k in q for k in ["profile", "account"]):
        return "Patients can update their own profile from the Profile section. Account roles are controlled by authorized administrators."
    return "I can help with appointments, profiles, medical-record navigation, MediDesk security, contact/support, and synthetic demo information."


def openai_answer(question, user, fallback):
    system = ("You are MediDesk AI. Only help with navigation, FAQs, appointments, security, "
              "and explaining synthetic/demo records. Never diagnose, prescribe, or reveal private data. "
              f"The user's role is {user.role}. Keep answers concise.")
    body = json.dumps({"model": os.environ["OPENAI_MODEL"], "input": [{"role": "system", "content": system}, {"role": "user", "content": question}], "max_output_tokens": 220}).encode()
    connection = http.client.HTTPSConnection("api.openai.com", timeout=8)
    try:
        connection.request("POST", "/v1/responses", body=body, headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"], "Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status >= 400:
            raise HTTPError("https://api.openai.com/v1/responses", response.status, "provider error", response.headers, None)
        data = json.loads(response.read().decode())
    finally:
        connection.close()
    text = data.get("output_text")
    return text.strip() if text else fallback


@app.errorhandler(403)
def forbidden(_error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


@app.errorhandler(413)
def payload_too_large(_error):
    flash("The uploaded file is too large. Maximum size is 5 MB.", "danger")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(500)
def internal_error(_error):
    db.session.rollback()
    logger.exception("Unhandled application error")
    return render_template("500.html"), 500


@app.cli.command("seed")
def seed():
    db.drop_all()
    db.create_all()
    ensure_demo_data(force=True)
    print("Seeded synthetic demo accounts. Password: Demo@12345")


def ensure_demo_data(force=False):
    demos = [("Demo Patient", "patient@medidesk.local", "patient", None), ("Dr. Sharma", "doctor@medidesk.local", "doctor", "General Medicine"), ("Dr. Rao", "doctor2@medidesk.local", "doctor", "Pediatrics"), ("MediDesk Admin", "admin@medidesk.local", "admin", None)]
    users = {}
    for name, email, role, specialization in demos:
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, role=role, specialization=specialization)
            user.set_password("Demo@12345")
            db.session.add(user)
            db.session.flush()
        users[email] = user
    patient = users["patient@medidesk.local"]
    doctor = users["doctor@medidesk.local"]
    if not patient.patient_profile:
        db.session.add(PatientProfile(user_id=patient.id, phone="+91 90000 00000", dob="2005-05-20", address="Synthetic address", emergency_contact="Synthetic contact"))
    appointment = Appointment.query.filter_by(patient_id=patient.id, doctor_id=doctor.id).first()
    if not appointment:
        appointment = Appointment(patient_id=patient.id, doctor_id=doctor.id, date="2099-10-08", time="10:30", reason="General consultation", status="Confirmed")
        db.session.add(appointment)
        db.session.flush()
    if not MedicalRecord.query.filter_by(patient_id=patient.id, doctor_id=doctor.id).first():
        db.session.add(MedicalRecord(patient_id=patient.id, doctor_id=doctor.id, diagnosis="Synthetic seasonal fever example", prescription="Demo prescription only"))
    if Notification.query.filter_by(user_id=patient.id).count() == 0:
        notify(patient.id, "Welcome to MediDesk", "Your synthetic demo workspace is ready.", "welcome")
    if Notification.query.filter_by(user_id=doctor.id).count() == 0:
        notify(doctor.id, "Demo workspace ready", "Your assigned synthetic appointment is available.", "welcome")
    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_demo_data()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
