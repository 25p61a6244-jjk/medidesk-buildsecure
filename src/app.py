import os
import uuid
from functools import wraps
from datetime import datetime
from pathlib import Path

import filetype
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for, send_from_directory
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

try:
    from .config import Config
    from .models import db, User, PatientProfile, Appointment, MedicalRecord, AuditLog
except ImportError:
    from config import Config
    from models import db, User, PatientProfile, Appointment, MedicalRecord, AuditLog

load_dotenv()
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.from_object(Config)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)

csp = {
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
Talisman(app, content_security_policy=csp, force_https=False, frame_options="DENY",
         strict_transport_security=False, referrer_policy="strict-origin-when-cross-origin")

ALLOWED_TYPES = {"pdf": "application/pdf", "jpg": "image/jpeg", "png": "image/png"}

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
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return deco

def audit(action, target=""):
    u = current_user()
    db.session.add(AuditLog(actor_id=u.id if u else None, action=action,
                            target=target, ip=request.remote_addr))
    db.session.commit()

@app.context_processor
def inject_user():
    return {"current_user": current_user()}

@app.get("/health")
def health():
    return {"status": "ok", "service": "medidesk"}, 200

@app.route("/")
def index():
    return redirect(url_for("dashboard")) if current_user() else render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not name or "@" not in email or len(password) < 8:
            flash("Use a valid name, email and password of at least 8 characters.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "danger")
            return render_template("register.html")
        u = User(name=name, email=email, role="patient")
        u.set_password(password)
        db.session.add(u); db.session.flush()
        db.session.add(PatientProfile(user_id=u.id))
        db.session.commit()
        flash("Registration complete. Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(password):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")
        session.clear()
        session["user_id"] = u.id
        session.permanent = True
        audit("LOGIN", f"user:{u.id}")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    audit("LOGOUT", f"user:{current_user().id}")
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    if u.role == "patient":
        return redirect(url_for("patient_dashboard"))
    if u.role == "doctor":
        return redirect(url_for("doctor_dashboard"))
    return redirect(url_for("admin_dashboard"))

@app.route("/patient")
@role_required("patient")
def patient_dashboard():
    u = current_user()
    appointments = Appointment.query.filter_by(patient_id=u.id).order_by(Appointment.date, Appointment.time).all()
    doctors = User.query.filter_by(role="doctor").order_by(User.name).all()
    records = MedicalRecord.query.filter_by(patient_id=u.id).order_by(MedicalRecord.created_at.desc()).all()
    return render_template("patient_dashboard.html", appointments=appointments, doctors=doctors, records=records, today=datetime.now().strftime("%Y-%m-%d"))

@app.post("/patient/profile")
@role_required("patient")
def update_profile():
    u=current_user()
    p=u.patient_profile or PatientProfile(user_id=u.id)
    p.phone=request.form.get("phone","").strip()[:30]
    p.dob=request.form.get("dob","").strip()[:20]
    p.address=request.form.get("address","").strip()[:250]
    p.emergency_contact=request.form.get("emergency_contact","").strip()[:120]
    db.session.add(p); db.session.commit()
    audit("UPDATE_PROFILE", f"patient:{u.id}")
    flash("Profile updated.", "success")
    return redirect(url_for("patient_dashboard"))

@app.post("/patient/appointments/book")
@role_required("patient")
def book_appointment():
    doctor_id=request.form.get("doctor_id", type=int)
    date=request.form.get("date","").strip()
    time=request.form.get("time","").strip()
    reason=request.form.get("reason","").strip()[:250]
    doctor=db.session.get(User, doctor_id)
    if not doctor or doctor.role != "doctor" or not date or not time:
        flash("Choose a valid doctor, date and time.", "danger"); return redirect(url_for("patient_dashboard"))
    exists=Appointment.query.filter_by(doctor_id=doctor.id,date=date,time=time,status="Confirmed").first()
    if exists:
        flash("That slot is already booked.", "danger"); return redirect(url_for("patient_dashboard"))
    ap=Appointment(patient_id=current_user().id,doctor_id=doctor.id,date=date,time=time,reason=reason)
    db.session.add(ap); db.session.commit()
    audit("BOOK_APPOINTMENT", f"appointment:{ap.id}")
    flash("Appointment booked.", "success")
    return redirect(url_for("patient_dashboard"))

@app.post("/patient/appointments/<int:appointment_id>/status")
@role_required("patient")
def patient_appointment_status(appointment_id):
    ap=db.session.get(Appointment, appointment_id)
    if not ap or ap.patient_id != current_user().id: abort(404)
    status=request.form.get("status")
    if status not in {"Cancelled","Reschedule Requested"}: abort(400)
    ap.status=status; db.session.commit()
    audit("APPOINTMENT_STATUS", f"appointment:{ap.id}:{status}")
    flash("Appointment updated.", "success")
    return redirect(url_for("patient_dashboard"))

@app.route("/doctor")
@role_required("doctor")
def doctor_dashboard():
    u=current_user()
    appointments=Appointment.query.filter_by(doctor_id=u.id).order_by(Appointment.date,Appointment.time).all()
    patient_ids={a.patient_id for a in appointments}
    patients=User.query.filter(User.id.in_(patient_ids)).all() if patient_ids else []
    return render_template("doctor_dashboard.html", appointments=appointments, patients=patients)

@app.post("/doctor/appointments/<int:appointment_id>/status")
@role_required("doctor")
def doctor_appointment_status(appointment_id):
    ap=db.session.get(Appointment, appointment_id)
    if not ap or ap.doctor_id != current_user().id: abort(404)
    status=request.form.get("status")
    if status not in {"Confirmed","Completed","Cancelled","Reschedule Requested"}: abort(400)
    ap.status=status; db.session.commit()
    audit("DOCTOR_APPOINTMENT_STATUS", f"appointment:{ap.id}:{status}")
    flash("Appointment status updated.", "success")
    return redirect(url_for("doctor_dashboard"))

@app.post("/doctor/records")
@role_required("doctor")
def add_record():
    patient_id=request.form.get("patient_id", type=int)
    diagnosis=request.form.get("diagnosis","").strip()[:500]
    prescription=request.form.get("prescription","").strip()[:1000]
    patient=db.session.get(User, patient_id)
    if not patient or patient.role != "patient": abort(404)
    assigned=Appointment.query.filter_by(patient_id=patient.id,doctor_id=current_user().id).first()
    if not assigned: abort(403)
    attachment_name=None
    f=request.files.get("attachment")
    if f and f.filename:
        data=f.read(1024)
        kind=filetype.guess(data)
        if not kind or kind.extension not in ALLOWED_TYPES:
            flash("Only PDF, PNG or JPG files are accepted.", "danger")
            return redirect(url_for("doctor_dashboard"))
        f.stream.seek(0)
        safe=secure_filename(f.filename)
        final=f"{uuid.uuid4().hex}_{safe}"
        f.save(Path(app.config["UPLOAD_FOLDER"]) / final)
        attachment_name=final
    r=MedicalRecord(patient_id=patient.id,doctor_id=current_user().id,
                    diagnosis=diagnosis,prescription=prescription,attachment_name=attachment_name)
    db.session.add(r); db.session.commit()
    audit("CREATE_MEDICAL_RECORD", f"record:{r.id}")
    flash("Synthetic medical record saved.", "success")
    return redirect(url_for("doctor_dashboard"))

@app.route("/files/<int:record_id>")
@login_required
def protected_file(record_id):
    r=db.session.get(MedicalRecord,record_id)
    u=current_user()
    if not r: abort(404)
    if u.role=="patient" and r.patient_id != u.id: abort(404)
    if u.role=="doctor" and r.doctor_id != u.id: abort(404)
    if u.role=="admin": pass
    if not r.attachment_name: abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"],r.attachment_name,as_attachment=True)

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html",
        users=User.query.order_by(User.created_at.desc()).all(),
        appointments=Appointment.query.order_by(Appointment.created_at.desc()).all(),
        audits=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all())

@app.post("/admin/users/<int:user_id>/role")
@role_required("admin")
def admin_role(user_id):
    u=db.session.get(User,user_id)
    if not u: abort(404)
    role=request.form.get("role")
    if role not in {"patient","doctor","admin"}: abort(400)
    u.role=role; db.session.commit()
    audit("CHANGE_ROLE", f"user:{u.id}:{role}")
    flash("Role updated.", "success")
    return redirect(url_for("admin_dashboard"))

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

@app.cli.command("seed")
def seed():
    db.drop_all(); db.create_all()
    users=[
        ("Demo Patient","patient@medidesk.local","patient"),
        ("Dr. Sharma","doctor@medidesk.local","doctor"),
        ("Dr. Rao","doctor2@medidesk.local","doctor"),
        ("MediDesk Admin","admin@medidesk.local","admin")]
    objs={}
    for name,email,role in users:
        u=User(name=name,email=email,role=role,specialization="General Medicine" if role=="doctor" else None)
        u.set_password("Demo@12345")
        db.session.add(u); db.session.flush(); objs[role+email]=u
    db.session.add(PatientProfile(user_id=objs["patientpatient@medidesk.local"].id,
                                  phone="+91 90000 00000",dob="2005-05-20",address="Synthetic address"))
    p=objs["patientpatient@medidesk.local"]; d=objs["doctordoctor@medidesk.local"]
    ap=Appointment(patient_id=p.id,doctor_id=d.id,date="2026-10-08",time="10:30 AM",reason="General consultation",status="Confirmed")
    db.session.add(ap); db.session.flush()
    db.session.add(MedicalRecord(patient_id=p.id,doctor_id=d.id,
        diagnosis="Synthetic seasonal fever example",prescription="Demo prescription only"))
    db.session.commit()
    print("Seeded demo accounts. Password: Demo@12345")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
