# Project Approach & Architecture — Build Secure 24

**Team ID:** 15  
**Project Name:** MediDesk — Secure Clinic & Appointment Management  
**Team Name:** Cyber Sentials  
**Team Size:** 4 Members  
**Primary Track / Domain:** HealthTech

---

## 1. Problem Understanding, Scope & Threat Model

### 1.1 Problem Statement & Real-World Motivation
MediDesk provides a secure clinic and appointment management workflow for the PS-04 HealthTech problem statement. The application covers patient registration/login, doctor authentication, patient profiles, appointment booking and management, synthetic medical records, doctor workflows, administrator management, and appointment history.

Only synthetic/demo patient information is used. The application is designed to demonstrate secure access separation rather than real clinical decision support.

### 1.2 Target Users & Personas
- **Patient:** manages their own profile, appointments, appointment history, and synthetic records.
- **Doctor:** accesses assigned appointments and relevant patient context, updates appointment status, and creates synthetic records for assigned patients.
- **Admin:** manages users, reviews appointments, and views security-relevant audit activity.

### 1.3 Threat Model & Attack Surface
**Critical assets:** credentials, session state, patient profile data, synthetic medical records, appointment data, uploaded attachments, audit records.

**Potential attack vectors:** broken access control/IDOR, credential attacks, CSRF, malicious uploads, injection, session theft, unauthorized role changes, information disclosure, security misconfiguration.

**OWASP focus:** Broken Access Control, Identification and Authentication Failures, Injection, Security Misconfiguration, Cryptographic Failures, and Software/Data Integrity risks.

---

## 2. Technical Architecture & Secure System Design

### 2.1 High-Level Architecture Overview
```text
Browser
  │ HTTPS in deployment / local HTTP for development
  ▼
Flask + Jinja UI
  │
  ├── Authentication / Session
  ├── Role-Based Access Control
  ├── Appointment Services
  ├── Medical Record Services
  ├── Secure Upload Handling
  └── Audit Logging
  │
  ▼
SQLAlchemy ORM ──► SQLite (local demo) / DATABASE_URL in deployment
  │
  └── Private upload storage for validated attachments
```

### 2.2 Data Flow & Component Interaction
1. User authenticates through the Flask login endpoint.
2. Credentials are verified against a scrypt password hash.
3. A server-side session identifies the authenticated user.
4. Role decorators enforce patient/doctor/admin access before protected handlers execute.
5. Object-level checks ensure patients only access their own records and doctors only access assigned patient records.
6. SQLAlchemy ORM handles normal persistence; user-controlled values are not concatenated into SQL.
7. Medical attachments are size-limited, signature-checked, renamed with UUIDs, and kept outside public static assets.
8. Security-relevant actions are written to the audit log.

### 2.3 Technology Stack Rationale
- **Backend:** Flask — lightweight, transparent server-side routing and security middleware suitable for a 24-hour prototype.
- **Frontend:** Jinja2 templates + CSS — keeps the UI integrated with server-side authorization and avoids a separate API/client deployment for the demo.
- **Database:** SQLite locally through SQLAlchemy — fast local setup while retaining a database abstraction for deployment.
- **Authentication:** Werkzeug scrypt password hashing + secure Flask session cookies.
- **Security middleware:** Flask-WTF CSRF protection and Flask-Talisman security headers/CSP.

### 2.4 Defense-in-Depth Security Controls
1. **Authentication & Session Security:** scrypt password hashes; session cleared on login/logout; HttpOnly and SameSite cookies.
2. **Authorization & Access Control:** role-based decorators plus patient ownership and doctor-assignment checks.
3. **Input Validation:** length limits, controlled role/status values, ORM queries, and server-side validation.
4. **File Security:** 5 MB limit, PDF/PNG/JPG allowlist, magic-byte detection, UUID filenames, private storage.
5. **Secrets & Configuration:** `SECRET_KEY`, database URL, and production cookie settings are environment-driven.
6. **Security Headers:** CSP, frame denial, referrer policy, and Talisman-managed response headers.
7. **Auditability:** authentication, profile, appointment, record, and role changes are logged.

---

## 3. Implementation Milestones & 24-Hour Timeline

| Milestone / Phase | Objective | Status |
|---|---|---|
| Foundation & onboarding | Official repo onboarding, team metadata, application structure | Complete |
| Core domain & auth | Patient/doctor/admin workflows and secure authentication | Complete |
| Security hardening | RBAC, CSRF, upload validation, security headers, audit logging | Complete |
| UI polish | Stitch-guided healthcare SaaS visual system integrated into Flask templates | Complete |
| Testing & deployment | Local verification, security testing, deployment record, final freeze | In progress |

---

## 4. Architecture Decision Records

### ADR-001: Server-rendered Flask/Jinja UI
- **Status:** Accepted
- **Context:** The hackathon requires a working web application quickly while preserving server-side authorization.
- **Options:** SPA + API; server-rendered Flask/Jinja.
- **Decision:** Flask/Jinja was selected to keep authentication, authorization, forms, CSRF, and UI close to the same trust boundary.
- **Security trade-off:** Fewer moving parts and a smaller attack surface for the demo; future scaling can split the frontend/API if needed.

### ADR-002: Stitch-guided UI without replacing the application backend
- **Status:** Accepted
- **Context:** The team wanted a professional healthcare portal visual design while retaining working application behavior.
- **Decision:** Use the Stitch-generated MediDesk screens as the visual reference and implement the design in the application's own Jinja templates/CSS.
- **Security trade-off:** No static-only prototype or duplicated backend is introduced; existing server-side controls remain authoritative.

---

## 5. Engineering Journal

### 2026-10-05 — Integration milestone
- **Focus:** Integrate the working MediDesk application into the official Build Secure repository and align the interface with the Stitch-generated healthcare portal design.
- **Key result:** Application source placed under `src/`; team metadata recorded; responsive clinical workspace UI added; protected error pages and health endpoint added.

---

## 6. Testing, Security Verification & Deployment Record

### 6.1 Testing & Security Verification Strategy
Planned/required verification before final freeze:
- Patient/doctor/admin login and role separation
- Patient A versus Patient B record access
- Doctor assigned versus unassigned patient access
- Appointment booking and status transitions
- File type/size validation
- CSRF rejection for protected POST actions
- `/health` availability
- 403/404 handling
- SAST/SCA/DAST with the team's selected security tooling (Semgrep/Bandit/pip-audit/ZAP/Burp as applicable)

### 6.2 Deployment Verification
- **Live Deployment Platform:** To be recorded after deployment.
- **Deployment URL:** To be recorded in `metadata/submission.yaml`.
- **Health Check:** `/health`
- **Final commit SHA:** To be recorded at code freeze.

### 2026-10-05 — Final UI/AI polish pass
- Added public doctor directory, FAQ, Contact Us, Security Center and polished responsive landing/auth experiences.
- Added patient notifications and doctor appointment notifications through a dedicated notification model.
- Added admin support-message workflow with auditable status transitions.
- Added MediDesk AI assistant. The assistant is intentionally bounded to navigation, FAQs, appointment guidance, security explanations and synthetic-record explanations; diagnosis and prescribing requests are refused. Optional live OpenAI Responses API integration is environment-controlled and no API secret is stored in source.
- Added automatic non-destructive demo-data initialization so missing synthetic demo accounts can be recreated at application startup without dropping existing data.
