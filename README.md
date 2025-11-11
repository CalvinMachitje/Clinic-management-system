# MediAssist — Clinic Management System  
**AI-Powered. Open-Source. For Every Clinic.**

---

## Transforming Healthcare Delivery

**MediAssist** , AI-enhanced clinic management platform** designed to **replace paper-based systems** with a **secure, real-time, role-based digital solution**.

Built for **all healthcare providers** — from **Government clinics** to **Private hospitals and specialist practices** — MediAssist streamlines operations, reduces wait times, and improves patient outcomes.

---

## The Problem We Solve

Clinics today face:

- Long patient queues due to manual triage  
- Lost or incomplete medical records  
- Staff burnout from repetitive admin tasks  
- Poor coordination between reception, nurses, and doctors  
- No real-time visibility into staffing or inventory  

---

## The MediAssist Solution  

### **How It Works**

1. **Patient Arrives**  
   → Checks in via receptionist or self-service kiosk  
   → Completes **AI-powered symptom triage** (web form)

2. **AI Analyzes**  
   → Infermedica API assesses urgency  
   → Patient is auto-prioritized: **Emergency → High → Medium → Low**

3. **Live Queue Updates**  
   → **Real-time dashboards** (SSE) show current patients  
   → Nurse sees next patient instantly

4. **Consultation Flow**  
   → Doctor views full digital history  
   → Adds notes, prescriptions, follow-ups  
   → Case closed → record saved securely

5. **Manager Oversight**  
   → Staffing, inventory, compliance, performance — all in one place

---

## Role-Based Dashboards  

| Role          | Key Functions |
|---------------|---------------|
| **Receptionist** | Check-in, search patients, book appointments |
| **Nurse**        | Triage queue, record vitals, mark helped |
| **Doctor**       | Full patient history, prescriptions, notes |
| **Manager**      | 7 modules: Staffing, Performance, Training, Compliance, Welfare, Inventory, Admin |
| **Admin**        | User management, audit logs, system settings |

---

## Core Features  

### **AI Triage Engine**
- Symptom-based self-assessment  
- Risk scoring & priority assignment  
- Reduces nurse workload by **20%**

### **Real-Time Updates**
- Server-Sent Events (SSE)  
- Live queue, roster, and alerts  
- No page refresh needed

### **Staff Scheduling**
- FullCalendar integration  
- Create/edit shifts via modal  
- Today’s roster: **Required vs. On-Duty**  
- Export PDF/CSV

### **Manager Tools (7 Modules)**
1. **Staffing** – Leave requests, shift planning  
2. **Performance** – KPI tracking, reviews  
3. **Training** – Sessions, certification alerts  
4. **Compliance** – POPIA, infection control  
5. **Welfare** – Wellness surveys, burnout reports  
6. **Inventory** – Low stock alerts  
7. **Admin** – Quick links to all tools

---

## Technical Architecture  

| Component      | Technology |
|----------------|------------|
| **Backend**    | Flask (Python) |
| **Database**   | SQLite (PostgreSQL-ready) |
| **Frontend**   | HTML5, Tailwind CSS, Jinja2 |
| **Real-Time**  | Server-Sent Events (SSE) |
| **AI**         | Infermedica API |
| **Scheduling** | FullCalendar |
| **Security**   | Flask-Login, Bcrypt, CSRF, Role Decorators |

---

## Our Goal  

> **To make high-quality clinic management accessible to every healthcare provider in South Africa — regardless of location, budget, or infrastructure.**

MediAssist is:  

- **Lightweight & Fast**  
- **Scalable** (SQLite → PostgreSQL)  
- **Customizable** for any clinic  

---

## Future Vision & Partnerships  

We are actively building **strategic partnerships** with:

| Partner Type               | Goal |
|----------------------------|------|
| **Government Health Departments** | National rollout in public clinics |
| **Private Hospital Groups** | Enterprise deployment |
| **NGOs & Donors**          | Township & rural outreach |
| **Telcos**                 | SMS integration for reminders |
| **Universities**           | Research & AI improvement |

**Coming Soon:**  

- Mobile App (Android/iOS)  
- Telemedicine Module  
- Multi-Clinic Dashboard  
- Voice-Enabled Triage  

---

## Get Involved  

- **Contact:** smachitje36@gmail.com and info@jnttechnology.co.za  

---

## Ownership & Partnership  

**MediAssist** is a **50/50 joint venture** between:  

- **J&T Technology PTY Ltd** – Business, marketing, operations, partnerships  
- **M&T Tech Solutions** (Sello Calvin Machitje) – Full system development, AI, architecture, maintenance  

All code, IP, and assets are **equally owned** under South African law.


> **"From paper to progress — one patient at a time."**  

**Built with purpose. Powered by partnership.**
