Overview

The Clinic Management System (CMS) is a web-based healthtech solution designed to modernize clinic operations in underserved areas, such as South African townships and broader African healthcare systems. Built with Flask (Python web framework) and SQLite as the database, it replaces outdated paper-based filing systems with a secure, scalable digital platform. The system features role-based dashboards for efficient patient management, appointment scheduling, and AI-driven triage to reduce wait times and administrative burdens.

Problem
Clinics in underserviced areas often rely on manual paper-based systems, leading to inefficiencies such as long wait times, data loss risks, delayed care, and staff overload. This results in reduced healthcare access, errors in record-keeping, and overall operational bottlenecks.

Solution
CMS provides a digital alternative that streamlines clinic operations through:

Digitized patient records and appointment management.
Role-based dashboards tailored for nurses, receptionists, doctors, and admins.
AI integration for patient self-triage, prioritizing urgent cases and reducing nurse workload by up to 20%.
Real-time updates and secure data handling to improve efficiency and patient outcomes.

The system supports small-to-medium clinics, handling 10-50 patients and 5-10 staff, with scalability for larger networks.
Features
Core Functionality

Patient Management: Store and retrieve patient data (name, contact, medical history, triage results, status).
Appointment Scheduling: Online booking with real-time status updates (pending/helped/cancelled) and SMS reminders.
AI Integration: Patient self-triage using health/medical APIs to recommend actions (e.g., "Consult Nurse" or "See Doctor").
Security: Role-based access control, password hashing, and secure API key storage via environment variables.
Performance Tracking: Logs staff actions, with metrics like database size and system uptime.

Role-Based Dashboards
Dashboards use a modern, user-friendly design with calming colors and real-time updates via Server-Sent Events (SSE).

Nurse Dashboard: Manage waiting lists and triage; table with patient details and actions (e.g., Mark Helped).
Receptionist Dashboard: Track appointments; table with filters for daily views and triage submissions.
Doctor Dashboard: Access patient data; table for records, history, and updates.
Admin Dashboard: Oversee performance; summaries, staff tables, and filters.

Installation
Prerequisites

Python 3.8+
Flask, requests, python-dotenv.

Install dependencies:
pip install -r requirements.txt

Initialize database: python init_db.py.
Run: python app.py (access at http://localhost:5000).

Usage

Login with role-based credentials.
Patients submit symptoms via portal for AI triage.
Navigate dashboards post-login.

Risk Mitigations

Data Security: Implements role-based access, password hashing, and encrypted API storage to prevent unauthorized access and data breaches.
Scalability Issues: Designed with SQLite for small setups but compatible with PostgreSQL for growth; cloud infrastructure support for handling increased loads.
AI Reliability: Uses established APIs like Infermedica; includes manual overrides for triage results to ensure clinical accuracy.
Downtime: Real-time updates via SSE and performance logs for monitoring; recommends backups and cloud hosting for high availability.
User Adoption: Intuitive dashboards with training resources; open-source nature allows customization.
Compliance: Aligns with healthcare data standards (e.g., secure handling for privacy); regular updates for vulnerability patches.

Why Choose This System Compared to Existing Similar Systems
CMS stands out for its affordability, AI focus, and township-specific tailoring, while being open-source and lightweight.

Compared to OpenMRS: Lighter footprint with built-in AI triage and real-time updates; easier for small clinics without complex setups.
Compared to BandaGo: Open-source vs. proprietary, reducing costs; emphasizes scalability for underserviced areas.
Compared to PappyJoe: Township/rural focus over urban; no subscription lock-in, with AI enhancements for triage.
Compared to LeHealth: AI-driven features for personalized care; better integration for real-time operations.

Overall, CMS offers cost savings, enhanced efficiency, and better patient outcomes through automation, making it ideal for resource-constrained environments.
Team

Calvin Machitje: System Developer (smachitje36@gmail.com)
Musa: System Researcher (cindimosa19@gmail.com)
Nkosi: Project Manager (ndawosen@gmail.com)
