# utils/reminders.py
from datetime import datetime, timedelta
from models import db, Appointment, Patient
import smtplib
from email.mime.text import MIMEText

def send_reminders():
    tomorrow = (datetime.now() + timedelta(days=1)).date()
    appointments = Appointment.query.filter(
        db.func.date(Appointment.appointment_date) == tomorrow,
        Appointment.status == 'scheduled'
    ).all()

    for appt in appointments:
        patient = appt.patient
        msg = f"Reminder: Your appointment is tomorrow at {appt.appointment_date}. Clinic A."
        
        # Send SMS (Twilio) or Email
        send_email(patient.email, "Appointment Reminder", msg)
        # send_sms(patient.phone, msg)  # Add Twilio later

def send_email(to, subject, body):
    # Use Gmail, Outlook, or SendGrid
    pass  # Implement with your SMTP