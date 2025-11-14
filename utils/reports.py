# utils/reports.py
from weasyprint import HTML
from models import Appointment, Patient, db
from datetime import date
import smtplib
from email.mime.text import MIMEText

def generate_daily_report():
    today = date.today()
    appts = Appointment.query.filter(db.func.date(Appointment.appointment_date) == today).count()
    patients = Patient.query.filter(Patient.status == 'active').count()

    html = f"""
    <h1>Daily Clinic Report - {today}</h1>
    <p><strong>Appointments Today:</strong> {appts}</p>
    <p><strong>Active Patients:</strong> {patients}</p>
    """
    pdf = HTML(string=html).write_pdf()
    
    with open(f"reports/daily_report_{today}.pdf", "wb") as f:
        f.write(pdf)
    
    # Email to admin
    def send_email(to, subject, body, attachment=None):
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = "noreply@clinic.com"
        msg['To'] = to
    
        if attachment:
            # Here you would add code to attach the PDF if needed
            pass
    
        with smtplib.SMTP('localhost') as server:
            server.send_message(msg)
    
    send_email("admin@clinic.ac.za", f"Report {today}", "See attached.", attachment=pdf)