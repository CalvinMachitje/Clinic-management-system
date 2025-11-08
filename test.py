from models import (
    db,
    Employee,
    Patient,
    Appointment,
    Prescription,
    Visit,
    EmergencyRequest,
    Message,
    SystemSetting,
    Preference,
    Announcement,
    Payment,
    Notification,
    HelpedPatient,
    SelfBookedAppointment,
    WalkinQueue,
    AuditLog
)
from script import app

with app.app_context():
    admin = Employee.query.filter_by(email='admin@clinic.com').first()
    print(f"Logged in: {admin.first_name} {admin.last_name} ({admin.staff_number})")