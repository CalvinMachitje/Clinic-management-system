# models.py
# Medi-Assist™ 
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# ========================================
# 1. Employee
# ========================================
class Employee(db.Model):
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    role = db.Column(db.String(20), nullable=False)
    hire_date = db.Column(db.String(20))
    availability = db.Column(db.String(20), default='available')
    profile_image = db.Column(db.String(255), default='default.jpg')
    staff_number = db.Column(db.String(50), unique=True, nullable=False, default='TEMPSTAFF')
    specialization = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    patients = db.relationship('Patient', backref='doctor', lazy=True)
    assigned_appointments = db.relationship(
        'Appointment',
        back_populates='helper',
        foreign_keys='Appointment.helper_id',
        primaryjoin='Employee.staff_number == Appointment.helper_id',
        overlaps="helper",
        lazy='dynamic'
    )

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return self.active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def __repr__(self):
        return f"<Employee {self.staff_number} - {self.role}>"


# ========================================
# 2. Patient
# ========================================
class Patient(db.Model):
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.String(20))
    gender = db.Column(db.String(10))
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(20))
    medical_history = db.Column(db.Text)
    allergies = db.Column(db.Text)
    current_medications = db.Column(db.Text)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    clinic = db.Column(db.String(50), default='Clinic A')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')

    appointments = db.relationship('Appointment', backref='patient', lazy=True)
    prescriptions = db.relationship('Prescription', backref='patient', lazy=True)
    visits = db.relationship('Visit', backref='patient', lazy=True)
    emergency_requests = db.relationship('EmergencyRequest', backref='patient', lazy=True)
    payments = db.relationship('Payment', backref='patient', lazy=True)
    helped = db.relationship('HelpedPatient', backref='patient', lazy=True)

    def __repr__(self):
        return f"<Patient {self.first_name} {self.last_name}>"


# ========================================
# 3. Appointment
# ========================================
class Appointment(db.Model):
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    appointment_date = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='scheduled')
    reason = db.Column(db.Text)
    created_by_role = db.Column(db.String(20), default='receptionist')
    helper_id = db.Column(db.String(50)) 
    
    helper = db.relationship(
        'Employee',
        back_populates='assigned_appointments',
        foreign_keys=[helper_id],
        primaryjoin='Appointment.helper_id == Employee.staff_number',
        overlaps="assigned_appointments",
        lazy='joined'
    )

    def __repr__(self):
        return f"<Appointment {self.id} - {self.status}>"


# ========================================
# 4. Prescription
# ========================================
class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    nurse_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    medication_name = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(100), nullable=False)
    instructions = db.Column(db.Text)
    prescribed_date = db.Column(db.String(20), nullable=False)

    nurse = db.relationship('Employee', backref='prescriptions', lazy=True)

    def __repr__(self):
        return f"<Prescription {self.medication_name}>"


# ========================================
# 5. Visit
# ========================================
class Visit(db.Model):
    __tablename__ = 'visits'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    visit_time = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text)
    def __repr__(self): return f"<Visit {self.id}>"


# ========================================
# 6. EmergencyRequest
# ========================================
class EmergencyRequest(db.Model):
    __tablename__ = 'emergency_requests'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    request_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    def __repr__(self): return f"<Emergency {self.id} - {self.status}>"


# ========================================
# 7. Message
# ========================================
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.Column(db.String(50), nullable=False)
    def __repr__(self): return f"<Message {self.title}>"


# ========================================
# 8. SystemSetting
# ========================================
class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    def __repr__(self): return f"<SystemSetting {self.key}={self.value}>"


# ========================================
# 9. Preference
# ========================================
class Preference(db.Model):
    __tablename__ = 'preferences'
    id = db.Column(db.Integer, primary_key=True)
    staff_number = db.Column(db.String(50), unique=True)
    theme = db.Column(db.String(20), default='dark')
    def __repr__(self): return f"<Pref {self.staff_number}>"


# ========================================
# 10. Announcement
# ========================================
class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pinned = db.Column(db.Boolean, default=False)
    target_role = db.Column(db.String(20), default='all')
    def __repr__(self): return f"<Announcement {self.title}>"


# ========================================
# 11. Payment
# ========================================
class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    def __repr__(self): return f"<Payment R{self.amount}>"


# ========================================
# 12. Notification
# ========================================
class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self): return f"<Notif {self.title}>"


# ========================================
# 13. HelpedPatient
# ========================================
class HelpedPatient(db.Model):
    __tablename__ = 'helped_patients'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    nurse_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    appointment_date = db.Column(db.String(50))
    helped_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.Text)
    notes = db.Column(db.Text)
    nurse = db.relationship('Employee', backref='helped_patients', lazy=True)
    def __repr__(self): return f"<Helped {self.id}>"


# ========================================
# 14. SelfBookedAppointment
# ========================================
class SelfBookedAppointment(db.Model):
    __tablename__ = 'self_booked_appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(200), nullable=False)
    patient_phone = db.Column(db.String(20))
    patient_email = db.Column(db.String(120))
    appointment_date = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.Text)
    doctor_staff_number = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self): return f"<SelfBook {self.patient_name}>"


# ========================================
# 15. WalkinQueue
# ========================================
class WalkinQueue(db.Model):
    __tablename__ = 'walkin_queue'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(50), nullable=False)
    patient_name = db.Column(db.String(200), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text)
    arrived_at = db.Column(db.String(50), nullable=False)
    def __repr__(self): return f"<Walkin {self.patient_name}>"


# ========================================
# 16. AuditLog
# ========================================
class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.Text, nullable=False)
    performed_by = db.Column(db.String(50), nullable=False)
    target_user = db.Column(db.String(50))
    details = db.Column(db.Text)
    timestamp = db.Column(db.String(50), nullable=False)
    def __repr__(self): return f"<Audit {self.action}>"


# ========================================
# 17–24. Missing classes from imports
# Inventory, Billing, Task, Attendance, LeaveRequest,
# Certification, PerformanceReview, TrainingSession
# ========================================

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    min_stock = db.Column(db.Integer, default=0)
    avg_daily_use = db.Column(db.Float, default=0.0)
    last_restocked = db.Column(db.DateTime)
    def __repr__(self):
        return f"<Inventory {self.item_name} qty={self.quantity}>"

class Billing(db.Model):
    __tablename__ = 'billing'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    cost = db.Column(db.Float, nullable=False)
    billing_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    patient = db.relationship('Patient', backref='billings', lazy=True)
    def __repr__(self):
        return f"<Billing {self.id} - R{self.cost}>"

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    assigned_to = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    due_date = db.Column(db.DateTime)
    def __repr__(self):
        return f"<Task {self.title} - {self.status}>"

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.String(20))
    check_out = db.Column(db.String(20))
    employee = db.relationship('Employee', backref='attendances', lazy=True)
    def __repr__(self):
        return f"<Attendance {self.employee_id} - {self.date}>"

class LeaveRequest(db.Model):
    __tablename__ = 'leave_requests'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    employee = db.relationship('Employee', backref='leave_requests', lazy=True)
    def __repr__(self):
        return f"<LeaveRequest {self.employee_id} - {self.status}>"

class Certification(db.Model):
    __tablename__ = 'certifications'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    issue_date = db.Column(db.Date)
    expiry_date = db.Column(db.Date)
    employee = db.relationship('Employee', backref='certifications', lazy=True)
    def __repr__(self):
        return f"<Certification {self.name} - {self.employee_id}>"

class PerformanceReview(db.Model):
    __tablename__ = 'performance_reviews'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    reviewer = db.Column(db.String(100))
    review_date = db.Column(db.Date)
    score = db.Column(db.Float)
    notes = db.Column(db.Text)
    employee = db.relationship('Employee', backref='performance_reviews', lazy=True)
    def __repr__(self):
        return f"<PerformanceReview {self.employee_id} - {self.score}>"

class TrainingSession(db.Model):
    __tablename__ = 'training_sessions'
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(200), nullable=False)
    trainer = db.Column(db.String(100))
    date = db.Column(db.Date)
    duration_hours = db.Column(db.Float)
    attendees = db.Column(db.Text)
    def __repr__(self):
        return f"<TrainingSession {self.topic} - {self.date}>"

# ========================================
# 25. StaffSchedule (already defined)
# ========================================
class StaffSchedule(db.Model):
    __tablename__ = 'staff_schedule'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    shift_date = db.Column(db.Date)
    shift_type = db.Column(db.String(20))
    notes = db.Column(db.Text)
    employee = db.relationship('Employee', backref='shifts', lazy=True)
    def __repr__(self):
        return f"<StaffSchedule {self.employee_id} - {self.shift_date}>"