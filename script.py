from flask import Flask, g, json, request, current_app, redirect, url_for, render_template, session, flash, Response, jsonify, abort, stream_with_context
from markupsafe import Markup
from datetime import datetime, date, timedelta
from flask.logging import create_logger
from werkzeug.utils import secure_filename
import secrets, string, jinja2, traceback, csv, threading, time, json, re, random, logging, os, sqlite3
from models import db, Announcement
from sqlalchemy import or_
from collections import deque
queue_lock = threading.Lock()
from queue import Queue
from threading import Lock
from flask_caching import Cache
appointment_queue = Queue()
waiting_patients_queue = Queue()
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import DateField, StringField, PasswordField, SubmitField, EmailField, DateTimeField, BooleanField, SelectField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import send_file
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
from pathlib import Path
from flask_migrate import Migrate   # ← ONLY ADDED THIS LINE

load_dotenv()
from models import (
    db,
    Inventory,
    Billing,
    Task,
    Attendance,
    LeaveRequest,
    Certification,
    PerformanceReview,
    TrainingSession,
    StaffSchedule,
    Employee, Patient, Appointment, Prescription, Visit, EmergencyRequest,
    Message, SystemSetting, Preference, Announcement, Payment, Notification,
    HelpedPatient, SelfBookedAppointment, WalkinQueue, AuditLog
)

# ===========================
# LOAD ENV + APP SETUP
# ===========================
load_dotenv()

app = Flask(__name__, static_folder='static')

# Critical config
instance_path = Path("instance")
instance_path.mkdir(exist_ok=True)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    f"sqlite:///{instance_path / 'clinicinfo.db'}"
).replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# =========================== FIXED PART – THIS IS THE ONLY REAL FIX ===========================
db.init_app(app)                  # Connects the db from models.py to this Flask app
migrate = Migrate(app, db)        # Optional but recommended
# ==============================================================================================

# ===========================
# EXTENSIONS
# ===========================
csrf = CSRFProtect(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
login_manager = LoginManager()
login_manager.login_view = 'login_page'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.init_app(app)

# ===========================
# FOLDERS & SETTINGS
# ===========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===========================
# LOGGING & FILTERS
# ===========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def jinja_strftime(value, format='%H:%M'):
    if not value: return ''
    try:
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return dt.strftime(format)
    except:
        return value[:5]
app.jinja_env.filters['strftime'] = jinja_strftime
app.jinja_env.filters['nl2br'] = lambda v: Markup(v.replace('\n', '<br>\n')) if v else ''

# Globals
clients = set()
message_queue = deque()
lock = threading.Lock()

# ===========================
# USER LOADER (Flask-Login + SQLAlchemy)
# ===========================
class User(UserMixin):
    def __init__(self, id, role):
        self.id = str(id)
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))

@app.context_processor
def inject_user():
    if current_user.is_authenticated:
        return dict(
            current_user=current_user,
            user_fullname=f"{current_user.first_name} {current_user.last_name}".strip(),
            user_role=current_user.role,
            user_staff_number=current_user.staff_number,
            user_id=current_user.id
        )
    return dict(
        current_user=None,
        user_fullname='Guest',
        user_role='guest',
        user_staff_number=None,
        user_id=None
    )

# ===========================
# DECORATORS
# ===========================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Admin access required.", "error")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role not in required_roles:
                flash("Access denied. Insufficient permissions.", "error")
                return redirect(url_for('login_page'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ===========================
# DATABASE INITIALIZATION 
# ===========================
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables checked/created.")

        # Create first admin if none exists
        if not Employee.query.filter_by(role='admin').first():
            admin = Employee(
                staff_number="MED001",
                first_name="Medi",
                last_name="Admin",
                email="admin@mediassist.co.za",        # ← Fixed: removed duplicate first_name=
                password=generate_password_hash("Medi2025!"),
                role="admin",
                active=True
            )
            db.session.add(admin)
            db.session.commit()
            print("FIRST ADMIN CREATED → Staff: MED001 | Pass: Medi2025!")

def generate_staff_number():
    last_employee = Employee.query.order_by(Employee.id.desc()).first()
    last_num = int(last_employee.staff_number.replace('STAFF', '') or 0) if last_employee else 0
    return f"STAFF{str(last_num + 1).zfill(3)}"

def get_db_connection():
    if not hasattr(g, 'sqlite_db'):
        db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'clinicinfo.db')
        g.sqlite_db = sqlite3.connect(db_path, check_same_thread=False)
        g.sqlite_db.row_factory = sqlite3.Row
    return g.sqlite_db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'sqlite_db', None)
    if db is not None:
        db.close()

@app.route('/')
def default_page():
    if current_user.is_authenticated:
        redirect_map = {
            'admin': 'admin_dashboard',
            'doctor': 'doctor_dashboard',
            'nurse': 'nurse_dashboard',
            'receptionist': 'reception_dashboard',
            'manager': 'manager_dashboard'
        }
        return redirect(url_for(redirect_map.get(current_user.role, 'login_page')))
    return render_template('homepage/defaultPage.html')

@app.route('/vaccinations')
def vaccinations_homepage():
    return render_template('homepage/vaccinationsHomepage.html')

@app.route('/consultations')
def consultation_homepage():
    return render_template('homepage/consultationsHomepage.html')

@app.route('/emergency')
def emergency_homepage():
    return render_template('homepage/emergencyHomepage.html')

@app.route('/about')
def about():
    return render_template('homepage/about.html')

@app.route('/contact')
def contact():
    return render_template('homepage/contact.html')

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username/Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    next = HiddenField()  # ← ADD THIS
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('doctor', 'Doctor'), ('nurse', 'Nurse'), ('receptionist', 'Receptionist')], validators=[DataRequired()])
    terms = BooleanField('I accept the terms and conditions', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_role(self, field):
        if field.data not in ['admin', 'doctor', 'nurse', 'receptionist']:
            raise ValidationError('Invalid role selected.')

class AppointmentForm(FlaskForm):
    patient_name = StringField('Patient Name', validators=[DataRequired(), Length(min=2, max=100)])
    patient_phone = StringField('Phone Number', validators=[Length(max=15)])
    patient_email = EmailField('Email', validators=[Email()])
    date = DateTimeField('Date', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    reason = StringField('Reason', validators=[Length(max=500)])
    submit = SubmitField('Book Appointment')

class SearchForm(FlaskForm):
    search_term = StringField('Search Term', validators=[DataRequired()])
    submit = SubmitField('Search')

class PatientForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    date_of_birth = DateField('Date of Birth', validators=[DataRequired()], format='%Y-%m-%d')
    gender = SelectField('Gender', choices=[('', 'Choose gender'), ('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    address = StringField('Address')
    phone = StringField('Phone')
    email = StringField('Email', validators=[Email()])
    emergency_contact_name = StringField('Emergency Contact Name')
    emergency_contact_phone = StringField('Emergency Contact Phone')
    medical_history = TextAreaField('Medical History')
    allergies = TextAreaField('Allergies')
    current_medications = TextAreaField('Current Medications')
    submit = SubmitField('Register Patient')
    
class PatientBookAppointmentForm(FlaskForm):
    patient_name = StringField('Full Name', validators=[DataRequired(), Length(min=3, max=100)])
    patient_phone = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=15)])
    patient_email = EmailField('Email', validators=[DataRequired(), Email()])
    date = DateTimeField('Date & Time', validators=[DataRequired()], format='%Y-%m-%dT%H:%M')
    reason = TextAreaField('Reason', validators=[Length(max=500)])
    submit = SubmitField('Book Appointment')
    
@app.template_filter('nl2br')
def nl2br_filter(value):
    if not value:
        return ''
    return Markup(value.replace('\n', '<br>\n'))

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('default_page'))
        
    form = LoginForm()
    if form.validate_on_submit():
        username_input = form.username.data.strip()
        password = form.password.data

        # Search by staff_number OR email
        user = Employee.query.filter(
            (Employee.staff_number == username_input) | 
            (Employee.email == username_input)
        ).first()

        if user and user.active and check_password_hash(user.password, password):
            login_user(user, remember=form.remember.data)
            
            flash('Login successful!', 'success')
            
            # Redirect based on role
            redirect_map = {
                'admin': 'admin_dashboard',
                'doctor': 'doctor_dashboard',
                'nurse': 'nurse_dashboard',
                'receptionist': 'reception_dashboard',
                'manager': 'manager_dashboard'
            }
            return redirect(url_for(redirect_map.get(user.role, 'default_page')))
        else:
            flash('Invalid credentials or account inactive.', 'error')
    
    return render_template('homepage/login_page.html', form=form)

# --------------------------------------------------------------
# POST: Create New User (Admin Only) – FIXED CSRF + Werkzeug
# --------------------------------------------------------------
@app.route('/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    """
    Admin creates a new staff member.
    Returns JSON with temporary password.
    """
    form_data = request.form
    first_name = form_data.get('first_name', '').strip()
    last_name = form_data.get('last_name', '').strip()
    email = form_data.get('email', '').strip().lower()
    role = form_data.get('role', '').strip()

    # Validation
    if not all([first_name, last_name, email, role]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if role not in ['doctor', 'nurse', 'receptionist', 'manager']:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    # Check if email exists
    if Employee.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already in use'}), 400

    # Generate staff number
    max_staff = db.session.query(Employee).order_by(Employee.id.desc()).first()
    if max_staff:
        last_num = int(max_staff.staff_number.replace('STAFF', '') or 0)
    else:
        last_num = 0
    staff_number = f"STAFF{str(last_num + 1).zfill(3)}"

    # Generate temporary password
    alphabet = string.ascii_letters + string.digits
    temp_password = ''.join(secrets.choice(alphabet) for _ in range(10))
    hashed_password = generate_password_hash(temp_password)

    # Create new user
    new_user = Employee(
        staff_number=staff_number,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        role=role,
        active=True
    )

    try:
        db.session.add(new_user)
        db.session.commit()

        # Optional: log creation
        logger.info(f"Admin {current_user.staff_number} created {role}: {staff_number}")

        return jsonify({
            'success': True,
            'staff_number': staff_number,
            'temp_password': temp_password,
            'message': f'{role.capitalize()} created successfully! Password: {temp_password}'
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create user: {e}")
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500

# --------------------------------------------------------------
# POST: Delete User – FIXED CSRF
# --------------------------------------------------------------
@app.route('/delete_user', methods=['POST'])
@login_required
@role_required('admin')
def delete_user():
    if not request.form.get('csrf_token'):
        logger.warning("CSRF token missing in delete_user")
        return jsonify({'success': False, 'message': 'CSRF token missing'}), 403

    user_id = request.form.get('user_id')
    reason = request.form.get('reason')

    if not user_id or not reason:
        return jsonify({'success': False, 'message': 'Missing ID or reason'}), 400

    try:
        user = Employee.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user.role == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin'}), 403

        staff_number = user.staff_number
        db.session.delete(user)
        db.session.commit()

        # Audit log
        audit = AuditLog(
            action='delete_user',
            performed_by=current_user.staff_number,
            target_user=staff_number,
            details=f"Reason: {reason}",
            timestamp=datetime.now()
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/search_patient', methods=['GET', 'POST'])
@login_required
@role_required('receptionist')
def search_patient():
    form = SearchForm()
    patients = []
    search_performed = False
    search_term = ''

    if form.validate_on_submit():
        search_term = form.search_term.data.strip()
        search_performed = True
        patients = Patient.query.filter(
            or_(
                Patient.id.like(f"%{search_term}%"),
                Patient.first_name.ilike(f"%{search_term}%"),
                Patient.last_name.ilike(f"%{search_term}%")
            )
        ).order_by(Patient.id.desc()).all()

    return render_template(
        'reception/search_patient.html',
        search_form=form,
        patients=patients,
        search_performed=search_performed,
        search_term=search_term
    )

@app.route('/cancel_appointment', methods=['POST'])
@login_required
@role_required('receptionist')
def cancel_appointment():
    appointment_id = request.form.get('appointment_id')
    if not appointment_id:
        flash('Invalid appointment ID.', 'error')
        return redirect(url_for('reception_dashboard'))

    appointment = Appointment.query.get(appointment_id)
    if appointment and appointment.status != 'cancelled':
        appointment.status = 'cancelled'
        db.session.commit()
        flash('Appointment cancelled successfully.', 'success')
    else:
        flash('Appointment not found or already cancelled.', 'error')

    return redirect(url_for('reception_dashboard'))

@app.route('/assign_staff', methods=['POST'])
@login_required
@role_required('receptionist')
def assign_staff():
    if not request.form.get('csrf_token') or request.form.get('csrf_token') != session.get('csrf_token'):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('reception_dashboard'))

    appointment_id = request.form.get('appointment_id')
    staff_id = request.form.get('staff_id')
    if not all([appointment_id, staff_id]):
        flash('Missing appointment or staff ID.', 'error')
        return redirect(url_for('reception_dashboard'))

    appointment = Appointment.query.get(appointment_id)
    if appointment:
        appointment.helper_id = staff_id
        appointment.status = 'assigned'
        db.session.commit()
        flash('Staff assigned successfully.', 'success')
    else:
        flash('Appointment not found.', 'error')

    return redirect(url_for('reception_dashboard'))

@app.route('/reschedule_appointment', methods=['POST'])
@login_required
@role_required('receptionist')
def reschedule_appointment():
    appointment_id = request.form.get('appointment_id')
    new_time = request.form.get('new_time')

    if not appointment_id or not new_time:
        flash('Appointment ID and new time are required.', 'error')
        return redirect(url_for('appointment_homepage'))

    try:
        appointment = Appointment.query.filter_by(id=appointment_id, status='scheduled').first()
        if appointment:
            appointment.appointment_date = datetime.strptime(new_time, '%Y-%m-%d %H:%M:%S')
            appointment.status = 'scheduled'
            db.session.commit()

            patient = Patient.query.get(appointment.patient_id)
            if patient:
                with queue_lock:
                    appointment_queue.put({
                        'id': appointment.id,
                        'patient_id': patient.id,
                        'first_name': patient.first_name,
                        'last_name': patient.last_name,
                        'appointment_date': new_time,
                        'reason': appointment.reason,
                        'status': 'scheduled'
                    })

            flash('Appointment rescheduled successfully!', 'success')
        else:
            flash('Appointment not found or not scheduled.', 'error')

    except Exception as e:
        logger.error(f"Error in reschedule_appointment: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')

    return redirect(url_for('appointment_homepage'))


@csrf.exempt
@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
@role_required('receptionist')
def add_patient():
    form = PatientForm()

    if form.validate_on_submit():
        try:
            patient = Patient(
                first_name=form.first_name.data.strip(),
                last_name=form.last_name.data.strip(),
                date_of_birth=form.date_of_birth.data,
                gender=form.gender.data,
                address=form.address.data,
                phone=form.phone.data,
                email=form.email.data,
                emergency_contact_name=form.emergency_contact_name.data,
                emergency_contact_phone=form.emergency_contact_phone.data,
                medical_history=form.medical_history.data,
                allergies=form.allergies.data,
                current_medications=form.current_medications.data
            )
            db.session.add(patient)
            db.session.commit()
            flash('Patient registered successfully!', 'success')
            return redirect(url_for('search_patient'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error in add_patient: {e}")
            flash(f'Failed to register patient: {str(e)}', 'error')

    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", 'error')

    return render_template('reception/patientRegistration.html', form=form)


# --------------------------------------------------------------
# RECEPTION: Walk-in patient check-in
# --------------------------------------------------------------
@csrf.exempt
@app.route('/add_walkin')
@login_required
@role_required('receptionist')
def add_walkin():
    patient_id = request.args.get('patient_id')
    if not patient_id:
        flash('No patient selected.', 'error')
        return redirect(url_for('search_patient'))

    patient = Patient.query.get(patient_id)
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('search_patient'))

    try:
        walkin = Appointment(
            patient_id=patient.id,
            appointment_date=datetime.now(),
            status='waiting',
            reason='Walk-in',
            created_by_role='receptionist'
        )
        db.session.add(walkin)
        db.session.commit()
        flash(f'Walk-in check-in successful for {patient.first_name} {patient.last_name}.', 'success')
        return redirect(url_for('check_in_desk'))

    except Exception as e:
        db.session.rollback()
        logger.error(f"Walk-in error: {e}")
        flash('Database error. Please try again.', 'error')
        return redirect(url_for('search_patient'))

            
# --------------------------------------------------------------
# PUBLIC: Patient Self-Booking
# --------------------------------------------------------------
@app.route('/patient_book_appointment', methods=['GET', 'POST'])
def patient_book_appointment():
    form = PatientBookAppointmentForm()
    doctors = Employee.query.filter_by(role='doctor', availability='available').all()
    success_data = None

    if form.validate_on_submit():
        try:
            appointment_dt = form.date.data
            doctor_staff = request.form.get('doctor')

            appointment = SelfBookedAppointment(
                patient_name=form.patient_name.data.strip(),
                patient_phone=form.patient_phone.data.strip(),
                patient_email=form.patient_email.data.strip(),
                appointment_date=appointment_dt,
                reason=form.reason.data.strip(),
                status='pending',
                doctor_staff_number=doctor_staff
            )
            db.session.add(appointment)
            db.session.commit()

            success_data = {
                'date': appointment_dt.strftime('%B %d, %Y at %I:%M %p'),
                'doctor': next((f"Dr. {d.first_name} {d.last_name}" for d in doctors if d.staff_number == doctor_staff), 'Selected Doctor')
            }
            flash('Appointment request sent! Awaiting confirmation.', 'success')

        except Exception as e:
            db.session.rollback()
            logger.error(f"Self-booking error: {e}")
            flash('Error saving appointment. Please try again.', 'error')

    return render_template(
        'homepage/patient_book_appointment.html',
        form=form,
        doctors=doctors,
        success_data=success_data
    )


# --------------------------------------------------------------
# RECEPTION: Manage Appointments (Walk-in + Self-Booked)
# --------------------------------------------------------------
@csrf.exempt
@app.route('/manage_appointments', methods=['GET', 'POST'])
@login_required
@role_required('receptionist')
def manage_appointments():
    selected_patient_id = request.args.get('patient_id')

    # -----------------------------------------------------------------
    # 1. Fetch Patients
    # -----------------------------------------------------------------
    patients = Patient.query.order_by(Patient.first_name, Patient.last_name).all()

    # -----------------------------------------------------------------
    # 2. Fetch Available Staff
    # -----------------------------------------------------------------
    available_staff = Employee.query.filter(
        Employee.availability == 'available',
        Employee.role.in_(['doctor', 'nurse'])
    ).order_by(Employee.role, Employee.first_name, Employee.last_name).all()

    # -----------------------------------------------------------------
    # 3. Fetch Pending Self-Booked
    # -----------------------------------------------------------------
    self_booked_appointments = SelfBookedAppointment.query.filter_by(status='pending').order_by(SelfBookedAppointment.id.desc()).all()

    # -----------------------------------------------------------------
    # 4. Fetch Active Appointments
    # -----------------------------------------------------------------
    appointments = db.session.query(
        Appointment,
        Patient.first_name.label('patient_first_name'),
        Patient.last_name.label('patient_last_name'),
        Employee.first_name.label('helper_first_name'),
        Employee.last_name.label('helper_last_name'),
        Employee.role.label('helper_role')
    ).join(Patient, Appointment.patient_id == Patient.id
    ).outerjoin(Employee, Appointment.helper_id == Employee.id
    ).filter(Appointment.status.notin_(['cancelled', 'helped'])
    ).order_by(Appointment.appointment_date).all()

    # -----------------------------------------------------------------
    # 5. Handle POST Actions
    # -----------------------------------------------------------------
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'book_appointment':
            patient_id = request.form.get('patient_id')
            appointment_time = request.form.get('appointment_time')
            reason = request.form.get('reason', '')
            helper_id = request.form.get('helper_id') or None

            if not patient_id or not appointment_time:
                return jsonify({'success': False, 'message': 'Missing data'})

            appointment = Appointment(
                patient_id=patient_id,
                appointment_date=datetime.strptime(appointment_time, '%Y-%m-%d %H:%M:%S'),
                status='scheduled',
                reason=reason,
                helper_id=helper_id,
                created_by_role='receptionist'
            )
            db.session.add(appointment)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Booked!'})

        elif action == 'convert_self_booked':
            self_id = request.form.get('self_booked_id')
            patient_id = request.form.get('patient_id')
            appointment_time = request.form.get('appointment_time')
            reason = request.form.get('reason', '')
            helper_id = request.form.get('helper_id') or None

            if not all([self_id, patient_id, appointment_time]):
                return jsonify({'success': False, 'message': 'Missing data'})

            self_appt = SelfBookedAppointment.query.get(self_id)
            if self_appt:
                self_appt.status = 'converted'
                db.session.commit()

            appointment = Appointment(
                patient_id=patient_id,
                appointment_date=datetime.strptime(appointment_time, '%Y-%m-%d %H:%M:%S'),
                status='scheduled',
                reason=reason,
                helper_id=helper_id,
                created_by_role='receptionist'
            )
            db.session.add(appointment)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Confirmed!'})

        elif action == 'cancel_appointment':
            appt_id = request.form.get('appointment_id')
            if not appt_id:
                return jsonify({'success': False, 'message': 'ID required'})
            appointment = Appointment.query.get(appt_id)
            if appointment:
                appointment.status = 'cancelled'
                db.session.commit()
            return jsonify({'success': True, 'message': 'Cancelled!'})

    return render_template(
        'reception/manage_appointments.html',
        patients=patients,
        available_staff=available_staff,
        self_booked_appointments=self_booked_appointments,
        appointments=appointments,
        selected_patient_id=selected_patient_id
    )

@app.route('/api/queue')
@login_required
@role_required('receptionist')
def api_get_queue():
    queue_rows = db.session.query(
        WalkinQueue,
        (Patient.first_name + ' ' + Patient.last_name).label('full_name')
    ).join(Patient, WalkinQueue.patient_id == Patient.id
    ).filter(WalkinQueue.status == 'waiting'
    ).order_by(
        db.case([
            (WalkinQueue.priority == 'emergency', 1),
            (WalkinQueue.priority == 'high', 2),
            (WalkinQueue.priority == 'medium', 3),
            (WalkinQueue.priority == 'low', 4),
        ]),
        WalkinQueue.arrived_at.asc()
    ).all()

    result = []
    for q, full_name in queue_rows:
        result.append({
            'id': q.id,
            'patient_id': q.patient_id,
            'patient_name': full_name,
            'priority': q.priority,
            'reason': q.reason,
            'arrived_at': q.arrived_at.isoformat(),
            'status': q.status
        })
    return jsonify(result)


@csrf.exempt
@app.route('/check_in_desk', methods=['POST'])
@login_required
@role_required('receptionist')
def check_in_desk():
    data = request.form
    action = data.get('action')

    try:
        # ────── ADD EXISTING PATIENT TO QUEUE ──────
        if action == 'add_to_queue':
            patient_id = data.get('patient_id')
            priority = data.get('priority')
            reason = data.get('reason', '')

            if not patient_id or not priority:
                return jsonify({'success': False, 'message': 'Patient and priority required'}), 400

            patient = Patient.query.get(patient_id)
            if not patient:
                return jsonify({'success': False, 'message': 'Patient not found'}), 404

            queue_entry = WalkinQueue(
                patient_id=patient.id,
                patient_name=f"{patient.first_name} {patient.last_name}",
                priority=priority,
                reason=reason,
                arrived_at=datetime.now()
            )
            db.session.add(queue_entry)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Added to queue',
                'patient': {
                    'id': queue_entry.id,
                    'name': queue_entry.patient_name,
                    'priority': priority,
                    'reason': reason,
                    'arrivedAt': queue_entry.arrived_at.isoformat()
                }
            })

        # ────── REGISTER NEW PATIENT + ADD TO QUEUE ──────
        elif action == 'register_patient':
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            phone = data.get('phone')
            email = data.get('email', '')

            if not all([first_name, last_name, phone]):
                return jsonify({'success': False, 'message': 'Name and phone required'}), 400

            patient = Patient(
                first_name=first_name,
                last_name=last_name,
                phone=phone,
                email=email
            )
            db.session.add(patient)
            db.session.commit()

            priority = data.get('priority', 'low')
            reason = data.get('reason', '')

            queue_entry = WalkinQueue(
                patient_id=patient.id,
                patient_name=f"{first_name} {last_name}",
                priority=priority,
                reason=reason,
                arrived_at=datetime.now()
            )
            db.session.add(queue_entry)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Registered & added to queue',
                'patient': {
                    'id': queue_entry.id,
                    'name': queue_entry.patient_name,
                    'priority': priority,
                    'reason': reason,
                    'arrivedAt': queue_entry.arrived_at.isoformat()
                }
            })

        return jsonify({'success': False, 'message': 'Invalid action'}), 400

    except Exception as e:
        logger.error(f"Error in check_in_desk: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Server error'}), 500



# --------------------------------------------------------------
# POST: Call Next Patient
# --------------------------------------------------------------
@app.route('/call_next', methods=['POST'])
@login_required
@role_required('receptionist')
def call_next():
    data = request.get_json()
    queue_id = data.get('queue_id')
    if not queue_id:
        return jsonify({'success': False, 'message': 'ID required'}), 400

    queue_entry = WalkinQueue.query.filter_by(id=queue_id, status='waiting').first()
    if not queue_entry:
        return jsonify({'success': False, 'message': 'Not found or already called'})

    queue_entry.status = 'called'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/remove_queue', methods=['POST'])
@login_required
@role_required('receptionist')
def remove_from_queue():
    data = request.get_json()
    queue_id = data.get('queue_id')
    if not queue_id:
        return jsonify({'success': False, 'message': 'ID required'}), 400

    queue_entry = WalkinQueue.query.get(queue_id)
    if queue_entry:
        db.session.delete(queue_entry)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/stream_queue')
@login_required
@role_required('receptionist')
def stream_queue():
    def event_stream():
        last_id = 0
        while True:
            rows = WalkinQueue.query.filter(
                WalkinQueue.id > last_id,
                WalkinQueue.status == 'waiting'
            ).all()
            for row in rows:
                last_id = row.id
                yield f"data: {json.dumps({'action': 'added', 'patient': {
                    'id': row.id,
                    'patient_id': row.patient_id,
                    'patient_name': row.patient_name,
                    'priority': row.priority,
                    'reason': row.reason,
                    'arrived_at': row.arrived_at.isoformat(),
                    'status': row.status
                }})}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/api/search_patient')
@login_required
def api_search_patient():
    phone = request.args.get('phone')
    if not phone:
        return jsonify({'patients': []})

    patients = Patient.query.filter(Patient.phone.like(f'%{phone}%')).all()
    result = [{
        'id': p.id,
        'name': f"{p.first_name} {p.last_name}",
        'phone': p.phone
    } for p in patients]
    return jsonify({'patients': result})

@app.route('/stream_appointments')
@login_required
@role_required('receptionist')
def stream_appointments():
    def event_stream():
        last_id = 0
        while True:
            updates = Appointment.query.filter(
                Appointment.id > last_id,
                Appointment.status.in_(['waiting', 'helped'])
            ).all()
            for u in updates:
                last_id = u.id
                yield f"data: {json.dumps({
                    'id': u.id,
                    'patient_id': u.patient_id,
                    'appointment_date': u.appointment_date.isoformat(),
                    'status': u.status,
                    'reason': u.reason,
                    'helper_id': u.helper_id
                })}\n\n"
            time.sleep(2)
    return Response(event_stream(), mimetype="text/event-stream")

@csrf.exempt
@app.route('/helped_patients_report')
@login_required
@role_required('receptionist')
def helped_patients_report():
    helped_patients = HelpedPatient.query.all()
    return render_template('reception/helped_patients_report.html', helped_patients=helped_patients)

@app.route('/prescription_page/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor', 'nurse')
def prescription_page(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    user_details = get_user_details(current_user.staff_number)

    if request.method == 'POST':
        medication_name = request.form.get('medication_name', '').strip()
        dosage = request.form.get('dosage', '').strip()
        instructions = request.form.get('instructions', '').strip()

        if not medication_name or not dosage:
            flash('Medication name and dosage are required.', 'error')
            return render_template('prescription_page.html', patient=patient, user_details=user_details)

        prescription = Prescription(
            patient_id=patient.id,
            nurse_id=current_user.id,
            medication_name=medication_name,
            dosage=dosage,
            instructions=instructions,
            prescribed_date=datetime.now()
        )

        # Update patient's current medications
        if patient.current_medications:
            patient.current_medications += f", {medication_name} ({dosage})"
        else:
            patient.current_medications = f"{medication_name} ({dosage})"

        db.session.add(prescription)
        db.session.commit()
        flash('Medication prescribed successfully!', 'success')
        return redirect(url_for('patient_profile', patient_id=patient.id))

    return render_template('prescription_page.html', patient=patient, user_details=user_details)

# ==================
# 1.ADMIN DASHBOARD
# ==================
@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    try:
        total_users = Employee.query.count()
        active_staff = Employee.query.filter(Employee.role.in_(['doctor', 'nurse', 'receptionist'])).count()
        system_alerts = Appointment.query.filter_by(status='pending').count()
        
        recent_users = Employee.query.order_by(Employee.id.desc()).limit(5).all()
        recent_users_list = [{
            'staff_number': u.staff_number,
            'email': u.email,
            'role': u.role.capitalize()
        } for u in recent_users]

        return render_template('admin/adminDashboard.html',
                               total_users=total_users,
                               active_staff=active_staff,
                               system_alerts=system_alerts,
                               recent_users=recent_users_list,
                               user_details=current_user)
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('login_page'))

@app.route('/doctor_dashboard')
@app.route('/doctorDashboard.html')
@role_required('doctor', 'nurse')
def doctor_dashboard():
    try:
        today_str = date.today().strftime('%Y-%m-%d')
        
        # Get doctor's patients
        patients = Patient.query.filter_by(doctor_id=current_user.id).all()
        patients_list = [{
            'id': p.id,
            'first_name': p.first_name,
            'last_name': p.last_name,
            'date_of_birth': p.date_of_birth,
            'gender': p.gender,
            'last_visit_date': 'N/A'
        } for p in patients]

        # Today's appointments
        appointments_today = db.session.query(Patient, Appointment)\
            .join(Appointment, Patient.id == Appointment.patient_id)\
            .filter(Appointment.doctor_id == current_user.id,
                    db.func.date(Appointment.date) == today_str).all()

        patients_today = [{
            'id': p.id,
            'first_name': p.first_name,
            'last_name': p.last_name,
            'appointment_time': a.time.strftime('%H:%M') if a.time else 'N/A'
        } for p, a in appointments_today]

        total_patients = len(patients)
        chronic_patients = Patient.query.filter(
            Patient.doctor_id == current_user.id,
            Patient.medical_history.ilike('%chronic%')
        ).count()

        # Average medications (approximate)
        avg_medications = db.session.query(db.func.avg(
            db.func.length(Patient.current_medications) - db.func.length(db.func.replace(Patient.current_medications, ',', '')) + 1
        )).filter(Patient.doctor_id == current_user.id, Patient.current_medications.isnot(None)).scalar() or 0

        unread_messages = Message.query.filter(Message.title.ilike('%Doctor%')).count()
        pending_lab_results = 0  # Add LabResult model later if needed

        reminders = [
            {'title': 'Staff Meeting', 'date': today_str, 'description': 'Team meeting at 2 PM'},
            {'title': 'Review Lab Results', 'date': today_str, 'description': 'Check pending lab results'}
        ]
        health_trends = "Stable, with a slight increase in chronic condition cases this month."

        return render_template('doctor/doctorDashboard.html',
                               now=datetime.now(),
                               patients=patients_list,
                               patients_today=patients_today,
                               total_patients=total_patients,
                               chronic_patients=chronic_patients,
                               avg_medications=round(avg_medications, 1),
                               health_trends=health_trends,
                               pending_lab_results=pending_lab_results,
                               unread_messages=unread_messages,
                               reminders=reminders,
                               user_details=current_user)
    except Exception as e:
        logger.error(f"Doctor dashboard error: {e}")
        flash('An error occurred.', 'error')
        return redirect(url_for('login_page'))

@app.route('/nurse_dashboard')
@role_required('nurse')
def nurse_dashboard():
    try:
        today_str = date.today().strftime('%Y-%m-%d')

        appointments = db.session.query(Appointment, Patient)\
            .join(Patient).filter(
                db.func.date(Appointment.date) == today_str,
                Appointment.status == 'scheduled'
            ).all()

        appointments_list = [{
            'id': a.id,
            'patient_id': p.id,
            'patient_name': f"{p.first_name} {p.last_name}",
            'appointment_date': a.date,
            'reason': a.reason or 'Checkup'
        } for a, p in appointments]

        pending_vitals = 5
        todays_patients = len(appointments_list)
        emergency_requests = 2
        new_messages = 3
        shift_start = "08:00 AM"
        shift_end = "04:00 PM"
        shift_hours_left = "5 hours"

        return render_template('nurse/nurseDashboard.html',
                               appointments=appointments_list,
                               pending_vitals=pending_vitals,
                               todays_patients=todays_patients,
                               patients=appointments_list,
                               emergency_requests=emergency_requests,
                               new_messages=new_messages,
                               shift_start=shift_start,
                               shift_end=shift_end,
                               shift_hours_left=shift_hours_left,
                               user_details=current_user)
    except Exception as e:
        logger.error(f"Nurse dashboard error: {e}")
        flash('An error occurred.', 'error')
        return render_template('nurse/nurseDashboard.html',
                               appointments=[], pending_vitals=0, todays_patients=0,
                               patients=[], emergency_requests=0, new_messages=0,
                               shift_start="N/A", shift_end="N/A", shift_hours_left="N/A",
                               user_details=current_user)


# ==========================
# 4. RECEPTIONIST DASHBOARD 
# ==========================
@app.route('/reception_dashboard')
@role_required('receptionist')
def reception_dashboard():
    try:
        today_str = date.today().strftime('%Y-%m-%d')

        # Today's appointments
        patients_today = db.session.query(Patient, Appointment)\
            .join(Appointment).filter(db.func.date(Appointment.date) == today_str)\
            .order_by(Appointment.time).all()

        patients_today_list = [{
            'patient_id': p.id,
            'first_name': p.first_name,
            'last_name': p.last_name,
            'appointment_date': a.date,
            'appointment_time': a.time.strftime('%H:%M') if a.time else 'N/A',
            'reason': a.reason or 'General',
            'status': a.status,
            'urgent': 1 if 'urgent' in (a.reason or '').lower() else 0
        } for p, a in patients_today]

        # Waiting patients
        waiting = Appointment.query.join(Patient).filter(
            Appointment.status.in_(['scheduled', 'waiting', 'helped']),
            db.func.date(Appointment.date) == today_str
        ).all()

        waiting_patients = []
        for a in waiting:
            helper = Employee.query.get(a.helper_id)
            helper_name = f"{helper.first_name} {helper.last_name}" if helper else "None"
            waiting_patients.append({
                'patient_id': a.patient.id,
                'first_name': a.patient.first_name,
                'last_name': a.patient.last_name,
                'appointment_time': a.time.strftime('%H:%M') if a.time else 'N/A',
                'reason': a.reason,
                'status': a.status,
                'helper_name': helper_name,
                'helper_role': helper.role.capitalize() if helper else ''
            })

        available_staff = Employee.query.filter(
            Employee.role != 'receptionist',
            Employee.availability == 'available'
        ).all()

        missed_appointments = Appointment.query.join(Patient)\
            .filter(Appointment.status == 'missed', db.func.date(Appointment.date) == today_str).all()

        notifications = Message.query.order_by(Message.timestamp.desc()).limit(5).all()

        walkins_waiting = [p for p in waiting_patients if p['status'] == 'waiting']
        pending_registrations = []  # Add self-booked model later if exists
        checked_in_patients = len([p for p in waiting_patients if p['status'] == 'helped'])
        appointments_rescheduled = len([a for a in waiting if a.status == 'rescheduled'])
        all_visits = Appointment.query.filter(db.func.date(Appointment.date) == today_str).count()

        current_time = datetime.now().strftime('%I:%M %p, %B %d, %Y')

        return render_template('reception/reception.html',
                               user_details=current_user,
                               patients_today=patients_today_list,
                               waiting_patients=waiting_patients,
                               available_staff=available_staff,
                               missed_appointments=missed_appointments,
                               notifications=notifications,
                               checked_in_patients=checked_in_patients,
                               walkins_processed=0,
                               appointments_rescheduled=appointments_rescheduled,
                               payments_processed=0,
                               pending_registrations=pending_registrations,
                               all_visits=all_visits,
                               walkins_waiting=walkins_waiting,
                               current_time=current_time)
    except Exception as e:
        logger.error(f"Reception dashboard error: {e}")
        flash('An error occurred.', 'error')
        return redirect(url_for('login_page'))

# --------------------------------------------------------------
# API: Get announcements for current user (role-based)
# --------------------------------------------------------------
@csrf.exempt
@app.route('/api/<role>/announcements')
def api_announcements(role):
    valid_roles = ['doctor', 'nurse', 'receptionist', 'admin']
    if role not in valid_roles or session.get('role') != role:
        return jsonify([])

    announcements = Announcement.query.filter(
        or_(Announcement.target_role == 'all', Announcement.target_role == role)
    ).order_by(Announcement.pinned.desc(), Announcement.timestamp.desc()).all()

    result = [{
        'id': a.id,
        'title': a.title,
        'message': a.message,
        'category': a.category,
        'pinned': a.pinned,
        'author': a.author,
        'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M')
    } for a in announcements]

    return jsonify(result)


# --------------------------------------------------------------
# API: SSE Stream for real-time announcements
# --------------------------------------------------------------
from flask import stream_with_context, Response

@app.route('/api/announcements/stream')
def announcement_stream():
    def event_stream():
        last_id = 0
        while True:
            announcements = Announcement.query.filter(
                Announcement.id > last_id,
                or_(Announcement.target_role == 'all', Announcement.target_role == session.get('role'))
            ).order_by(Announcement.timestamp.desc()).all()
            for a in announcements:
                last_id = a.id
                yield f"data: {json.dumps({'id': a.id, 'title': a.title, 'message': a.message})}\n\n"
            time.sleep(2)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

# ---- ADMIN: create / list / delete ---------------------------------
@csrf.exempt
@app.route('/admin/announcements', methods=['GET', 'POST'])
def admin_announcements():
    if session.get('role') != 'admin':
        flash('Admin access only.', 'error')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        ann = Announcement(
            title=request.form['title'],
            message=request.form['message'],
            category=request.form['category'],
            target_role=request.form['target_role'],
            pinned='pinned' in request.form,
            author=session.get('username', 'Admin')
        )
        db.session.add(ann)
        db.session.commit()
        flash('Announcement created.', 'success')
        return redirect(url_for('admin_announcements'))

    announcements = Announcement.query.order_by(
        Announcement.pinned.desc(),
        Announcement.timestamp.desc()
    ).all()
    return render_template('admin/announcement.html',
                           announcements=announcements,
                           request=request)

@csrf.exempt
@app.route('/admin/announcements/<int:aid>/delete', methods=['POST'])
def delete_announcement(aid):
    if session.get('role') != 'admin':
        abort(403)
    ann = Announcement.query.get_or_404(aid)
    db.session.delete(ann)
    db.session.commit()
    flash('Announcement deleted.', 'info')
    return redirect(url_for('admin_announcements'))


# ---- ROLE-BASED VIEW (shared helper) -------------------------------
def _view_announcements(role, template):
    announcements = Announcement.query.filter(
        or_(Announcement.target_role == 'all',
            Announcement.target_role == role)
    ).order_by(
        Announcement.pinned.desc(),
        Announcement.timestamp.desc()
    ).all()
    return render_template(template, announcements=announcements)


@app.route('/doctor/announcements')
def doctor_view_announcements():
    if session.get('role') != 'doctor':
        flash('Access denied.', 'error')
        return redirect(url_for('login_page'))
    return _view_announcements('doctor', 'doctor/view_announcements.html')


@app.route('/nurse/announcements')
def nurse_view_announcements():
    if session.get('role') != 'nurse':
        flash('Access denied.', 'error')
        return redirect(url_for('login_page'))
    return _view_announcements('nurse', 'nurse/view_announcements.html')


@app.route('/reception/announcements')
def reception_view_announcements():
    if session.get('role') != 'receptionist':
        flash('Access denied.', 'error')
        return redirect(url_for('login_page'))
    return _view_announcements('receptionist', 'reception/view_announcements.html')

@app.route('/mark_helped', methods=['POST'])
def mark_helped():
    if 'username' not in session or session.get('role') != 'nurse':
        return jsonify({'success': False, 'category': 'error', 'message': 'Unauthorized access.'}), 403

    appointment_id = request.form.get('appointment_id')
    if not appointment_id:
        return jsonify({'success': False, 'category': 'error', 'message': 'Appointment ID missing.'}), 400

    try:
        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({'success': False, 'category': 'error', 'message': 'Appointment not found.'}), 404

        nurse = Employee.query.filter_by(staff_number=session['username']).first()
        if not nurse:
            return jsonify({'success': False, 'category': 'error', 'message': 'Nurse not found.'}), 404

        helped_entry = HelpedPatient(
            patient_id=appointment.patient_id,
            appointment_id=appointment.id,
            nurse_id=nurse.id,
            helped_timestamp=datetime.now(),
            notes=request.form.get('notes', 'Patient helped by nurse').strip()
        )
        db.session.add(helped_entry)

        appointment.status = "helped"
        db.session.commit()

        patient = Patient.query.get(appointment.patient_id)

        with queue_lock:
            waiting_patients_queue.put({
                'id': appointment.id,
                'patient_id': patient.id,
                'first_name': patient.first_name,
                'last_name': patient.last_name,
                'status': 'helped',
                'helper_name': f"{nurse.first_name} {nurse.last_name}",
                'helper_role': nurse.role,
                'timestamp': datetime.now().isoformat()
            })

        return jsonify({'success': True, 'category': 'success', 'message': 'Patient marked as helped.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'category': 'error', 'message': 'Database error occurred.'}), 500

@app.route('/stream_waiting_patients')
def stream_waiting_patients():
    if 'username' not in session or session.get('role') not in ['nurse', 'receptionist']:
        return Response(status=403)

    def generate_stream():
        try:
            while True:
                with queue_lock:
                    if not waiting_patients_queue.empty():
                        yield f"data: {json.dumps(waiting_patients_queue.get())}\n\n"
                time.sleep(1)
        except GeneratorExit:
            return

    return Response(generate_stream(), mimetype='text/event-stream')

@csrf.exempt
@app.route('/nurse_assess_patient/<int:patient_id>', methods=['GET', 'POST'])
def nurse_assess_patient(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to assess patients.', 'error')
        return redirect(url_for('login_page'))

    nurse = Employee.query.filter_by(staff_number=session['username']).first()
    if not nurse:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))

    patient = Patient.query.get(patient_id)
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('nurse_dashboard'))

    if request.method == 'POST':
        vitals = request.form.get('vitals', '').strip()
        notes = request.form.get('notes', '').strip()

        if not vitals:
            flash('Vitals are required.', 'error')
            return render_template('nurse/nurseAssessPatient.html', patient=patient, user_details=nurse)

        try:
            visit = Visit(
                patient_id=patient.id,
                visit_time=datetime.now(),
                notes=f"Vitals: {vitals}\nNotes: {notes}" if notes else f"Vitals: {vitals}"
            )
            db.session.add(visit)
            db.session.commit()

            flash('Patient assessment recorded successfully!', 'success')
            return redirect(url_for('nurse_dashboard'))

        except Exception:
            db.session.rollback()
            flash('Database error occurred while saving assessment.', 'error')
            return render_template('nurse/nurseAssessPatient.html', patient=patient, user_details=nurse)

    return render_template('nurse/nurseAssessPatient.html', patient=patient, user_details=nurse)

@csrf.exempt
@app.route('/nurse_view_medical_history/<int:patient_id>')
def nurse_view_medical_history(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to view medical history.', 'error')
        return redirect(url_for('login_page'))

    nurse = Employee.query.filter_by(staff_number=session['username']).first()
    if not nurse:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))

    patient = Patient.query.get(patient_id)
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('nurse_dashboard'))

    prescriptions = Prescription.query.filter_by(patient_id=patient_id)\
        .order_by(Prescription.prescribed_date.desc()).all()

    return render_template(
        'nurse/nurseViewMedicalHistory.html',
        patient=patient,
        prescriptions=prescriptions,
        user_details=nurse
    )

@csrf.exempt
@app.route('/nurse_prescribe_medication/<int:patient_id>', methods=['GET', 'POST'])
def nurse_prescribe_medication(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to prescribe medications.', 'error')
        return redirect(url_for('login_page'))

    nurse = Employee.query.filter_by(staff_number=session['username']).first()
    if not nurse:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))

    patient = Patient.query.get(patient_id)
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('nurse_dashboard'))

    if request.method == 'POST':
        medication_name = request.form.get('medication_name', '').strip()
        dosage = request.form.get('dosage', '').strip()
        instructions = request.form.get('instructions', '').strip()

        if not medication_name or not dosage:
            flash('Medication name and dosage are required.', 'error')
            return render_template('nurse/nursePrescribeMedication.html', patient=patient, user_details=nurse)

        try:
            prescription = Prescription(
                patient_id=patient.id,
                nurse_id=nurse.id,
                medication_name=medication_name,
                dosage=dosage,
                instructions=instructions
            )
            db.session.add(prescription)

            # Append medication to patient's active medications
            current_meds = patient.current_medications or ''
            updated_meds = f"{current_meds}, {medication_name} ({dosage})" if current_meds else f"{medication_name} ({dosage})"
            patient.current_medications = updated_meds

            db.session.commit()

            flash('Medication prescribed successfully!', 'success')
            return redirect(url_for('nurse_view_medical_history', patient_id=patient_id))

        except Exception:
            db.session.rollback()
            flash('Database error occurred while prescribing medication.', 'error')
            return render_template('nurse/nursePrescribeMedication.html', patient=patient, user_details=nurse)

    return render_template('nurse/nursePrescribeMedication.html', patient=patient, user_details=nurse)

@csrf.exempt
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Please log in as an admin to manage users.', 'error')
        return redirect(url_for('login_page'))

    admin = Employee.query.filter_by(id=session.get('user_id')).first()
    if not admin:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        action = request.form.get('action')
        staff_number = request.form.get('staff_number')

        if not staff_number:
            return jsonify({'success': False, 'message': 'Staff number required'}), 400

        user = Employee.query.filter_by(staff_number=staff_number).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Prevent deletion of admins
        if action == 'delete':
            if user.role == 'admin':
                return jsonify({'success': False, 'message': 'Cannot delete an admin'}), 400

            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'User deleted'})

        elif action == 'update':
            role = request.form.get('role')
            allowed_roles = ['doctor', 'nurse', 'receptionist', 'manager', 'admin']

            if role not in allowed_roles:
                return jsonify({'success': False, 'message': 'Invalid role'}), 400

            user.role = role
            db.session.commit()
            return jsonify({'success': True, 'message': 'Role updated'})

    # GET request — Load users list
    employees = Employee.query.order_by(Employee.role, Employee.id).all()

    return render_template(
        'admin/manageUsers.html',
        employees=employees,
        user_details=admin,
        username=session.get('username', 'Admin')
    )

# === MANAGER ROUTES ===
@app.route('/manager_dashboard')
@login_required
def manager_dashboard():
    if session.get('role') != 'manager':
        flash("Access denied.", "error")
        return redirect(url_for('login_page'))

    try:
        # --- HIGH-LEVEL BUSINESS METRICS ---
        total_staff = Employee.query.filter_by(active=True).count()
        patients_today = Appointment.query.filter(
            db.func.date(Appointment.appointment_date) == db.func.current_date()
        ).count()

        low_stock = Inventory.query.filter(Inventory.quantity <= Inventory.min_stock).count()

        revenue_mtd = (
            db.session.query(db.func.coalesce(db.func.sum(Billing.cost), 0))
            .filter(db.func.to_char(Billing.billing_date, "YYYY-MM") ==
                    db.func.to_char(db.func.current_date(), "YYYY-MM"))
            .scalar()
        )

        # Top pending tasks
        tasks = (
            db.session.query(Task, Employee.first_name, Employee.last_name)
            .outerjoin(Employee, Task.assigned_to == Employee.id)
            .filter(Task.status == "pending")
            .order_by(Task.priority.desc())
            .limit(5)
            .all()
        )
        task_list = [
            {
                **t[0].to_dict(),
                "assigned_name": f"{t[1]} {t[2]}" if t[1] else "Unassigned"
            }
            for t in tasks
        ]

        # --- Daily HR & Operations ---
        today = date.today()

        on_duty_today = Attendance.query.filter_by(date=today).count()
        pending_leave = LeaveRequest.query.filter_by(status="pending").count()
        training_due = Certification.query.filter(Certification.expiry < today + timedelta(days=30)).count()

        # Roster by role
        roster = []
        for role, required in {"doctor": 3, "nurse": 5, "receptionist": 2, "manager": 1}.items():
            on_duty = (
                db.session.query(Attendance)
                .join(Employee, Attendance.staff_id == Employee.id)
                .filter(Employee.role == role, Attendance.date == today)
                .count()
            )
            roster.append({
                "role": role,
                "on_duty": on_duty,
                "required": required
            })

        # Pending leave requests list
        leave_requests = db.session.query(
            LeaveRequest,
            Employee.first_name,
            Employee.last_name,
            Employee.role
        ).join(Employee, LeaveRequest.staff_id == Employee.id).filter(
            LeaveRequest.status == "pending"
        ).all()
        leave_list = [
            {
                **lr[0].to_dict(),
                "name": f"{lr[1]} {lr[2]}",
                "role": lr[3],
            } for lr in leave_requests
        ]

        # Performance reviews
        performance = db.session.query(
            PerformanceReview,
            Employee.first_name,
            Employee.last_name,
            Employee.role,
        ).join(Employee, PerformanceReview.staff_id == Employee.id).order_by(
            PerformanceReview.last_review.desc()
        ).all()
        performance_list = [
            {
                **pr[0].to_dict(),
                "name": f"{pr[1]} {pr[2]}",
                "role": pr[3],
                "score": int(pr[0].score or 0),
            } for pr in performance
        ]

        # Training sessions
        training = TrainingSession.query.filter(
            TrainingSession.date >= today
        ).order_by(TrainingSession.date).all()

        # Certifications due
        certifications = db.session.query(
            Certification,
            Employee.first_name,
            Employee.last_name,
            db.func.cast(db.func.julianday(Certification.expiry) - db.func.julianday(db.func.current_date()), db.Integer).label("days_left")
        ).join(Employee, Certification.staff_id == Employee.id).filter(
            Certification.expiry < today + timedelta(days=90)
        ).order_by("days_left").all()
        certification_list = [
            {
                **c[0].to_dict(),
                "staff": f"{c[1]} {c[2]}",
                "days_left": c[3]
            } for c in certifications
        ]

        # Compliance (placeholder)
        compliance = {'popia': 98, 'infection': 100, 'ppe': 92}

    except Exception as e:
        logger.error(f"Manager dashboard error: {e}")
        flash("Error loading dashboard information.", "error")

        return render_template(
            "manager/dashboard.html",
            stats=dict.fromkeys([
                'total_staff', 'patients_today', 'low_stock',
                'revenue_mtd', 'on_duty_today', 'pending_leave', 'training_due'
            ], 0),
            tasks=[],
            roster=[],
            leave_requests=[],
            performance=[],
            training=[],
            certifications=[],
            compliance={'popia': 0, 'infection': 0, 'ppe': 0}
        )

    return render_template(
        "manager/dashboard.html",
        stats={
            'total_staff': total_staff,
            'patients_today': patients_today,
            'low_stock': low_stock,
            'revenue_mtd': revenue_mtd,
            'on_duty_today': on_duty_today,
            'pending_leave': pending_leave,
            'training_due': training_due
        },
        tasks=task_list,
        roster=roster,
        leave_requests=leave_list,
        performance=performance_list,
        training=training,
        certifications=certification_list,
        compliance=compliance
    )

@app.route('/manager/leave_action', methods=['POST'])
@login_required
@role_required('manager')
def manager_leave_action():
    req_id = request.form.get('id')
    action = request.form.get('action')  # approve / reject

    if not req_id or action not in ['approve', 'reject']:
        return jsonify({'success': False, 'message': 'Invalid request'}), 400

    leave = LeaveRequest.query.get(req_id)
    if not leave:
        return jsonify({'success': False, 'message': 'Leave request not found'}), 404

    leave.status = action
    db.session.commit()

    return jsonify({'success': True, 'message': f'Leave request {action}d'})


@app.route('/inventory')
@login_required
def inventory():
    if session.get('role') != 'manager':
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT *,
                CASE 
                    WHEN avg_daily_use > 0 THEN ROUND(quantity * 1.0 / avg_daily_use, 1)
                    ELSE NULL
                END AS days_left
            FROM inventory
            ORDER BY COALESCE(days_left, 999)
        """)
        inventory = [dict(row) for row in c.fetchall()]
        low_stock_alerts = [i for i in inventory if i['quantity'] <= i['min_stock']]
    finally:
        conn.close()

    return render_template(
        'manager/inventory.html',
        inventory=inventory,
        low_stock_alerts=low_stock_alerts
    )

@app.route('/reorder_item', methods=['POST'])
@login_required
def reorder_item():
    if session.get('role') != 'manager':
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json() or {}
    item_id = data.get("id")
    qty = data.get("quantity")

    if not item_id or not isinstance(qty, int) or qty <= 0:
        return jsonify({"success": False, "message": "Invalid quantity"}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute(
            "UPDATE inventory SET quantity = quantity + ?, last_restocked = DATE('now') WHERE id = ?",
            (qty, item_id)
        )
        if c.rowcount == 0:
            return jsonify({"success": False, "message": "Item not found"}), 404

        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Stock updated"}), 200

@app.route('/executive_report')
@login_required
def executive_report():
    if session.get('role') != 'manager':
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()

    months = []
    revenue = []
    expenses = []
    patients = []

    try:
        for i in range(5, -1, -1):  # Last 6 months
            target_date = datetime.now().replace(day=1) - relativedelta(months=i)
            month_label = target_date.strftime('%b %Y')
            month_key = target_date.strftime('%Y-%m')

            months.append(month_label)

            # Revenue
            c.execute(
                "SELECT COALESCE(SUM(cost),0) FROM billing WHERE strftime('%Y-%m', billing_date) = ?",
                (month_key,)
            )
            revenue.append(float(c.fetchone()[0]))

            # Placeholder until full accounting module is ready
            expenses.append(50000)

            # Patient load
            c.execute(
                "SELECT COUNT(*) FROM appointments WHERE strftime('%Y-%m', appointment_date) = ?",
                (month_key,)
            )
            patients.append(int(c.fetchone()[0]))

        total_rev = sum(revenue)
        total_pat = sum(patients)

        kpi = {
            "revenue": total_rev,
            "expenses": sum(expenses),
            "patients": total_pat,
            "avg_per_patient": round(total_rev / total_pat, 2) if total_pat else 0
        }

        report_data = {
            "months": months,
            "revenue": revenue,
            "expenses": expenses,
            "patients": patients
        }

    except Exception as e:
        conn.close()
        flash("Error generating executive report.", "error")
        logger.error(f"Executive report error: {e}")
        return redirect(url_for('manager_dashboard'))

    conn.close()
    return render_template("manager/executive_report.html", report_data=report_data, kpi=kpi)

@app.route('/manage_staff')
@login_required
def manage_staff():
    if session.get('role') != 'manager':
        flash("Access denied.", "error")
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT id, first_name, last_name, role, email, phone
            FROM employees
            WHERE role NOT IN ('admin', 'manager') AND active = 1
            ORDER BY first_name
        """)
        staff = [dict(row) for row in c.fetchall()]
    except Exception as e:
        conn.close()
        flash("Error loading staff list.", "error")
        logger.error(f"Manage staff error: {e}")
        return redirect(url_for('manager_dashboard'))

    conn.close()
    return render_template("manager/manage_staff.html", staff=staff)

@app.route('/manager_announcements')
@login_required
def manager_announcements():
    if session.get('role') != 'manager': return redirect(url_for('login_page'))
    return render_template('manager/view_announcements.html')

@app.route('/staff_schedule')
@login_required
def staff_schedule():
    if session.get('role') != 'manager':
        flash("Access denied.", "error")
        return redirect(url_for('login_page'))

    staff = Employee.query.filter(
        Employee.active == True,
        Employee.role.notin_(["admin", "manager"])
    ).order_by(Employee.first_name).all()

    return render_template("manager/staff_schedule.html", staff=staff)

@app.route('/get_schedule')
@login_required
def get_schedule():
    if session.get('role') != 'manager':
        return jsonify([])

    schedules = (
        db.session.query(StaffSchedule, Employee)
        .join(Employee, StaffSchedule.employee_id == Employee.id)
        .all()
    )

    color_map = {
        "morning": "#28a745",
        "afternoon": "#ffc107",
        "night": "#007bff",
    }

    events = []
    for schedule, emp in schedules:
        staff_name = f"{emp.first_name} {emp.last_name}"
        color = color_map.get(schedule.shift_type, "#6c757d")

        events.append({
            "id": schedule.id,
            "title": f"{staff_name} ({schedule.shift_type.capitalize()})",
            "start": schedule.shift_date.isoformat(),
            "backgroundColor": color,
            "borderColor": color,
            "extendedProps": {
                "employee_id": schedule.employee_id,
                "shift_type": schedule.shift_type,
                "notes": schedule.notes or ""
            }
        })

    return jsonify(events)

@app.route('/save_shift', methods=['POST'])
@login_required
def save_shift():
    if session.get('role') != 'manager':
        return '', 403

    data = request.get_json()
    emp_id = data["employee_id"]
    shift_date = date.fromisoformat(data["shift_date"])
    shift_type = data["shift_type"]
    shift_id = data.get("id")

    # Shift time ranges
    shift_times = {
        "morning": ("08:00", "16:00"),
        "afternoon": ("13:00", "21:00"),
        "night": ("20:00", "08:00"),
    }

    new_start, new_end = shift_times[shift_type]

    # Conflicts (excluding the current shift in edit mode)
    existing = StaffSchedule.query.filter(
        StaffSchedule.employee_id == emp_id,
        StaffSchedule.shift_date == shift_date,
        StaffSchedule.id != (shift_id or 0)
    ).all()

    # Time overlap logic
    def to_minutes(t):
        hr, mn = map(int, t.split(":"))
        return hr * 60 + mn

    is_night = shift_type == "night"
    new_start_m = to_minutes(new_start)
    new_end_m = to_minutes(new_end) + (1440 if new_end < new_start else 0)

    for e in existing:
        e_start, e_end = shift_times[e.shift_type]
        e_start_m = to_minutes(e_start)
        e_end_m = to_minutes(e_end) + (1440 if e_end < e_start else 0)

        if max(new_start_m, e_start_m) < min(new_end_m, e_end_m):
            return jsonify({
                "error": "Shift conflict!",
                "message": f"This staff member already has a {e.shift_type.capitalize()} shift on {shift_date}.",
                "conflicts": [{"id": e.id, "type": e.shift_type}]
            }), 400

    # Save
    if shift_id:
        schedule = StaffSchedule.query.get(shift_id)
        schedule.employee_id = emp_id
        schedule.shift_date = shift_date
        schedule.shift_type = shift_type
        schedule.notes = data.get("notes", "")
    else:
        schedule = StaffSchedule(
            employee_id=emp_id,
            shift_date=shift_date,
            shift_type=shift_type,
            notes=data.get("notes", "")
        )
        db.session.add(schedule)

    db.session.commit()
    return '', 204


# ---------------- SHIFT UPDATE ----------------
@app.route('/update_shift_date', methods=['POST'])
@login_required
def update_shift_date():
    if session.get('role') != 'manager':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    if not data or not data.get('shift_date') or not data.get('id'):
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE staff_schedule SET shift_date=? WHERE id=?", (data['shift_date'], data['id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 200


# ---------------- API: STAFF LIST ----------------
@app.route('/api/staff_list')
@login_required
def staff_list():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT staff_number, first_name, last_name, role 
        FROM employees 
        WHERE active = 1
    """)
    staff = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(staff), 200


# ---------------- MANAGER: SEND MESSAGE ----------------
@app.route('/manager_send_message', methods=['POST'])
@login_required
def manager_send_message():
    if session.get('role') != 'manager':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # CSRF enforcement
    if session.get('csrf_token') != request.form.get('csrf_token'):
        return jsonify({'success': False, 'message': 'Invalid CSRF'}), 403

    msg_type = request.form.get('msg_type', 'announcement')
    title = (request.form.get('title') or '').strip()
    message = (request.form.get('message') or '').strip()
    pinned = 'pinned' in request.form

    if not message:
        return jsonify({'success': False, 'message': 'Message required'}), 400

    conn = get_db_connection()
    c = conn.cursor()

    try:
        if msg_type == 'announcement':
            target_role = request.form.get('target_role')
            if target_role not in ['all', 'doctor', 'nurse', 'receptionist']:
                return jsonify({'success': False, 'message': 'Invalid role'}), 400

            c.execute("""
                INSERT INTO announcements
                (title, message, author, target_role, pinned, category, timestamp)
                VALUES (?, ?, ?, ?, ?, 'general', datetime('now'))
            """, (title or 'Announcement', message, session['username'], target_role, pinned))

            target_text = "All Staff" if target_role == "all" else f"{target_role.capitalize()}s"

        else:  # direct message
            target_user = request.form.get('target_user')
            if not target_user:
                return jsonify({'success': False, 'message': 'Select recipient'}), 400

            c.execute("""
                INSERT INTO direct_messages (sender_id, recipient_id, message, timestamp)
                VALUES (?, ?, ?, datetime('now'))
            """, (session['user_id'], target_user, message))

            c.execute("SELECT first_name, last_name FROM employees WHERE staff_number = ?", (target_user,))
            user = c.fetchone()
            target_text = f"{user['first_name']} {user['last_name']}" if user else "User"

        conn.commit()

        # Broadcast the notification to SSE clients
        broadcast_message({
            'title': title if title else ('Announcement' if msg_type == 'announcement' else 'Direct Message'),
            'message': message,
            'author': session['username'],
            'target_role': target_role if msg_type == 'announcement' else None,
            'target_user': target_user if msg_type == 'direct' else None,
            'target_text': target_text,
            'pinned': pinned and msg_type == 'announcement',
            'category': 'general',
            'timestamp': datetime.now().isoformat()
        })

        return jsonify({'success': True, 'message': 'Sent!'})

    except Exception as e:
        conn.rollback()
        app.logger.error(f"Send message error: {e}")
        return jsonify({'success': False, 'message': 'Failed'}), 500

    finally:
        conn.close()


# ---------------- SSE MESSAGE STREAM ----------------
clients = set()
message_queue = deque()
lock = threading.Lock()


@app.route('/stream_messages')
def stream_messages():
    def event_stream(client_id):
        last_ping = datetime.now()
        try:
            while True:
                # Send a ping every 15 seconds to keep connection alive
                if (datetime.now() - last_ping).seconds >= 15:
                    yield "data: ping\n\n"
                    last_ping = datetime.now()

                # Send any queued messages
                with lock:
                    while message_queue:
                        msg = message_queue.popleft()
                        yield f"data: {json.dumps(msg)}\n\n"

                time.sleep(0.4)  # prevent busy-waiting CPU spikes

        except GeneratorExit:
            # Client disconnected
            with lock:
                clients.discard(client_id)
            print(f"Client {client_id} disconnected")

    # Register client
    client_id = request.remote_addr
    with lock:
        clients.add(client_id)
        print(f"Client {client_id} connected")

    return Response(stream_with_context(event_stream(client_id)),
                    mimetype="text/event-stream")


def broadcast_message(msg):
    with lock:
        message_queue.append(msg)

@app.route('/download_guide')
@login_required
def download_guide():
    try:
        return send_file(
            'static/guide/conversation_guide.pdf',
            as_attachment=True,
            download_name='ClinicCare_Guide_2025.pdf'
        )
    except FileNotFoundError:
        flash("Guide not found. Please contact admin.", "error")
        return redirect(url_for('manager_dashboard'))

#--------------------------------------------------------------------------------------------------------

# ---------------- CHANGE THEME ----------------
@app.route('/change_theme', methods=['POST'])
@login_required
def change_theme():
    theme = request.form.get('theme')
    if theme in ['light', 'dark']:
        session['theme'] = theme
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE employees SET theme = ? WHERE staff_number = ?",
            (theme, session.get('staff_number'))
        )
        conn.commit()
        conn.close()
    return '', 204


# ---------------- DOCTOR REPORT ----------------
@app.route('/doctor_report')
@login_required
def doctor_report():
    if session.get('role') != 'doctor':
        flash('Access denied.', 'error')
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['user_id'],))
        employee = c.fetchone()
        if not employee:
            flash('Doctor not found.', 'error')
            return redirect(url_for('doctor_dashboard'))

        employee_id = employee['id']
        c.execute("""
            SELECT a.id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.helper_id = ? AND DATE(a.appointment_date) >= DATE('now', '-30 days')
            ORDER BY a.appointment_date DESC
        """, (employee_id,))

        reports = [
            {
                'id': row['id'],
                'patient_name': f"{row['first_name']} {row['last_name']}",
                'appointment_date': row['appointment_date'],
                'status': row['status'],
                'reason': row['reason'] or 'Not specified'
            }
            for row in c.fetchall()
        ]
        return render_template('doctor/doctor_report.html', reports=reports)

    except Exception as e:
        logger.error(f"Error fetching doctor report: {e}")
        flash('Database error.', 'error')
        return redirect(url_for('doctor_dashboard'))
    finally:
        conn.close()


# ---------------- SYSTEM SETTINGS ----------------
@app.route('/system_settings', methods=['GET', 'POST'])
@login_required
@admin_required
def system_settings():
    settings_file = os.path.join(app.instance_path, 'system_settings.json')
    system_settings = {}

    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r') as f:
                system_settings = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load system settings: {e}")
            system_settings = {}

    if request.method == 'POST':
        data = request.form.to_dict()
        action = data.get('action')

        if action == 'add_user':
            username = data.get('add_user_username')
            role = data.get('add_user_role')
            if username and role:
                flash(f"User '{username}' added as {role}.", "success")

        elif action == 'reset_password':
            flash("Password reset requested.", "info")

        else:
            save_keys = [
                'clinic_name', 'clinic_address', 'clinic_contact', 'clinic_logo',
                'branding_color', 'operating_hours', 'holiday_calendar', 'password_policy'
            ]
            updated = {k: data.get(k, '') for k in save_keys}
            system_settings.update(updated)

            os.makedirs(app.instance_path, exist_ok=True)
            with open(settings_file, 'w') as f:
                json.dump(system_settings, f, indent=2)
            flash("System settings saved successfully.", "success")

        return redirect(url_for('system_settings'))

    return render_template('admin/systemSettings.html', system_settings=system_settings)


# ---------------- ANNOUNCEMENTS ----------------
@app.route('/announcements', methods=['GET', 'POST'])
@login_required
def announcements():
    if session.get('role') != 'admin':
        flash('Please log in as an admin to manage announcements.', 'error')
        return redirect(url_for('login_page'))

    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))

        if request.method == 'POST':
            title       = (request.form.get('title') or '').strip()
            message     = (request.form.get('message') or '').strip()
            category    = (request.form.get('category') or '').strip()
            target_role = (request.form.get('target_role') or 'all').strip()
            pinned      = request.form.get('pinned') == 'on'

            if not title or not message or not category:
                flash('Title, message and category are required.', 'error')
                return redirect(url_for('announcements'))

            if target_role not in ['all', 'doctor', 'nurse', 'receptionist']:
                flash('Invalid target role selected.', 'error')
                return redirect(url_for('announcements'))

            c.execute("""
                INSERT INTO announcements
                (title, message, category, author, pinned, target_role)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                title, message, category,
                f"{user_details['first_name']} {user_details['last_name']}",
                pinned, target_role
            ))
            conn.commit()
            flash('Announcement created successfully!', 'success')
            return redirect(url_for('announcements'))

        # GET: List all announcements
        c.execute("""
            SELECT id, title, message, category, author, timestamp, pinned, target_role
            FROM announcements
            ORDER BY pinned DESC, timestamp DESC
        """)
        announcements = [
            {
                'id': row['id'],
                'title': row['title'],
                'message': row['message'],
                'category': row['category'],
                'author': row['author'],
                'timestamp': row['timestamp'],
                'pinned': row['pinned'],
                'target_role': row['target_role'] or 'all'
            }
            for row in c.fetchall()
        ]
        return render_template('admin/announcement.html', announcements=announcements,
                               user_details=user_details, username=session['username'])

    except sqlite3.Error as e:
        logger.error(f"Database error in announcements: {e}")
        flash('An error occurred while managing announcements.', 'error')
        return redirect(url_for('admin_dashboard'))

    finally:
        if conn:
            conn.close()

# ---------------- TOGGLE AVAILABILITY ----------------
def broadcast_message(msg):
    """Send message to all connected clients (SSE)."""
    with lock:
        message_queue.append(msg)

@app.route('/toggle_availability', methods=['POST'])
@login_required
def toggle_availability():
    if session.get('role') not in ['doctor', 'nurse']:
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403

    new_status = request.form.get('status')
    if new_status not in ['available', 'unavailable']:
        return jsonify({'success': False, 'message': 'Invalid status.'}), 400

    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE employees SET availability = ? WHERE staff_number = ?",
                  (new_status, session['username']))

        if c.rowcount == 0:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

        # Notify system & managers
        c.execute("SELECT first_name, last_name, role FROM employees WHERE staff_number = ?", 
                  (session['username'],))
        user = c.fetchone()
        notification = f"{user['first_name']} {user['last_name']} ({user['role']}) is now {new_status}."
        c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                  (f"{user['role'].capitalize()} Status Update", notification, 'System'))
        conn.commit()

        # Broadcast to SSE clients
        broadcast_message({
            'type': 'availability_update',
            'staff': f"{user['first_name']} {user['last_name']}",
            'role': user['role'],
            'status': new_status
        })

        return jsonify({'success': True, 'message': f'Availability set to {new_status}.'})

    except sqlite3.Error as e:
        logger.error(f"Database error in toggle_availability: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()

# ---------------- EMERGENCY REQUEST ----------------
@csrf.exempt
@app.route('/emergency_request', methods=['POST'])
@login_required
def emergency_request():
    patient_id = request.form.get('patient_id')
    reason = (request.form.get('reason') or '').strip()
    if not patient_id or not reason:
        return jsonify({'success': False, 'message': 'Patient ID and reason are required.'}), 400

    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
        if not c.fetchone():
            return jsonify({'success': False, 'message': 'Patient not found.'}), 404

        # Insert request with audit: who submitted
        c.execute("""
            INSERT INTO emergency_requests (patient_id, reason, request_time, status, submitted_by)
            VALUES (?, ?, ?, ?, ?)
        """, (patient_id, reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'pending', session['username']))
        conn.commit()

        # Broadcast new emergency request
        broadcast_message({
            'type': 'emergency_request',
            'patient_id': patient_id,
            'reason': reason,
            'submitted_by': session['username']
        })

        return jsonify({'success': True, 'message': 'Emergency request submitted successfully!'})

    except sqlite3.Error as e:
        logger.error(f"Database error in emergency_request: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()


# ---------------- VIEW EMERGENCY REQUESTS ----------------
@app.route('/view_emergency_requests')
@login_required
def view_emergency_requests():
    if session.get('role') not in ['doctor', 'nurse']:
        flash('Please log in as a doctor or nurse to view emergency requests.', 'error')
        return redirect(url_for('login_page'))

    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Get user details
        c.execute("SELECT * FROM employees WHERE staff_number = ?", (session['username'],))
        user_details = c.fetchone()
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))

        # Fetch all emergency requests
        c.execute("""
            SELECT er.id, er.patient_id, p.first_name, p.last_name, er.reason, er.request_time, er.status
            FROM emergency_requests er
            JOIN patients p ON er.patient_id = p.id
            ORDER BY er.request_time DESC
        """)
        emergency_requests = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'reason': row['reason'],
                'request_time': row['request_time'],
                'status': row['status']
            } for row in c.fetchall()
        ]

        return render_template('emergency_requests.html',
                               emergency_requests=emergency_requests,
                               user_details=user_details,
                               username=session['username'])

    except sqlite3.Error as e:
        logger.error(f"Database error in view_emergency_requests: {e}")
        flash('An error occurred while fetching emergency requests.', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()
            
from werkzeug.utils import secure_filename

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # current_user is already loaded by Flask-Login → no session or raw DB needed
    employee = current_user

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        availability = request.form.get('availability')
        specialization = request.form.get('specialization') if employee.role == 'doctor' else employee.specialization

        if not all([first_name, last_name, email]):
            flash("First name, last name, and email are required.", "error")
            return redirect(url_for('edit_profile'))

        # Update basic fields
        employee.first_name = first_name.strip()
        employee.last_name = last_name.strip()
        employee.email = email.strip().lower()
        employee.phone = phone.strip() or None
        employee.availability = availability

        if employee.role == 'doctor':
            employee.specialization = specialization.strip() if specialization else None

        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"profile_{employee.id}_{int(time.time())}_{file.filename}")
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                file.save(upload_path)
                employee.profile_image = f"uploads/{filename}"
                flash("Profile picture updated!", "success")

        # Password change logic
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if any([current_password, new_password, confirm_password]):
            if not all([current_password, new_password, confirm_password]):
                flash("All password fields are required to change password.", "error")
            elif not check_password_hash(employee.password, current_password):
                flash("Current password is incorrect.", "error")
            elif new_password != confirm_password:
                flash("New passwords do not match.", "error")
            elif len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
            else:
                employee.password = generate_password_hash(new_password)
                flash("Password changed successfully!", "success")

        try:
            db.session.commit()
            flash("Profile updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Profile update failed: {e}")
            flash("Failed to update profile. Please try again.", "error")

        return redirect(url_for('edit_profile'))

    # GET request → show form
    return render_template('edit_profile.html', employee=employee)         

@app.route('/update_emergency_request/<int:request_id>', methods=['POST'])
def update_emergency_request(request_id):
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        status = request.form.get('status')
        if status not in ['pending', 'in_progress', 'resolved']:
            return jsonify({'success': False, 'message': 'Invalid status.'}), 400
        c.execute("UPDATE emergency_requests SET status = ? WHERE id = ?", (status, request_id))
        if c.rowcount > 0:
            conn.commit()
            return jsonify({'success': True, 'message': f'Emergency request status updated to {status}.'})
        else:
            return jsonify({'success': False, 'message': 'Emergency request not found.'}), 404
    except sqlite3.Error as e:
        logger.error(f"Database error in update_emergency_request: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/health')
def health():
    try:
        db.session.execute(db.text('SELECT 1'))
        return {"status": "healthy", "db": "ok"}, 200
    except:
        return {"status": "unhealthy", "db": "down"}, 500

@app.route('/logout')
@login_required
def logout():
    # Optional: Set doctor/nurse as unavailable on logout
    if current_user.role in ['doctor', 'nurse']:
        current_user.availability = 'unavailable'
        db.session.commit()

        notification = f"{current_user.first_name} {current_user.last_name} ({current_user.role}) is now unavailable."
        msg = Message(title="Staff Status", content=notification, sender="System")
        db.session.add(msg)
        db.session.commit()

    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_page'))

def upgrade_database():
    """
    Safely adds missing columns (like 'active') without dropping data.
    Only runs if column doesn't exist.
    """
    import sqlite3
    conn = sqlite3.connect('clinicinfo.db')
    c = conn.cursor()

    # Check for 'active' column
    c.execute("PRAGMA table_info(employees)")
    columns = [row[1] for row in c.fetchall()]

    if 'active' not in columns:
        print("Adding missing 'active' column to employees table...")
        c.execute("""
            ALTER TABLE employees 
            ADD COLUMN active BOOLEAN NOT NULL DEFAULT 1
        """)
        print("'active' column added. All existing users set to active.")
    
    conn.commit()
    conn.close()

# Call it on startup
with app.app_context():
    try:
        upgrade_database()  # runs migrations
        print("Database ready.")

    except Exception as e:
        print(f"DB Error: {e}")   

def get_user_details(staff_number):
    """Fallback for old templates"""
    user = Employee.query.filter_by(staff_number=staff_number).first()
    if user:
        return {
            'name': f"{user.first_name} {user.last_name}",
            'role': user.role,
            'profile_pic': user.profile_pic or '/static/default.jpg'
        }
    return {'name': 'User', 'role': 'unknown', 'profile_pic': '/static/default.jpg'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
else:
    # When run via Gunicorn (Azure/Docker production)
    init_db()