from flask import Flask, g, json, request, current_app, redirect, url_for, render_template, session, flash, Response, jsonify, abort, stream_with_context
from markupsafe import Markup
from datetime import datetime, date, timedelta
from flask.logging import create_logger
from werkzeug.utils import secure_filename
import secrets, string, jinja2, traceback, csv, time, json, re, random, logging, os, sqlite3
from models import db, Announcement
from sqlalchemy import or_
from collections import deque
import threading
from queue import Queue
from threading import Lock
from flask_caching import Cache
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import DateField, StringField, PasswordField, SubmitField, EmailField, DateTimeField, BooleanField, SelectField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from io import StringIO
from flask import send_file
from functools import wraps


load_dotenv()
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

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != required_role:
                flash("Access denied. You do not have permission.", "error")
                return redirect(url_for('login_page'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Load environment variables from .env file
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Validate
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY not set!")
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise ValueError("DATABASE_URL not set!")
csrf = CSRFProtect(app)

# --- DATABASE: Auto-detect .env (PostgreSQL) or clinicinfo.db (SQLite) ---
db_url = os.getenv('DATABASE_URL')
if db_url:
    # Force TCP/IP: add host=127.0.0.1 port=5433 if not present
    if 'host=' not in db_url:
        db_url += '?host=127.0.0.1&port=5433'
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
elif os.path.exists('clinicinfo.db'):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinicinfo.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinicinfo.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app.jinja_env.filters['datetime'] = lambda d, f: datetime.strptime(d, '%Y-%m-%d %H:%M:%S').strftime(f) if d else 'N/A'

# Static file configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'clinicinfo.db')}"

# Static folders
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

bcrypt = Bcrypt(app)
db.init_app(app)

# In-memory queues for notifications
announcement_queue = Queue()
appointment_queue = Queue()
queue_lock = Lock()
waiting_patients_queue = Queue()

def allowed_file(filename):
    
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- FIXED: App-context safe DB connection ---
def get_db_connection():
    """
    Returns a SQLite connection:
      • From g.db during requests
      • Creates a new one in background threads / startup
    """
    if 'db' in g:
        return g.db

    # Fallback: create a new connection (e.g., SSE, background tasks)
    try:
        conn = sqlite3.connect('clinicinfo.db', check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Failed to create fallback DB connection: {e}")
        raise
# Set up g.db on request start
@app.before_request
def before_request():
    g.db = get_db_connection()
    
@app.before_request
def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

# Teardown
@app.teardown_appcontext
def teardown_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Optional: expose via current_app for legacy
with app.app_context():
    current_app.config['DB_CONNECTION'] = get_db_connection()  

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()      

def get_user_details(conn, user_id):
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM employees WHERE staff_number = ?", (user_id,))
        user = c.fetchone()
        return dict(user) if user else {}
    except sqlite3.Error as e:
        logger.error(f"Error fetching user details: {e}")
        return {}
    
def jinja_strftime(value, format='%H:%M'):
    if not value:
        return ''
    try:
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return dt.strftime(format)
    except:
        return value[:5]  # fallback

app.jinja_env.filters['strftime'] = jinja_strftime

# In script.py (top, after imports)
def get_setting(key, default=''):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else default

def set_setting(key, value):
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = SystemSetting(key=key, value=value)
        db.session.add(setting)
    db.session.commit()

# Custom error handler for template not found
@app.errorhandler(jinja2.exceptions.TemplateNotFound)
def template_not_found(e):
    logger.error(f"Template not found: {e.name}")
    flash(f"Template {e.name} is missing. Please contact the administrator.", 'error')
    return render_template('homepage/error.html'), 404

# --- REPLACED: Use SQLAlchemy for both SQLite & PostgreSQL ---
def init_db():
    """
    Initialize database using SQLAlchemy.
    Works with:
      • SQLite (clinicinfo.db)
      • PostgreSQL (via DATABASE_URL in .env)
    """
    with app.app_context():
        db.create_all()
        logger.info("Database tables created via SQLAlchemy (SQLite or PostgreSQL)")
        return True

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = str(id)
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT staff_number, role FROM employees WHERE staff_number = ?", (user_id,))
        user = c.fetchone()
        if user and session.get('user_id') == user['staff_number']:
            return User(id=user['staff_number'], username=user['staff_number'], role=user['role'])
    except:
        pass
    finally:
        conn.close()
    return None  

@app.route('/')
def default_page():
    if 'user_id' in session:
        role = session.get('role', 'user')
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'nurse':
            return redirect(url_for('nurse_dashboard'))
        elif role == 'receptionist':
            return redirect(url_for('reception_dashboard'))
    
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
    form = LoginForm()
    if form.validate_on_submit():
        username_input = form.username.data.strip()
        password = form.password.data
        remember = form.remember.data

        if not all([username_input, password]):
            flash('Both username and password are required.', 'error')
            return render_template('homepage/login_page.html', form=form)

        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
                SELECT staff_number, password, role, first_name, last_name, active, profile_image 
                FROM employees 
                WHERE (staff_number = ? OR email = ?) AND active = 1
            """, (username_input, username_input))
            user = c.fetchone()

            if user and bcrypt.check_password_hash(user['password'], password):
                session.clear()
                session.permanent = True
                session.modified = True

                session['user_id'] = user['staff_number']
                session['staff_number'] = user['staff_number']
                session['username'] = f"{user['first_name']} {user['last_name']}"
                session['role'] = user['role']
                session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S SAST')
                session['profile_image'] = user['profile_image'] or 'profile_images/user.png'  # ADD THIS LINE

                if remember:
                    app.permanent_session_lifetime = timedelta(days=30)
                else:
                    app.permanent_session_lifetime = timedelta(hours=8)

                flash('Login successful!', 'success')
                logger.info(f"User {user['staff_number']} ({user['role']}) logged in.")

                role = user['role'].lower()
                redirect_map = {
                    'receptionist': 'reception_dashboard',
                    'admin': 'admin_dashboard',
                    'doctor': 'doctor_dashboard',
                    'nurse': 'nurse_dashboard',
                    'manager': 'manager_dashboard'
                }
                endpoint = redirect_map.get(role)
                if endpoint:
                    return redirect(url_for(endpoint))
                else:
                    flash('Unknown role. Contact admin.', 'error')
                    return redirect(url_for('default_page'))

            else:
                flash('Invalid username, password, or account inactive.', 'error')
                logger.warning(f"Failed login: {username_input}")

        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login failed. Try again.', 'error')
        finally:
            if conn:
                conn.close()

    return render_template('homepage/login_page.html', form=form)

    next_page = request.args.get('next')
    if next_page and next_page.startswith('/'):
        form.next.data = next_page

    return render_template('homepage/login_page.html', form=form)

# --------------------------------------------------------------
# POST: Create New User (Admin Only) – FIXED CSRF
# --------------------------------------------------------------
@app.route('/create_user', methods=['POST'])
def create_user():
    # Only admin can create users
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # CSRF protection
    if not request.form.get('csrf_token'):
        return jsonify({'success': False, 'message': 'CSRF token missing'}), 403

    data = request.form
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    email = data.get('email', '').strip().lower()
    role = data.get('role')

    # === VALIDATION ===
    if not all([first_name, last_name, email, role]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # Allow 'manager' in valid roles
    valid_roles = ['doctor', 'nurse', 'receptionist', 'manager']
    if role not in valid_roles:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Check if email already exists
        c.execute("SELECT id FROM employees WHERE email = ?", (email,))
        if c.fetchone():
            return jsonify({'success': False, 'message': 'Email already in use'}), 400

        # Generate staff number
        c.execute("SELECT MAX(CAST(SUBSTR(staff_number, 6) AS INTEGER)) FROM employees WHERE staff_number GLOB 'STAFF[0-9][0-9][0-9]'")
        max_num = c.fetchone()[0] or 0
        staff_number = f"STAFF{str(max_num + 1).zfill(3)}"

        # GENERATE RANDOM 10-CHAR PASSWORD
        alphabet = string.ascii_letters + string.digits
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(10))
        hashed_password = bcrypt.generate_password_hash(temp_password).decode('utf-8')

        # Insert new user
        c.execute('''
            INSERT INTO employees 
            (staff_number, first_name, last_name, email, password, role, 
             availability, profile_image, active)
            VALUES (?, ?, ?, ?, ?, ?, 'available', 'default.jpg', ?)
        ''', (staff_number, first_name, last_name, email, hashed_password, role, 1))

        conn.commit()

        # Audit log
        c.execute('''
            INSERT INTO audit_log (action, performed_by, target_user, details, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        ''', (
            'create_user',
            session['username'],
            staff_number,
            f"Created {role}: {staff_number} | Temp: {temp_password}"
        ))
        conn.commit()

        logger.info(f"Admin {session['username']} created {role}: {staff_number}")

        return jsonify({
            'success': True,
            'staff_number': staff_number,
            'temp_password': temp_password,
            'message': f'{role.capitalize()} created successfully! Password: {temp_password}'
        })

    except Exception as e:
        logger.error(f"Create user error: {e}")
        conn.rollback()
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500
    finally:
        conn.close()


# --------------------------------------------------------------
# POST: Delete User – FIXED CSRF
# --------------------------------------------------------------
@app.route('/delete_user', methods=['POST'])
def delete_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    if not request.form.get('csrf_token'):
        logger.warning("CSRF token missing in delete_user")
        return jsonify({'success': False, 'message': 'CSRF token missing'}), 403

    user_id = request.form.get('user_id')
    reason = request.form.get('reason')

    if not user_id or not reason:
        return jsonify({'success': False, 'message': 'Missing ID or reason'}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, staff_number, first_name, last_name, role FROM employees WHERE id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user['role'] == 'admin':
            return jsonify({'success': False, 'message': 'Cannot delete admin'}), 403

        c.execute("DELETE FROM employees WHERE id = ?", (user_id,))
        conn.commit()

        c.execute('''
            INSERT INTO audit_log (action, performed_by, target_user, details, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        ''', ('delete_user', session['username'], user['staff_number'], f"Reason: {reason}"))
        conn.commit()

        return jsonify({'success': True, 'message': 'User deleted successfully'})

    except Exception as e:
        logger.error(f"Delete user error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/search_patient', methods=['GET', 'POST'])
def search_patient():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        flash('Please log in as a receptionist.', 'error')
        return redirect(url_for('login_page'))

    form = SearchForm()
    patients = []
    search_performed = False
    search_term = ''

    if form.validate_on_submit():
        search_term = form.search_term.data.strip()
        search_performed = True
        conn = get_db_connection()
        patients = conn.execute('''
            SELECT id, first_name, last_name FROM patients
            WHERE id LIKE ? OR first_name LIKE ? OR last_name LIKE ?
            ORDER BY id DESC
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')).fetchall()
        conn.close()

    return render_template('reception/search_patient.html',
                           search_form=form,
                           patients=patients,
                           search_performed=search_performed,
                           search_term=search_term)

@app.route('/cancel_appointment', methods=['POST'])
def cancel_appointment():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    
    appointment_id = request.form.get('appointment_id')
    if not appointment_id:
        flash('Invalid appointment ID.', 'error')
        return redirect(url_for('reception_dashboard'))

    conn = sqlite3.connect('clinicinfo.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appointment_id,))
    if cursor.rowcount > 0:
        flash('Appointment cancelled successfully.', 'success')
    else:
        flash('Appointment not found or already cancelled.', 'error')
    conn.commit()
    conn.close()
    return redirect(url_for('reception_dashboard'))

@app.route('/assign_staff', methods=['POST'])
def assign_staff():
    if session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    
    # CSRF check
    if not request.form.get('csrf_token') or request.form.get('csrf_token') != session.get('csrf_token'):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('reception_dashboard'))

    appointment_id = request.form.get('appointment_id')
    staff_id = request.form.get('staff_id')
    if not all([appointment_id, staff_id]):
        flash('Missing appointment or staff ID.', 'error')
        return redirect(url_for('reception_dashboard'))

    conn = sqlite3.connect('clinicinfo.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE appointments SET helper_id = ?, status = 'assigned' WHERE id = ?", (staff_id, appointment_id))
    if cursor.rowcount > 0:
        flash('Staff assigned successfully.', 'success')
    else:
        flash('Appointment not found.', 'error')
    conn.commit()
    conn.close()
    return redirect(url_for('reception_dashboard'))

@app.route('/reschedule_appointment', methods=['POST'])
def reschedule_appointment():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        new_time = request.form.get('new_time')
        if not appointment_id or not new_time:
            flash('Appointment ID and new time are required.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("UPDATE appointments SET appointment_date = ?, status = 'scheduled' WHERE id = ? AND status = 'scheduled'", (new_time, appointment_id))
        if c.rowcount > 0:
            c.execute("SELECT patient_id, appointment_date, reason FROM appointments WHERE id = ?", (appointment_id,))
            appt = c.fetchone()
            c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appt['patient_id'],))
            patient = c.fetchone()
            with queue_lock:
                appointment_queue.put({
                    'id': appointment_id,
                    'patient_id': appt['patient_id'],
                    'first_name': patient['first_name'],
                    'last_name': patient['last_name'],
                    'appointment_date': new_time,
                    'reason': appt['reason'],
                    'status': 'scheduled'
                })
            conn.commit()
            flash('Appointment rescheduled successfully!', 'success')
        else:
            flash('Appointment not found or not scheduled.', 'error')
        return redirect(url_for('appointment_homepage'))
    except Exception as e:
        logger.error(f"Error in reschedule_appointment: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('appointment_homepage'))
    finally:
        if conn:
            conn.close()

@csrf.exempt
@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        flash('Please log in as a receptionist.', 'error')
        return redirect(url_for('login_page'))

    form = PatientForm()  # This is your WTForms class

    if form.validate_on_submit():
        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()

            # Insert patient
            c.execute('''
                INSERT INTO patients (
                    first_name, last_name, date_of_birth, gender, address, phone, email,
                    emergency_contact_name, emergency_contact_phone, medical_history,
                    allergies, current_medications
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                form.first_name.data,
                form.last_name.data,
                form.date_of_birth.data.strftime('%Y-%m-%d'),
                form.gender.data,
                form.address.data,
                form.phone.data,
                form.email.data,
                form.emergency_contact_name.data,
                form.emergency_contact_phone.data,
                form.medical_history.data,
                form.allergies.data,
                form.current_medications.data
            ))
            conn.commit()
            flash('Patient registered successfully!', 'success')
            return redirect(url_for('search_patient'))

        except sqlite3.Error as e:
            logger.error(f"Database error in add_patient: {e}")
            flash(f'Failed to register patient: {str(e)}', 'error')
        finally:
            if conn:
                conn.close()
    else:
        # Show form errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", 'error')

    return render_template('reception/patientRegistration.html', form=form)

# --------------------------------------------------------------
# RECEPTION: Walk-in patient check-in
# --------------------------------------------------------------
@csrf.exempt
@app.route('/add_walkin')
def add_walkin():
    if session.get('role') != 'receptionist':
        flash('Reception access only.', 'error')
        return redirect(url_for('login_page'))

    patient_id = request.args.get('patient_id')
    if not patient_id:
        flash('No patient selected.', 'error')
        return redirect(url_for('search_patient'))

    conn = get_db_connection()
    try:
        c = conn.cursor()

        # Verify patient exists
        c.execute('SELECT id, first_name, last_name FROM patients WHERE id = ?', (patient_id,))
        patient = c.fetchone()
        if not patient:
            flash('Patient not found.', 'error')
            return redirect(url_for('search_patient'))

        # Insert walk-in appointment
        c.execute('''
            INSERT INTO appointments 
            (patient_id, appointment_date, status, reason, created_by_role)
            VALUES (?, datetime('now'), 'waiting', 'Walk-in', 'receptionist')
        ''', (patient_id,))
        conn.commit()

        flash(f'Walk-in check-in successful for {patient["first_name"]} {patient["last_name"]}.', 'success')
        return redirect(url_for('check_in_desk'))

    except sqlite3.Error as e:
        logger.error(f"Walk-in error: {e}")
        flash('Database error. Please try again.', 'error')
        return redirect(url_for('search_patient'))
    finally:
        if conn:
            conn.close()
            
# --------------------------------------------------------------
# PUBLIC: Patient Self-Booking
# --------------------------------------------------------------
@app.route('/patient_book_appointment', methods=['GET', 'POST'])
def patient_book_appointment():
    form = PatientBookAppointmentForm()
    doctors = []
    success_data = None

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT staff_number, first_name, last_name FROM employees WHERE role = 'doctor' AND availability = 'available'")
        doctors = c.fetchall()
    except Exception as e:
        logger.error(f"Failed to load doctors: {e}")
    finally:
        conn.close()

    if form.validate_on_submit():
        try:
            conn = get_db_connection()
            c = conn.cursor()
            appointment_dt = form.date.data
            appointment_date = appointment_dt.strftime('%Y-%m-%d %H:%M:%S')
            doctor_staff = request.form.get('doctor')

            # Fixed variable names
            patient_name = form.patient_name.data.strip()
            patient_phone = form.patient_phone.data.strip()
            patient_email = form.patient_email.data.strip()
            reason = form.reason.data.strip()

            c.execute('''
                INSERT INTO self_booked_appointments 
                (patient_name, patient_phone, patient_email, appointment_date, reason, status, doctor_staff_number)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
            ''', (
                patient_name,
                patient_phone,
                patient_email,
                appointment_date,
                reason,
                doctor_staff
            ))
            conn.commit()

            success_data = {
                'date': appointment_dt.strftime('%B %d, %Y at %I:%M %p'),
                'doctor': next((f"Dr. {d[1]} {d[2]}" for d in doctors if d[0] == doctor_staff), 'Selected Doctor')
            }
            flash('Appointment request sent! Awaiting confirmation.', 'success')

        except sqlite3.Error as e:
            logger.error(f"Self-booking error: {e}")
            flash('Error saving appointment. Please try again.', 'error')
        finally:
            if conn:
                conn.close()

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
def manage_appointments():
    if session.get('role') != 'receptionist':
        flash('Reception access only.', 'error')
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    cursor = conn.cursor()
    selected_patient_id = request.args.get('patient_id')

    # -----------------------------------------------------------------
    # Initialize ALL variables (prevents NameError)
    # -----------------------------------------------------------------
    patients = []
    available_staff = []
    self_booked_appointments = []
    appointments = []

    try:
        # -----------------------------------------------------------------
        # 1. Fetch Patients
        # -----------------------------------------------------------------
        cursor.execute("SELECT id, first_name || ' ' || last_name AS name FROM patients ORDER BY name")
        patients = [dict(row) for row in cursor.fetchall()]

        # -----------------------------------------------------------------
        # 2. Fetch Available Staff
        # -----------------------------------------------------------------
        cursor.execute("""
            SELECT id, staff_number, first_name || ' ' || last_name AS name, role 
            FROM employees 
            WHERE availability = 'available' 
              AND role IN ('doctor', 'nurse')
            ORDER BY role, name
        """)
        available_staff = [dict(row) for row in cursor.fetchall()]

        # -----------------------------------------------------------------
        # 3. Fetch Pending Self-Booked
        # -----------------------------------------------------------------
        cursor.execute("""
            SELECT id, patient_name, patient_phone, patient_email, 
                   appointment_date, reason, doctor_staff_number
            FROM self_booked_appointments 
            WHERE status = 'pending' 
            ORDER BY id DESC
        """)
        self_booked_appointments = [dict(row) for row in cursor.fetchall()]

        # -----------------------------------------------------------------
        # 4. Fetch Active Appointments
        # -----------------------------------------------------------------
        cursor.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, 
                   a.appointment_date, a.status, a.reason,
                   e.first_name || ' ' || e.last_name AS helper_name,
                   e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            WHERE a.status NOT IN ('cancelled', 'helped')
            ORDER BY a.appointment_date
        """)
        appointments = [dict(row) for row in cursor.fetchall()]

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

                cursor.execute("""
                    INSERT INTO appointments 
                    (patient_id, appointment_date, status, reason, helper_id, created_by_role)
                    VALUES (?, ?, 'scheduled', ?, ?, 'receptionist')
                """, (patient_id, appointment_time, reason, helper_id))
                conn.commit()
                return jsonify({'success': True, 'message': 'Booked!'})

            elif action == 'convert_self_booked':
                self_id = request.form.get('self_booked_id')
                patient_id = request.form.get('patient_id')
                appointment_time = request.form.get('appointment_time')
                reason = request.form.get('reason', '')
                helper_id = request.form.get('helper_id') or None

                if not all([self_id, patient_id, appointment_time]):
                    return jsonify({'success': False, 'message': 'Missing data'})

                cursor.execute("UPDATE self_booked_appointments SET status = 'converted' WHERE id = ?", (self_id,))
                cursor.execute("""
                    INSERT INTO appointments 
                    (patient_id, appointment_date, status, reason, helper_id, created_by_role)
                    VALUES (?, ?, 'scheduled', ?, ?, 'receptionist')
                """, (patient_id, appointment_time, reason, helper_id))
                conn.commit()
                return jsonify({'success': True, 'message': 'Confirmed!'})

            elif action == 'cancel_appointment':
                appt_id = request.form.get('appointment_id')
                if not appt_id:
                    return jsonify({'success': False, 'message': 'ID required'})
                cursor.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appt_id,))
                conn.commit()
                return jsonify({'success': True, 'message': 'Cancelled!'})

    except Exception as e:
        logger.error(f"Manage appointments error: {e}")
        flash('Database error.', 'error')

    finally:
        conn.close()

    # -----------------------------------------------------------------
    # 6. Render Template – ALWAYS pass all variables
    # -----------------------------------------------------------------
    return render_template(
        'reception/manage_appointments.html',
        patients=patients,
        available_staff=available_staff,
        self_booked_appointments=self_booked_appointments,
        appointments=appointments,
        selected_patient_id=selected_patient_id
    )
  
# --------------------------------------------------------------
# API: Get Current Queue
# --------------------------------------------------------------
@app.route('/api/queue')
def api_get_queue():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT q.*, p.first_name || ' ' || p.last_name AS full_name
        FROM walkin_queue q
        JOIN patients p ON q.patient_id = p.id
        WHERE q.status = 'waiting'
        ORDER BY 
            CASE q.priority 
                WHEN 'emergency' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            q.arrived_at ASC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

# --------------------------------------------------------------
# POST: Add Walk-in to Queue
# --------------------------------------------------------------
# --------------------------------------------------------------
# POST: Add Walk-in to Queue (Smart: Register if not exists)
# --------------------------------------------------------------
@csrf.exempt
@app.route('/check_in_desk', methods=['POST'])
def check_in_desk():  # ← Rename from add_walkin_smart to match JS
    if session.get('role') != 'receptionist':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.form
    action = data.get('action')

    conn = get_db_connection()
    c = conn.cursor()

    try:
        # ────── ADD EXISTING PATIENT TO QUEUE ──────
        if action == 'add_to_queue':
            patient_id = data.get('patient_id')
            priority = data.get('priority')
            reason = data.get('reason', '')

            if not patient_id or not priority:
                return jsonify({'success': False, 'message': 'Patient and priority required'}), 400

            c.execute("SELECT id, first_name, last_name FROM patients WHERE id = ?", (patient_id,))
            patient = c.fetchone()
            if not patient:
                return jsonify({'success': False, 'message': 'Patient not found'}), 404

            c.execute('''
                INSERT INTO walkin_queue (patient_id, patient_name, priority, reason, arrived_at)
                VALUES (?, ?, ?, ?, DATETIME('now'))
            ''', (patient_id, f"{patient[1]} {patient[2]}", priority, reason))
            queue_id = c.lastrowid
            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Added to queue',
                'patient': {
                    'id': queue_id,
                    'name': f"{patient[1]} {patient[2]}",
                    'priority': priority,
                    'reason': reason,
                    'arrivedAt': datetime.now().isoformat()
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

            c.execute('''
                INSERT INTO patients (first_name, last_name, phone, email)
                VALUES (?, ?, ?, ?)
            ''', (first_name, last_name, phone, email))
            patient_id = c.lastrowid

            priority = data.get('priority', 'low')
            reason = data.get('reason', '')
            c.execute('''
                INSERT INTO walkin_queue (patient_id, patient_name, priority, reason, arrived_at)
                VALUES (?, ?, ?, ?, DATETIME('now'))
            ''', (patient_id, f"{first_name} {last_name}", priority, reason))
            queue_id = c.lastrowid
            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Registered & added to queue',
                'patient': {
                    'id': queue_id,
                    'name': f"{first_name} {last_name}",
                    'priority': priority,
                    'reason': reason,
                    'arrivedAt': datetime.now().isoformat()
                }
            })

        return jsonify({'success': False, 'message': 'Invalid action'}), 400

    except Exception as e:
        app.logger.error(f"Error in check_in_desk: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500
    finally:
        conn.close()

# --------------------------------------------------------------
# POST: Call Next Patient
# --------------------------------------------------------------
@app.route('/call_next', methods=['POST'])
def call_next():
    if session.get('role') != 'receptionist':
        return jsonify({'success': False}), 403

    data = request.get_json()
    queue_id = data.get('queue_id')
    if not queue_id:
        return jsonify({'success': False, 'message': 'ID required'}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE walkin_queue SET status = 'called' WHERE id = ? AND status = 'waiting'", (queue_id,))
        if c.rowcount == 0:
            return jsonify({'success': False, 'message': 'Not found or already called'})
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# --------------------------------------------------------------
# POST: Remove from Queue
# --------------------------------------------------------------
@app.route('/remove_queue', methods=['POST'])
def remove_from_queue():
    if session.get('role') != 'receptionist':
        return jsonify({'success': False}), 403

    data = request.get_json()
    queue_id = data.get('queue_id')
    if not queue_id:
        return jsonify({'success': False, 'message': 'ID required'}), 400

    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM walkin_queue WHERE id = ?", (queue_id,))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# --------------------------------------------------------------
# SSE: Stream Queue Updates
# --------------------------------------------------------------
@app.route('/stream_queue')
def stream_queue():
    def event_stream():
        last_id = 0
        while True:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM walkin_queue WHERE id > ? AND status = 'waiting'", (last_id,))
            rows = c.fetchall()
            for row in rows:
                last_id = row['id']
                yield f"data: {json.dumps({'action': 'added', 'patient': dict(row)})}\n\n"
            conn.close()
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")
  
# --------------------------------------------------------------
# API: Search Patient by Phone
# --------------------------------------------------------------
@app.route('/api/search_patient')
def api_search_patient():
    phone = request.args.get('phone')
    if not phone:
        return jsonify({'patients': []})

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, first_name || ' ' || last_name AS name, phone FROM patients WHERE phone LIKE ?", (f'%{phone}%',))
    rows = c.fetchall()
    conn.close()
    return jsonify({'patients': [dict(row) for row in rows]})  
    
@app.route('/stream_appointments')
def stream_appointments():
    def event_stream():
        last_id = 0
        while True:
            conn = get_db_connection()
            try:
                c = conn.cursor()
                c.execute('SELECT * FROM appointments WHERE id > ? AND status IN ("waiting", "helped")', (last_id,))
                updates = c.fetchall()
                for u in updates:
                    last_id = u['id']
                    yield f"data: {json.dumps(dict(u))}\n\n"
            finally:
                conn.close()
            time.sleep(2)
    return Response(event_stream(), mimetype="text/event-stream")

@csrf.exempt
@app.route('/helped_patients_report')
def helped_patients_report():
    if 'user_id' not in session or session.get('role') != 'receptionist':  # Changed from 'username' to 'user_id'
        return redirect(url_for('login_page'))
    
    conn = sqlite3.connect('clinicinfo.db')  # Changed from 'clinic.db' to 'clinicinfo.db'
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM helped_patients")
    helped_patients = cursor.fetchall()
    conn.close()
    return render_template('reception/helped_patients_report.html', helped_patients=helped_patients)

@csrf.exempt
@app.route('/prescription_page/<int:patient_id>', methods=['GET', 'POST'])
def prescription_page(patient_id):
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        logger.error(f"Unauthorized access to prescription_page: username={session.get('username')}, role={session.get('role')}")
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, first_name, last_name FROM patients WHERE id = ?", (patient_id,))
        patient = c.fetchone()
        if not patient:
            logger.error(f"Patient not found: patient_id={patient_id}")
            flash('Patient not found.', 'error')
            return redirect(url_for('doctor_dashboard'))
        patient_data = {
            'id': patient['id'],
            'first_name': patient['first_name'],
            'last_name': patient['last_name']
        }
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            medication_name = request.form.get('medication_name', '').strip()
            dosage = request.form.get('dosage', '').strip()
            instructions = request.form.get('instructions', '').strip()
            if not medication_name or not dosage:
                flash('Medication name and dosage are required.', 'error')
                return render_template('prescription_page.html', patient=patient_data, user_details=user_details)
            c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],))
            doctor = c.fetchone()
            if not doctor:
                logger.error(f"Doctor not found: username={session['username']}")
                flash('Doctor not found.', 'error')
                return redirect(url_for('doctor_dashboard'))
            c.execute("""
                INSERT INTO prescriptions (patient_id, nurse_id, medication_name, dosage, instructions, prescribed_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (patient_id, doctor['id'], medication_name, dosage, instructions, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            c.execute("SELECT current_medications FROM patients WHERE id = ?", (patient_id,))
            current_meds = c.fetchone()['current_medications'] or ''
            updated_meds = f"{current_meds}, {medication_name} ({dosage})" if current_meds else f"{medication_name} ({dosage})"
            c.execute("UPDATE patients SET current_medications = ? WHERE id = ?", (updated_meds, patient_id))
            conn.commit()
            flash('Medication prescribed successfully!', 'success')
            return redirect(url_for('patient_profile', patient_id=patient_id))
        logger.debug(f"Rendering prescription_page for patient_id={patient_id}, username={session['username']}")
        return render_template('prescription_page.html', patient=patient_data, user_details=user_details)
    except Exception as e:
        logger.error(f"Error in prescription_page: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('doctor_dashboard'))
    finally:
        if conn:
            conn.close()

@csrf.exempt
@app.route('/patient_profile/<int:patient_id>')
def patient_profile(patient_id):
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        logger.error(f"Unauthorized access to patient_profile: username={session.get('username')}, role={session.get('role')}")
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, first_name, last_name, date_of_birth, gender, medical_history, allergies, current_medications
            FROM patients WHERE id = ?
        """, (patient_id,))
        patient = c.fetchone()
        if not patient:
            logger.error(f"Patient not found: patient_id={patient_id}")
            flash('Patient not found.', 'error')
            return redirect(url_for('doctor_dashboard'))
        patient_data = {
            'id': patient['id'],
            'first_name': patient['first_name'],
            'last_name': patient['last_name'],
            'date_of_birth': patient['date_of_birth'],
            'gender': patient['gender'],
            'medical_history': patient['medical_history'] or 'No medical history recorded.',
            'allergies': patient['allergies'] or 'No allergies recorded.',
            'current_medications': patient['current_medications'] or 'No medications recorded.'
        }
        user_details = get_user_details(conn, session['username'])
        logger.debug(f"Rendering patient_profile for patient_id={patient_id}, username={session['username']}")
        return render_template('patient_profile.html', patient=patient_data, user_details=user_details)
    except Exception as e:
        logger.error(f"Error in patient_profile: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('doctor_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM employees")
        total_users = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role IN ('doctor', 'nurse', 'receptionist')")
        active_staff = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'pending'")
        system_alerts = c.fetchone()[0]
        c.execute("SELECT staff_number, email, role FROM employees ORDER BY id DESC LIMIT 5")
        recent_users = [{'staff_number': row['staff_number'], 'email': row['email'], 'role': row['role']} for row in c.fetchall()]
        user_details = get_user_details(conn, session['user_id'])
        return render_template('admin/adminDashboard.html',
                              username=session['user_id'],
                              total_users=total_users,
                              active_staff=active_staff,
                              system_alerts=system_alerts,
                              recent_users=recent_users,
                              user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/doctorDashboard.html')
def doctor_dashboard():
    if 'user_id' not in session or session.get('role') not in ['doctor', 'nurse']:
        logger.error(f"Unauthorized access: user_id={session.get('user_id')}, role={session.get('role')}")
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        employee_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['user_id'],)).fetchone()[0]
        c.execute("SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender FROM patients p WHERE p.employee_id = ?", (employee_id,))
        patients = [{'id': row['id'], 'first_name': row['first_name'], 'last_name': row['last_name'], 'date_of_birth': row['date_of_birth'], 'gender': row['gender'], 'last_visit_date': 'N/A'} for row in c.fetchall()]
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT p.id, p.first_name, p.last_name, a.appointment_date
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ? AND p.employee_id = ?
        """, (f'{today}%', employee_id))
        patients_today = [{'id': row['id'], 'first_name': row['first_name'], 'last_name': row['last_name'], 'appointment_time': row['appointment_date']} for row in c.fetchall()]
        c.execute("SELECT COUNT(*) FROM patients WHERE employee_id = ?", (employee_id,))
        total_patients = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM patients WHERE medical_history LIKE '%chronic%' AND employee_id = ?", (employee_id,))
        chronic_patients = c.fetchone()[0]
        c.execute("SELECT AVG(length(current_medications) - length(replace(current_medications, ',', '')) + 1) FROM patients WHERE current_medications IS NOT NULL AND employee_id = ?", (employee_id,))
        avg_medications = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM messages WHERE title LIKE '%Doctor%'")
        unread_messages = c.fetchone()[0] or 0
        pending_lab_results = 0
        reminders = [
            {'title': 'Staff Meeting', 'date': datetime.now().strftime('%Y-%m-%d'), 'description': 'Team meeting at 2 PM'},
            {'title': 'Review Lab Results', 'date': datetime.now().strftime('%Y-%m-%d'), 'description': 'Check pending lab results'}
        ]
        health_trends = "Stable, with a slight increase in chronic condition cases this month."
        user_details = get_user_details(conn, session['user_id'])
        logger.debug(f"Rendering dashboard for username={session['user_id']}, role={session['role']}")
        return render_template('doctor/doctorDashboard.html',
                              now=datetime.now(),
                              username=session['user_id'],
                              patients=patients,
                              patients_today=patients_today,
                              total_patients=total_patients,
                              chronic_patients=chronic_patients,
                              avg_medications=avg_medications,
                              health_trends=health_trends,
                              user_details=user_details,
                              pending_lab_results=pending_lab_results,
                              unread_messages=unread_messages,
                              reminders=reminders)
    except Exception as e:
        logger.error(f"Doctor dashboard error: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/nurse_dashboard')
def nurse_dashboard():
    if 'user_id' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    try:
        user_details = get_user_details(conn, session['user_id'])
        if not user_details:
            flash('User not found.', 'error')
            return redirect(url_for('login_page'))
        today = date.today().strftime('%Y-%m-%d')
        c = conn.cursor()
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name || ' ' || p.last_name AS patient_name,
                   a.appointment_date, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ?
            AND a.status = 'scheduled'
        """, (f'{today}%',))
        appointments = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'patient_name': row['patient_name'],
                'appointment_date': row['appointment_date'],
                'reason': row['reason']
            } for row in c.fetchall()
        ]
        pending_vitals = 5
        todays_patients = len(appointments)
        emergency_requests = 2
        new_messages = 3
        shift_start = "08:00 AM"
        shift_end = "04:00 PM"
        shift_hours_left = "5 hours"
        return render_template('nurse/nurseDashboard.html',
                              appointments=appointments,
                              pending_vitals=pending_vitals,
                              todays_patients=todays_patients,
                              patients=appointments,
                              emergency_requests=emergency_requests,
                              new_messages=new_messages,
                              shift_start=shift_start,
                              shift_end=shift_end,
                              shift_hours_left=shift_hours_left,
                              user_details=user_details)
    except Exception as e:
        logger.error(f"Database error in nurse_dashboard: {e}")
        flash('An error occurred while fetching data.', 'error')
        return render_template('nurse/nurseDashboard.html',
                              appointments=[],
                              pending_vitals=0,
                              todays_patients=0,
                              patients=[],
                              emergency_requests=0,
                              new_messages=0,
                              shift_start="N/A",
                              shift_end="N/A",
                              shift_hours_left="N/A",
                              user_details={})
    except sqlite3.Error as e:
        logger.error(f"Database error in nurse_dashboard: {e}")
        flash('An error occurred while fetching data.', 'error')
        return render_template('nurse/nurseDashboard.html',
                              appointments=[],
                              pending_vitals=0,
                              todays_patients=0,
                              patients=[],
                              emergency_requests=0,
                              new_messages=0,
                              shift_start="N/A",
                              shift_end="N/A",
                              shift_hours_left="N/A",
                              user_details={})
    finally:
        conn.close()

@app.route('/reception_dashboard')
def reception_dashboard():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        flash('Please log in as a receptionist.', 'error')
        return redirect(url_for('login_page'))

    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # User details - FIXED: Use 'staff_number' instead of 'employee_id'
        c.execute('SELECT * FROM employees WHERE staff_number = ?', (session['user_id'],))
        user_details = c.fetchone()

        # Today's Appointments - FIXED: Use appointment_date instead of non-existent appointment_time
        # Extract time using strftime for display if needed
        c.execute('''
            SELECT p.id as patient_id, p.first_name, p.last_name, a.appointment_date, 
                   strftime('%H:%M', a.appointment_date) as appointment_time, a.reason, a.status, 
                   CASE WHEN a.reason LIKE '%urgent%' THEN 1 ELSE 0 END AS urgent
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE DATE(a.appointment_date) = DATE('now')
            ORDER BY a.appointment_date
        ''')
        patients_today = c.fetchall()
        logger.debug(f"patients_today sample: {patients_today[:1] if patients_today else 'Empty'}")

        # Waiting Patients - FIXED: Similar change for appointment_time
        c.execute('''
            SELECT p.id as patient_id, p.first_name, p.last_name, a.appointment_date, 
                   strftime('%H:%M', a.appointment_date) as appointment_time, a.reason, a.status,
                   e.first_name || ' ' || e.last_name AS helper_name, e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            WHERE a.status IN ('scheduled', 'waiting', 'helped')
            AND DATE(a.appointment_date) = DATE('now')
            ORDER BY a.appointment_date
        ''')
        waiting_patients = c.fetchall()
        logger.debug(f"waiting_patients sample: {waiting_patients[:1] if waiting_patients else 'Empty'}")

        # Available Staff - FIXED: availability is TEXT 'available', not INTEGER 1
        c.execute('SELECT first_name, last_name FROM employees WHERE role != ? AND availability = ?', ('receptionist', 'available'))
        available_staff = c.fetchall()
        logger.debug(f"available_staff sample: {available_staff[:1] if available_staff else 'Empty'}")

        # Missed Appointments - FIXED: appointment_time
        c.execute('''
            SELECT p.first_name, p.last_name, a.appointment_date, 
                   strftime('%H:%M', a.appointment_date) as appointment_time
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.status = 'missed' AND DATE(a.appointment_date) = DATE('now')
        ''')
        missed_appointments = c.fetchall()
        logger.debug(f"missed_appointments sample: {missed_appointments[:1] if missed_appointments else 'Empty'}")

        # Notifications - FIXED: notifications table has no 'status' column; remove WHERE clause or add if needed
        # Assuming all are unread for now, or adjust schema. For fix, remove status filter
        c.execute('''
            SELECT title, message, datetime(timestamp, 'localtime') AS timestamp
            FROM notifications
            ORDER BY timestamp DESC
            LIMIT 5
        ''')
        notifications = c.fetchall()
        logger.debug(f"notifications sample: {notifications[:1] if notifications else 'Empty'}")

        # FIXED: Compute walkins_waiting as list of waiting patients
        walkins_waiting = [p for p in waiting_patients if p['status'] == 'waiting']

        # FIXED: Set pending_registrations as list (e.g., pending self-booked) to match |length in template
        # For now, query pending self-booked appointments
        c.execute("SELECT id FROM self_booked_appointments WHERE status = 'pending'")
        pending_registrations = c.fetchall()  # list of rows

        # Summary Data (placeholders, adjust queries as needed)
        checked_in_patients = len([p for p in waiting_patients if p['status'] == 'helped'])
        walkins_processed = 0  # Requires specific query
        appointments_rescheduled = len([p for p in waiting_patients if p['status'] == 'rescheduled'])
        payments_processed = 0  # Requires specific query
        # all_visits = 0  # Already int, but template uses |default(0), no |length
        c.execute("SELECT COUNT(*) FROM appointments WHERE DATE(appointment_date) = DATE('now')")
        all_visits = c.fetchone()[0]

        conn.close()

        current_time = datetime.now().strftime('%I:%M %p %Z, %B %d, %Y')

        return render_template('reception/reception.html',
                             user_details=user_details,
                             patients_today=patients_today,
                             waiting_patients=waiting_patients,
                             available_staff=available_staff,
                             missed_appointments=missed_appointments,
                             notifications=notifications,
                             checked_in_patients=checked_in_patients,
                             walkins_processed=walkins_processed,
                             appointments_rescheduled=appointments_rescheduled,
                             payments_processed=payments_processed,
                             pending_registrations=pending_registrations,
                             all_visits=all_visits,
                             walkins_waiting=walkins_waiting,  # FIXED: Added missing variable
                             current_time=current_time)
    except sqlite3.Error as e:
        logger.error(f"Database error in reception_dashboard: {e}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('login_page'))
    except Exception as e:
        logger.error(f"Unexpected error in reception_dashboard: {e}")
        flash('An unexpected error occurred.', 'error')
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
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT patient_id FROM appointments WHERE id = ?", (appointment_id,))
        appointment = c.fetchone()
        if not appointment:
            return jsonify({'success': False, 'category': 'error', 'message': 'Appointment not found.'}), 404
        c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],))
        nurse = c.fetchone()
        if not nurse:
            return jsonify({'success': False, 'category': 'error', 'message': 'Nurse not found.'}), 404
        c.execute("""
            INSERT INTO helped_patients (patient_id, appointment_id, nurse_id, helped_timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (appointment['patient_id'], appointment_id, nurse['id'], datetime.now(), 'Patient helped by nurse'))
        c.execute("UPDATE appointments SET status = 'helped' WHERE id = ?", (appointment_id,))
        c.execute("SELECT first_name, last_name, role FROM employees WHERE id = ?", (nurse['id'],))
        nurse_data = c.fetchone()
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appointment['patient_id'],))
        patient = c.fetchone()
        with queue_lock:
            waiting_patients_queue.put({
                'id': appointment_id,
                'patient_id': appointment['patient_id'],
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'status': 'helped',
                'helper_name': f"{nurse_data['first_name']} {nurse_data['last_name']}",
                'helper_role': nurse_data['role'],
                'timestamp': datetime.now().isoformat()
            })
        conn.commit()
        return jsonify({'success': True, 'category': 'success', 'message': 'Patient marked as helped.'})
    except sqlite3.Error as e:
        logger.error(f"Database error in mark_helped: {e}")
        return jsonify({'success': False, 'category': 'error', 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/stream_waiting_patients')
def stream_waiting_patients():
    if 'username' not in session or session.get('role') not in ['nurse', 'receptionist']:
        return Response(status=403)
    def generate():
        try:
            while True:
                with queue_lock:
                    if not waiting_patients_queue.empty():
                        update = waiting_patients_queue.get()
                        yield f"data: {json.dumps(update)}\n\n"
                time.sleep(1)
        except GeneratorExit:
            logger.debug("SSE connection closed by client")
            return
        except Exception as e:
            logger.error(f"Unexpected error in SSE stream: {e}")
            return
    return Response(generate(), mimetype='text/event-stream')

@csrf.exempt
@app.route('/nurse_assess_patient/<int:patient_id>', methods=['GET', 'POST'])
def nurse_assess_patient(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to assess patients.', 'error')
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    user_details = get_user_details(conn, session['username'])
    if not user_details:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))
    c = conn.cursor()
    c.execute("""
        SELECT id, first_name, last_name 
        FROM patients 
        WHERE id = ?
    """, (patient_id,))
    patient = c.fetchone()
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('nurse_dashboard'))
    patient_data = {
        'id': patient['id'],
        'first_name': patient['first_name'],
        'last_name': patient['last_name']
    }
    if request.method == 'POST':
        vitals = request.form.get('vitals', '').strip()
        notes = request.form.get('notes', '').strip()
        visit_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if not vitals:
            flash('Vitals are required.', 'error')
            return render_template('nurse/nurseAssessPatient.html', patient=patient_data, user_details=user_details)
        c.execute("""
            INSERT INTO visits (patient_id, visit_time, notes)
            VALUES (?, ?, ?)
        """, (patient_id, visit_time, f"Vitals: {vitals}\nNotes: {notes}"))
        conn.commit()
        flash('Patient assessment recorded successfully!', 'success')
        return redirect(url_for('nurse_dashboard'))
    return render_template('nurse/nurseAssessPatient.html', patient=patient_data, user_details=user_details)

@csrf.exempt
@app.route('/nurse_view_medical_history/<int:patient_id>')
def nurse_view_medical_history(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to view medical history.', 'error')
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    try:
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User not found.', 'error')
            return redirect(url_for('login_page'))
        c = conn.cursor()
        c.execute("""
            SELECT id, first_name, last_name, medical_history, allergies, current_medications
            FROM patients 
            WHERE id = ?
        """, (patient_id,))
        patient = c.fetchone()
        if not patient:
            flash('Patient not found.', 'error')
            return redirect(url_for('nurse_dashboard'))
        patient_data = {
            'id': patient['id'],
            'first_name': patient['first_name'],
            'last_name': patient['last_name'],
            'medical_history': patient['medical_history'] or 'No medical history recorded.',
            'allergies': patient['allergies'] or 'No allergies recorded.',
            'current_medications': patient['current_medications'] or 'No medications recorded.'
        }
        c.execute("""
            SELECT medication_name, dosage, instructions, prescribed_date
            FROM prescriptions 
            WHERE patient_id = ?
            ORDER BY prescribed_date DESC
        """, (patient_id,))
        prescriptions = [
            {
                'medication_name': row['medication_name'],
                'dosage': row['dosage'],
                'instructions': row['instructions'] or 'No instructions provided.',
                'prescribed_date': row['prescribed_date']
            } for row in c.fetchall()
        ]
        return render_template('nurse/nurseViewMedicalHistory.html', 
                              patient=patient_data, 
                              prescriptions=prescriptions, 
                              user_details=user_details)
    except sqlite3.Error as e:
        logger.error(f"Database error in nurse_view_medical_history: {e}")
        flash('An error occurred while fetching medical history.', 'error')
        return redirect(url_for('nurse_dashboard'))
    finally:
        conn.close()

@csrf.exempt
@app.route('/nurse_prescribe_medication/<int:patient_id>', methods=['GET', 'POST'])
def nurse_prescribe_medication(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to prescribe medications.', 'error')
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    try:
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User not found.', 'error')
            return redirect(url_for('login_page'))
        c = conn.cursor()
        c.execute("""
            SELECT id, first_name, last_name 
            FROM patients 
            WHERE id = ?
        """, (patient_id,))
        patient = c.fetchone()
        if not patient:
            flash('Patient not found.', 'error')
            return redirect(url_for('nurse_dashboard'))
        patient_data = {
            'id': patient['id'],
            'first_name': patient['first_name'],
            'last_name': patient['last_name']
        }
        if request.method == 'POST':
            medication_name = request.form.get('medication_name', '').strip()
            dosage = request.form.get('dosage', '').strip()
            instructions = request.form.get('instructions', '').strip()
            if not medication_name or not dosage:
                flash('Medication name and dosage are required.', 'error')
                return render_template('nurse/nursePrescribeMedication.html', patient=patient_data, user_details=user_details)
            c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],))
            nurse = c.fetchone()
            if not nurse:
                flash('Nurse not found.', 'error')
                return redirect(url_for('nurse_dashboard'))
            c.execute("""
                INSERT INTO prescriptions (patient_id, nurse_id, medication_name, dosage, instructions)
                VALUES (?, ?, ?, ?, ?)
            """, (patient_id, nurse['id'], medication_name, dosage, instructions))
            c.execute("SELECT current_medications FROM patients WHERE id = ?", (patient_id,))
            current_meds = c.fetchone()['current_medications'] or ''
            updated_meds = f"{current_meds}, {medication_name} ({dosage})" if current_meds else f"{medication_name} ({dosage})"
            c.execute("UPDATE patients SET current_medications = ? WHERE id = ?", (updated_meds, patient_id))
            conn.commit()
            flash('Medication prescribed successfully!', 'success')
            return redirect(url_for('nurse_view_medical_history', patient_id=patient_id))
        return render_template('nurse/nursePrescribeMedication.html', patient=patient_data, user_details=user_details)
    except sqlite3.Error as e:
        logger.error(f"Database error in nurse_prescribe_medication: {e}")
        flash('An error occurred while prescribing medication.', 'error')
        return redirect(url_for('nurse_dashboard'))
    finally:
        conn.close()

@csrf.exempt
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Please log in as an admin to manage users.', 'error')
        return redirect(url_for('login_page'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['user_id'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
        if request.method == 'POST':
            action = request.form.get('action')
            staff_number = request.form.get('staff_number')
            if not staff_number:
                return jsonify({'success': False, 'message': 'Staff number required'}), 400
            
            if action == 'delete':
                c.execute("DELETE FROM employees WHERE staff_number = ? AND role != 'admin'", (staff_number,))
                if c.rowcount > 0:
                    conn.commit()
                    return jsonify({'success': True, 'message': 'User deleted'})
                else:
                    return jsonify({'success': False, 'message': 'Cannot delete admin or user not found'}), 400
            elif action == 'update':
                role = request.form.get('role')
                if role not in ['doctor', 'nurse', 'receptionist', 'manager']:
                    return jsonify({'success': False, 'message': 'Invalid role'}), 400
                c.execute("UPDATE employees SET role = ? WHERE staff_number = ?", (role, staff_number))
                if c.rowcount > 0:
                    conn.commit()
                    return jsonify({'success': True, 'message': 'Role updated'})
                else:
                    return jsonify({'success': False, 'message': 'User not found'}), 400

        # GET: List users
        c.execute("SELECT staff_number, first_name, last_name, email, role FROM employees ORDER BY role, id")
        employees = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/manageUsers.html',
                              employees=employees,
                              user_details=user_details,
                              username=session.get('username', 'Admin'))

    except Exception as e:
        logger.error(f"manage_users error: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500
    finally:
        if conn:
            conn.close()

# === MANAGER ROUTES ===
@app.route('/manager_dashboard')
@login_required
def manager_dashboard():
    if session.get('role') != 'manager':
        flash("Access denied.", "error")
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()

    # === EXISTING CODE (UNCHANGED) ===
    try:
        c.execute("SELECT COUNT(*) FROM employees WHERE active = 1")
        total_staff = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM appointments WHERE DATE(appointment_date) = DATE('now')")
        patients_today = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM inventory WHERE quantity <= min_stock")
        low_stock = c.fetchone()[0]

        c.execute("SELECT COALESCE(SUM(cost), 0) FROM billing WHERE strftime('%Y-%m', billing_date) = strftime('%Y-%m', 'now')")
        revenue_mtd = c.fetchone()[0] or 0.0

        c.execute("""
            SELECT t.*, e.first_name || ' ' || e.last_name as assigned_name
            FROM tasks t LEFT JOIN employees e ON t.assigned_to = e.id
            WHERE t.status = 'pending' ORDER BY t.priority DESC LIMIT 5
        """)
        tasks = [dict(row) for row in c.fetchall()]

    except sqlite3.OperationalError as e:
        if 'no such table' in str(e):
            total_staff = patients_today = low_stock = 0
            revenue_mtd = 0.0
            tasks = []
        else:
            raise

    # === NEW MANAGER FUNCTIONALITY ===
    try:
        from datetime import date
        today = date.today().isoformat()

        # On Duty Today
        c.execute("SELECT COUNT(*) FROM attendance WHERE date = ?", (today,))
        on_duty_today = c.fetchone()[0]

        # Pending Leave
        c.execute("SELECT COUNT(*) FROM leave_requests WHERE status = 'pending'")
        pending_leave = c.fetchone()[0]

        # Training Due
        c.execute("SELECT COUNT(*) FROM certifications WHERE expiry < DATE('now', '+30 days')")
        training_due = c.fetchone()[0]

        # Roster by Role
        c.execute("""
            SELECT e.role, COALESCE(COUNT(a.id), 0) as on_duty,
                   CASE e.role 
                     WHEN 'doctor' THEN 3 
                     WHEN 'nurse' THEN 5 
                     ELSE 2 
                   END as required
            FROM employees e 
            LEFT JOIN attendance a ON e.id = a.staff_id AND a.date = ?
            WHERE e.active = 1
            GROUP BY e.role
        """, (today,))
        roster = [dict(row) for row in c.fetchall()]

        # Leave Requests
        c.execute("""
            SELECT lr.*, e.first_name || ' ' || e.last_name as name, e.role
            FROM leave_requests lr
            JOIN employees e ON lr.staff_id = e.id
            WHERE lr.status = 'pending'
        """)
        leave_requests = [dict(row) for row in c.fetchall()]

        # Performance Reviews
        c.execute("""
            SELECT pr.*, e.first_name || ' ' || e.last_name as name, e.role,
                   CAST(COALESCE(pr.score, 0) AS INTEGER) as score
            FROM performance_reviews pr
            JOIN employees e ON pr.staff_id = e.id
            ORDER BY pr.last_review DESC
        """)
        performance = [dict(row) for row in c.fetchall()]

        # Training Sessions
        c.execute("SELECT * FROM training_sessions WHERE date >= DATE('now') ORDER BY date")
        training = [dict(row) for row in c.fetchall()]

        # Certifications Due
        c.execute("""
            SELECT c.*, e.first_name || ' ' || e.last_name as staff,
                   CAST((julianday(c.expiry) - julianday('now')) AS INTEGER) as days_left
            FROM certifications c
            JOIN employees e ON c.staff_id = e.id
            WHERE c.expiry < DATE('now', '+90 days')
            ORDER BY days_left ASC
        """)
        certifications = [dict(row) for row in c.fetchall()]

        # Compliance (static data for demo)
        compliance = {
            'popia': 98,
            'infection': 100,
            'ppe': 92
        }

    except sqlite3.OperationalError as e:
        if 'no such table' in str(e):
            on_duty_today = pending_leave = training_due = 0
            roster = leave_requests = performance = training = certifications = []
            compliance = {'popia': 0, 'infection': 0, 'ppe': 0}
        else:
            raise

    conn.close()

    return render_template('manager/dashboard.html',
                         stats={
                             'total_staff': total_staff,
                             'patients_today': patients_today,
                             'low_stock': low_stock,
                             'revenue_mtd': revenue_mtd,
                             'on_duty_today': on_duty_today,
                             'pending_leave': pending_leave,
                             'training_due': training_due
                         },
                         tasks=tasks,
                         roster=roster,
                         leave_requests=leave_requests,
                         performance=performance,
                         training=training,
                         certifications=certifications,
                         compliance=compliance)

@app.route('/manager/leave_action', methods=['POST'])
@login_required
@role_required('manager')
def manager_leave_action():
    req_id = request.form.get('id')
    action = request.form.get('action')  # 'approve' or 'reject'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE leave_requests SET status = ? WHERE id = ?", (action, req_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Leave request {action}d'})

@app.route('/inventory')
@login_required
def inventory():
    if session.get('role') != 'manager': return redirect(url_for('login_page'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT *, 
               CASE WHEN avg_daily_use > 0 THEN quantity / avg_daily_use ELSE 999 END as days_left
        FROM inventory ORDER BY days_left
    """)
    inventory = [dict(row) for row in c.fetchall()]
    low_stock_alerts = [i for i in inventory if i['quantity'] <= i['min_stock']]
    conn.close()
    return render_template('manager/inventory.html', inventory=inventory, low_stock_alerts=low_stock_alerts)

@app.route('/reorder_item', methods=['POST'])
@login_required
def reorder_item():
    if session.get('role') != 'manager': return '', 403
    data = request.get_json()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE inventory SET quantity = quantity + ?, last_restocked = DATE('now') WHERE id = ?",
              (data['quantity'], data['id']))
    conn.commit()
    conn.close()
    return '', 204

@app.route('/executive_report')
@login_required
def executive_report():
    if session.get('role') != 'manager': return redirect(url_for('login_page'))
    conn = get_db_connection()
    c = conn.cursor()

    months = []
    revenue = []
    expenses = []
    patients = []
    for i in range(5, -1, -1):
        month = (datetime.now() - timedelta(days=30*i)).strftime('%b %Y')
        months.append(month)
        c.execute("SELECT COALESCE(SUM(cost),0) FROM billing WHERE strftime('%Y-%m', billing_date) = ?", 
                  ((datetime.now() - timedelta(days=30*i)).strftime('%Y-%m'),))
        revenue.append(c.fetchone()[0])
        expenses.append(50000)  # mock
        c.execute("SELECT COUNT(*) FROM appointments WHERE strftime('%Y-%m', appointment_date) = ?", 
                  ((datetime.now() - timedelta(days=30*i)).strftime('%Y-%m'),))
        patients.append(c.fetchone()[0])

    total_rev = sum(revenue)
    total_pat = sum(patients)
    kpi = {
        'revenue': total_rev,
        'expenses': sum(expenses),
        'patients': total_pat,
        'avg_per_patient': total_rev / total_pat if total_pat else 0
    }

    report_data = {'months': months, 'revenue': revenue, 'expenses': expenses, 'patients': patients}
    conn.close()
    return render_template('manager/executive_report.html', report_data=report_data, kpi=kpi)

@app.route('/manage_staff')
@login_required
def manage_staff():
    if session.get('role') != 'manager':
        flash("Access denied.", "error. error")
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, first_name, last_name, role, email, phone
        FROM employees 
        WHERE role NOT IN ('admin', 'manager') AND active = 1
        ORDER BY first_name
    """)
    staff = [dict(row) for row in c.fetchall()]
    conn.close()
    return render_template('manager/manage_staff.html', staff=staff)

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

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, first_name, last_name, role 
        FROM employees 
        WHERE role NOT IN ('admin', 'manager') AND active = 1
    """)
    staff = [dict(row) for row in c.fetchall()]
    conn.close()
    return render_template('manager/staff_schedule.html', staff=staff)

@app.route('/get_schedule')
@login_required
def get_schedule():
    if session.get('role') != 'manager': return jsonify([])
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT s.*, e.first_name || ' ' || e.last_name as staff_name
        FROM staff_schedule s
        JOIN employees e ON s.employee_id = e.id
    """)
    rows = c.fetchall()
    events = []
    for row in rows:
        color_class = {
            'morning': '#28a745',
            'afternoon': '#ffc107',
            'night': '#007bff'
        }.get(row['shift_type'], '#6c757d')
        events.append({
            'id': row['id'],
            'title': f"{row['staff_name']} ({row['shift_type'].capitalize()})",
            'start': row['shift_date'],
            'backgroundColor': color_class,
            'borderColor': color_class,
            'extendedProps': {
                'employee_id': row['employee_id'],
                'shift_type': row['shift_type'],
                'notes': row['notes']
            }
        })
    conn.close()
    return jsonify(events)

@app.route('/save_shift', methods=['POST'])
@login_required
def save_shift():
    if session.get('role') != 'manager':
        return '', 403

    data = request.get_json()
    employee_id = data['employee_id']
    shift_date = data['shift_date']
    shift_type = data['shift_type']
    shift_id = data.get('id')  # None if new

    conn = get_db_connection()
    c = conn.cursor()

    # === CONFLICT CHECK ===
    conflicts = []

    # Define shift time ranges
    shift_times = {
        'morning': ('08:00', '16:00'),
        'afternoon': ('13:00', '21:00'),
        'night': ('20:00', '08:00')
    }

    # Get existing shifts for this employee on this date
    c.execute("""
        SELECT shift_type, id FROM staff_schedule 
        WHERE employee_id = ? AND shift_date = ? AND id != ?
    """, (employee_id, shift_date, shift_id or 0))
    existing = c.fetchall()

    new_start, new_end = shift_times[shift_type]
    is_night_shift = shift_type == 'night'

    for row in existing:
        existing_type = row['shift_type']
        existing_id = row['id']
        start, end = shift_times[existing_type]

        # Handle night shift wrap-around
        if is_night_shift or existing_type == 'night':
            # Convert to minutes from midnight
            def to_minutes(t): 
                h, m = map(int, t.split(':'))
                return h * 60 + m

            new_start_min = to_minutes(new_start)
            new_end_min = to_minutes(new_end) + (1440 if new_end < new_start else 0)
            exist_start_min = to_minutes(start)
            exist_end_min = to_minutes(end) + (1440 if end < start else 0)

            # Check overlap
            if max(new_start_min, exist_start_min) < min(new_end_min, exist_end_min):
                conflicts.append({
                    'type': existing_type,
                    'id': existing_id
                })
        else:
            if new_start < end and new_end > start:
                conflicts.append({
                    'type': existing_type,
                    'id': existing_id
                })

    if conflicts:
        conn.close()
        return jsonify({
            'error': 'Shift conflict!',
            'message': f"This staff member already has a {', '.join([c['type'].capitalize() for c in conflicts])} shift on {shift_date}.",
            'conflicts': conflicts
        }), 400

    # === SAVE SHIFT ===
    if shift_id:
        c.execute("""
            UPDATE staff_schedule 
            SET employee_id=?, shift_date=?, shift_type=?, notes=?
            WHERE id=?
        """, (employee_id, shift_date, shift_type, data.get('notes', ''), shift_id))
    else:
        try:
            c.execute("""
                INSERT INTO staff_schedule (employee_id, shift_date, shift_type, notes)
                VALUES (?, ?, ?, ?)
            """, (employee_id, shift_date, shift_type, data.get('notes', '')))
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Same shift already assigned!'}), 400

    conn.commit()
    conn.close()
    return '', 204

@app.route('/update_shift_date', methods=['POST'])
@login_required
def update_shift_date():
    if session.get('role') != 'manager': return '', 403
    data = request.get_json()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE staff_schedule SET shift_date=? WHERE id=?", (data['shift_date'], data['id']))
    conn.commit()
    conn.close()
    return '', 204

# --- API: Staff List ---
@app.route('/api/staff_list')
def staff_list():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT staff_number, first_name, last_name, role FROM employees WHERE active = 1")
    staff = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(staff)

# --- Manager: Send Message ---
@app.route('/manager_send_message', methods=['POST'])
@login_required
def manager_send_message():
    if session.get('role') != 'manager':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    if not request.form.get('csrf_token') or request.form.get('csrf_token') != session.get('csrf_token'):
        return jsonify({'success': False, 'message': 'Invalid CSRF'}), 403

    msg_type = request.form.get('msg_type', 'announcement')
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
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

            c.execute('''
                INSERT INTO announcements 
                (title, message, author, target_role, pinned, category, timestamp)
                VALUES (?, ?, ?, ?, ?, 'general', datetime('now'))
            ''', (title or 'Announcement', message, session['username'], target_role, pinned))
            
            target_text = 'All Staff' if target_role == 'all' else f"{target_role.capitalize()}s"

        else:  # direct message
            target_user = request.form.get('target_user')
            if not target_user:
                return jsonify({'success': False, 'message': 'Select recipient'}), 400

            c.execute('''
                INSERT INTO direct_messages 
                (sender_id, recipient_id, message, timestamp)
                VALUES (?, ?, ?, datetime('now'))
            ''', (session['user_id'], target_user, message))

            c.execute("SELECT first_name, last_name FROM employees WHERE staff_number = ?", (target_user,))
            user = c.fetchone()
            target_text = f"{user['first_name']} {user['last_name']}" if user else "User"

        conn.commit()

        # Broadcast via SSE
        msg_data = {
            'title': title or 'Direct Message',
            'message': message,
            'author': session['username'],
            'target_role': target_role if msg_type == 'announcement' else None,
            'target_user': target_user if msg_type == 'direct' else None,
            'target_text': target_text,
            'pinned': pinned and msg_type == 'announcement',
            'category': 'general'
        }
        broadcast_message(msg_data)

        return jsonify({'success': True, 'message': 'Sent!'})

    except Exception as e:
        conn.rollback()
        app.logger.error(f"Send message error: {e}")
        return jsonify({'success': False, 'message': 'Failed'}), 500
    finally:
        conn.close()

clients = set()
message_queue = deque()
lock = threading.Lock()

@app.route('/stream_messages')
def stream_messages():
    def event_stream():
        client_id = request.remote_addr
        with lock:
            clients.add(client_id)
        try:
            while True:
                if message_queue:
                    msg = message_queue.popleft()
                    yield f"data: {json.dumps(msg)}\n\n"
        except GeneratorExit:
            with lock:
                clients.discard(client_id)
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

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

@app.route('/change_theme', methods=['POST'])
@login_required
def change_theme():
    theme = request.form.get('theme')
    if theme in ['light', 'dark']:
        session['theme'] = theme
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE employees SET theme = ? WHERE staff_number = ?", (theme, session['staff_number']))
        conn.commit()
        conn.close()
    return '', 204    

@app.route('/doctor_report')
def doctor_report():
    if 'user_id' not in session or session.get('role') != 'doctor':
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
            } for row in c.fetchall()
        ]

        return render_template('doctor/doctor_report.html', reports=reports)
    
    except Exception as e:
        logger.error(f"Error: {e}")
        flash('Database error.', 'error')
        return redirect(url_for('doctor_dashboard'))
    finally:
        conn.close()      

@app.route('/system_settings', methods=['GET', 'POST'])
@login_required
@admin_required
def system_settings():
    # Load settings from file (or DB later)
    settings_file = os.path.join(app.instance_path, 'system_settings.json')
    system_settings = {}
    
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r') as f:
                system_settings = json.load(f)
        except:
            system_settings = {}

    if request.method == 'POST':
        data = request.form.to_dict()
        action = data.get('action')

        if action == 'add_user':
            username = data.get('add_user_username')
            role = data.get('add_user_role')
            if username and role:
                # Add user logic here (e.g., insert into DB)
                flash(f"User '{username}' added as {role}.", "success")
        
        elif action == 'reset_password':
            flash("Password reset requested.", "info")
        
        else:
            # Save all settings
            save_keys = [
                'clinic_name', 'clinic_address', 'clinic_contact', 'clinic_logo',
                'branding_color', 'operating_hours', 'holiday_calendar',
                'password_policy'
            ]
            updated = {k: data.get(k, '') for k in save_keys}
            system_settings.update(updated)

            os.makedirs(app.instance_path, exist_ok=True)
            with open(settings_file, 'w') as f:
                json.dump(system_settings, f, indent=2)
            
            flash("System settings saved successfully.", "success")

        return redirect(url_for('system_settings'))

    # Always pass system_settings to template
    return render_template(
        'admin/systemSettings.html',
        system_settings=system_settings
    )

@app.route('/announcements', methods=['GET', 'POST'])
def announcements():
    if 'username' not in session or session.get('role') != 'admin':
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
            title       = request.form.get('title', '').strip()
            message     = request.form.get('message', '').strip()
            category    = request.form.get('category', '').strip()
            target_role = request.form.get('target_role', 'all').strip()  # New: 'all', 'doctor', 'nurse', 'receptionist'
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
            """, (title, message, category,
                  f"{user_details['first_name']} {user_details['last_name']}",
                  pinned, target_role))
            conn.commit()
            flash('Announcement created successfully!', 'success')
            return redirect(url_for('announcements'))
        
        # GET: List all announcements (admin sees everything)
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
                'target_role': row['target_role'] or 'all'  # Safety
            } for row in c.fetchall()
        ]
        return render_template('admin/announcement.html',
                              announcements=announcements,
                              user_details=user_details,
                              username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error in announcements: {e}")
        flash('An error occurred while managing announcements.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/toggle_availability', methods=['POST'])
def toggle_availability():
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        new_status = request.form.get('status')
        if new_status not in ['available', 'unavailable']:
            return jsonify({'success': False, 'message': 'Invalid status.'}), 400
        c.execute("UPDATE employees SET availability = ? WHERE staff_number = ?", (new_status, session['username']))
        if c.rowcount > 0:
            c.execute("SELECT first_name, last_name, role FROM employees WHERE staff_number = ?", (session['username'],))
            user = c.fetchone()
            notification = f"{user['first_name']} {user['last_name']} ({user['role']}) is now {new_status}."
            c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                     (f"{user['role'].capitalize()} Status Update", notification, 'System'))
            conn.commit()
            return jsonify({'success': True, 'message': f'Availability set to {new_status}.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
    except sqlite3.Error as e:
        logger.error(f"Database error in toggle_availability: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()

@csrf.exempt
@app.route('/emergency_request', methods=['POST'])
def emergency_request():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please log in to submit an emergency request.'}), 403
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        patient_id = request.form.get('patient_id')
        reason = request.form.get('reason', '').strip()
        if not patient_id or not reason:
            return jsonify({'success': False, 'message': 'Patient ID and reason are required.'}), 400
        c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
        if not c.fetchone():
            return jsonify({'success': False, 'message': 'Patient not found.'}), 404
        c.execute("""
            INSERT INTO emergency_requests (patient_id, reason, request_time, status)
            VALUES (?, ?, ?, ?)
        """, (patient_id, reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'pending'))
        conn.commit()
        return jsonify({'success': True, 'message': 'Emergency request submitted successfully!'})
    except sqlite3.Error as e:
        logger.error(f"Database error in emergency_request: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/view_emergency_requests')
def view_emergency_requests():
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        flash('Please log in as a doctor or nurse to view emergency requests.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
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
    if 'staff_number' not in session:
        flash("Please log in to continue.", "error")
        return redirect(url_for('login_page'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # === ADDED: password to SELECT ===
    cursor.execute("""
        SELECT id, staff_number, first_name, last_name, email, role, 
               availability, specialization, phone, profile_image, password 
        FROM employees WHERE staff_number = ?
    """, (session['staff_number'],))
    employee = cursor.fetchone()
    if not employee:
        conn.close()
        flash("Employee not found.", "error")
        return redirect(url_for('login_page'))

    employee_dict = dict(employee)
    employee_dict['specialization'] = employee_dict['specialization'] or ''

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        availability = request.form.get('availability')
        specialization = request.form.get('specialization') if employee_dict['role'] == 'doctor' else None
        profile_picture = request.files.get('profile_picture')

        if not all([first_name, last_name, email]):
            flash("Name and email are required.", "error")
            conn.close()
            return redirect(url_for('edit_profile'))

        try:
            update_fields = []
            update_values = []

            update_fields.append("first_name = ?")
            update_values.append(first_name)
            update_fields.append("last_name = ?")
            update_values.append(last_name)
            update_fields.append("email = ?")
            update_values.append(email)
            update_fields.append("phone = ?")
            update_values.append(phone or None)
            update_fields.append("availability = ?")
            update_values.append(availability)

            if employee_dict['role'] == 'doctor':
                update_fields.append("specialization = ?")
                update_values.append(specialization)

            profile_image_path = employee_dict['profile_image']
            if profile_picture and profile_picture.filename:
                filename = secure_filename(f"profile_{employee_dict['id']}_{profile_picture.filename}")
                upload_path = os.path.join(app.static_folder, 'uploads', filename)
                os.makedirs(os.path.dirname(upload_path), exist_ok=True)
                profile_picture.save(upload_path)
                profile_image_path = f"uploads/{filename}"
                update_fields.append("profile_image = ?")
                update_values.append(profile_image_path)

            # === PASSWORD CHANGE LOGIC ===
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if current_password or new_password or confirm_password:
                if not all([current_password, new_password, confirm_password]):
                    flash("All password fields are required.", "error")
                    conn.close()
                    return redirect(url_for('edit_profile'))

                if not bcrypt.check_password_hash(employee_dict['password'], current_password):
                    flash("Current password is incorrect.", "error")
                    conn.close()
                    return redirect(url_for('edit_profile'))

                if new_password != confirm_password:
                    flash("New passwords do not match.", "error")
                    conn.close()
                    return redirect(url_for('edit_profile'))

                if len(new_password) < 6:
                    flash("New password must be at least 6 characters.", "error")
                    conn.close()
                    return redirect(url_for('edit_profile'))

                hashed_new = bcrypt.generate_password_hash(new_password).decode('utf-8')
                update_fields.append("password = ?")
                update_values.append(hashed_new)

            update_query = f"UPDATE employees SET {', '.join(update_fields)} WHERE id = ?"
            update_values.append(employee_dict['id'])
            cursor.execute(update_query, update_values)
            conn.commit()

            # UPDATE SESSION
            session['name'] = f"{first_name} {last_name}"
            session['profile_image'] = profile_image_path

            flash("Profile updated successfully!", "success")
            return redirect(url_for('edit_profile'))

        except Exception as e:
            conn.rollback()
            app.logger.error(f"Profile update error: {e}")
            flash("Update failed. Try again.", "error")
            return redirect(url_for('edit_profile'))
        finally:
            conn.close()

    conn.close()
    return render_template('edit_profile.html', employee=employee_dict)         

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
def logout():
    if 'username' in session:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT first_name, last_name, role FROM employees WHERE staff_number = ?", (session['username'],))
            user = c.fetchone()
            if user and user['role'] in ['doctor', 'nurse']:
                c.execute("UPDATE employees SET availability = 'unavailable' WHERE staff_number = ?", (session['username'],))
                notification = f"{user['first_name']} {user['last_name']} ({user['role']}) is now unavailable."
                c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                         (f"{user['role'].capitalize()} Unavailable", notification, 'System'))
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error during logout: {e}")
        finally:
            conn.close()
        session.pop('username', None)
        session.pop('role', None)
        session.pop('theme', None)
        session.pop('login_time', None)
        flash('You have been logged out.', 'success')
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
    upgrade_database()
    print("Database ready.")
    
with app.app_context():
    try:
        db.create_all()  # Only creates missing tables
        print("Tables checked/created.")
    except Exception as e:
        print(f"DB Error: {e}")     

# Run the Flask app
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
        print("Database tables ready.")
    app.run(debug=True, threaded=True)
    
if __name__ != '__main__':
    # Azure uses gunicorn → no need to run app
    pass
else:
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

 #Add Scheduler + Auto-Admin   
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # AUTO-CREATE FIRST ADMIN
        if not Employee.query.filter_by(role='admin').first():
            admin = Employee(
                staff_number="STAFF001",
                first_name="Admin",
                last_name="User",
                email="admin@clinic.local",
                password=bcrypt.generate_password_hash("admin123").decode('utf-8'),
                role="admin",
                active=True
            )
            db.session.add(admin)
            db.session.commit()
            print("First admin created: STAFF001 / admin123")

    from scheduler import start_scheduler
    start_scheduler()

    app.run(host='0.0.0.0', port=5000, debug=False)