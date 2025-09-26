from flask import Flask, request, redirect, url_for, render_template, session, flash, Response, jsonify
import sqlite3
import os
from datetime import datetime, date, timedelta
from flask.logging import create_logger
import logging
from werkzeug.utils import secure_filename
import secrets
import random
import re
from queue import Queue
from threading import Lock
import time
from flask_caching import Cache
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import traceback
import jinja2
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, DateTimeField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
#from app import appointment_homepage, admin_dashboard, doctor_dashboard, nurse_dashboard, reception_dashboard


# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

# Load environment variables from .env file
load_dotenv()
secret_key = os.urandom(24)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=7)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Static file configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

bcrypt = Bcrypt(app)

# In-memory queues for notifications
appointment_queue = Queue()
waiting_patients_queue = Queue()
queue_lock = Lock()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    try:
        conn = sqlite3.connect('clinicinfo.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_user_details(conn, user_id):
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM employees WHERE staff_number = ?", (user_id,))
        user = c.fetchone()
        return dict(user) if user else {}
    except sqlite3.Error as e:
        logger.error(f"Error fetching user details: {e}")
        return {}

# Custom error handler for template not found
@app.errorhandler(jinja2.exceptions.TemplateNotFound)
def template_not_found(e):
    logger.error(f"Template not found: {e.name}")
    flash(f"Template {e.name} is missing. Please contact the administrator.", 'error')
    return render_template('homepage/error.html'), 404

def init_db():
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        
        c.execute('PRAGMA foreign_keys = ON;')
        
        c.execute('''CREATE TABLE IF NOT EXISTS employees
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      first_name TEXT NOT NULL,
                      last_name TEXT NOT NULL,
                      email TEXT NOT NULL,
                      password TEXT NOT NULL,
                      phone TEXT,
                      address TEXT,
                      role TEXT NOT NULL,
                      hire_date TEXT,
                      availability TEXT DEFAULT 'available',
                      profile_image TEXT DEFAULT 'default.jpg',
                      staff_number TEXT UNIQUE NOT NULL DEFAULT 'TEMPSTAFF')''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS patients
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      first_name TEXT NOT NULL,
                      last_name TEXT NOT NULL,
                      date_of_birth TEXT,
                      gender TEXT,
                      address TEXT,
                      phone TEXT,
                      email TEXT,
                      emergency_contact_name TEXT,
                      emergency_contact_phone TEXT,
                      medical_history TEXT,
                      allergies TEXT,
                      current_medications TEXT,
                      employee_id INTEGER,
                      clinic TEXT DEFAULT 'Clinic A',
                      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                      status TEXT DEFAULT 'active',  -- Added status column
                      FOREIGN KEY (employee_id) REFERENCES employees(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS appointments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      appointment_date TEXT NOT NULL,
                      status TEXT DEFAULT 'scheduled',
                      reason TEXT,
                      created_by_role TEXT DEFAULT 'receptionist',
                      helper_id INTEGER,  -- Ensure this is INTEGER to match employees.id
                      FOREIGN KEY (patient_id) REFERENCES patients(id),
                      FOREIGN KEY (helper_id) REFERENCES employees(id))''')

        c.execute("CREATE INDEX IF NOT EXISTS idx_appointments_date_status ON appointments(appointment_date, status)")
        
        c.execute('''CREATE TABLE IF NOT EXISTS prescriptions
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      nurse_id INTEGER,
                      medication_name TEXT NOT NULL,
                      dosage TEXT NOT NULL,
                      instructions TEXT,
                      prescribed_date TEXT NOT NULL,
                      FOREIGN KEY (patient_id) REFERENCES patients(id),
                      FOREIGN KEY (nurse_id) REFERENCES employees(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS visits
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      visit_time TEXT NOT NULL,
                      notes TEXT,
                      FOREIGN KEY (patient_id) REFERENCES patients(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS emergency_requests
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      reason TEXT NOT NULL,
                      request_time TEXT DEFAULT CURRENT_TIMESTAMP,
                      status TEXT DEFAULT 'pending',
                      FOREIGN KEY (patient_id) REFERENCES patients(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      content TEXT NOT NULL,
                      date TEXT DEFAULT CURRENT_TIMESTAMP,
                      sender TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS self_booked_appointments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        patient_name TEXT NOT NULL,
                        patient_phone TEXT,
                        patient_email TEXT,
                        appointment_date TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        reason TEXT,
                        booked_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS system_settings
                     (id INTEGER PRIMARY KEY,
                      backup_frequency TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS preferences
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      staff_number TEXT UNIQUE,
                      theme TEXT DEFAULT 'dark')''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS helped_patients
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      appointment_id INTEGER NOT NULL,
                      nurse_id INTEGER NOT NULL,
                      helped_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      notes TEXT,
                      FOREIGN KEY (patient_id) REFERENCES patients(id),
                      FOREIGN KEY (appointment_id) REFERENCES appointments(id),
                      FOREIGN KEY (nurse_id) REFERENCES employees(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS announcements
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      message TEXT NOT NULL,
                      category TEXT NOT NULL,
                      author TEXT NOT NULL,
                      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                      pinned BOOLEAN DEFAULT FALSE)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS payments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      amount REAL NOT NULL,
                      payment_date TEXT DEFAULT CURRENT_TIMESTAMP,
                      status TEXT DEFAULT 'pending',
                      FOREIGN KEY (patient_id) REFERENCES patients(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS notifications
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      message TEXT NOT NULL,
                      timestamp TEXT DEFAULT CURRENT_TIMESTAMP)''')
        
        try:
            c.execute('''
                ALTER TABLE appointments
                ADD COLUMN helper_id INTEGER
                REFERENCES employees(id)
            ''')
            logger.info("Added helper_id column to appointments table")
        except sqlite3.OperationalError as e:
            if 'duplicate column name' not in str(e).lower():
                logger.error(f"Error adding helper_id column: {e}")
        
        c.execute("INSERT OR REPLACE INTO system_settings (id, backup_frequency) VALUES (1, 'weekly')")
        
        c.execute("INSERT OR IGNORE INTO employees (first_name, last_name, password, email, role, staff_number) VALUES (?, ?, ?, ?, ?, ?)",
                  ('Admin', 'User', bcrypt.generate_password_hash('admin123').decode('utf-8'), 'admin@clinic.com', 'admin', 'STAFF001'))
        
        conn.commit()
        logger.info("Database initialized successfully")
        return True
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        flash(f"Failed to initialize database: {str(e)}", 'error')
        return False
    finally:
        if conn:
            conn.close()

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
    username = StringField('Username (Staff Number or Email)', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
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

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        remember = form.remember.data
        if not all([username, password]):
            flash('Both username and password are required.', 'error')
            return render_template('homepage/login_page.html', form=form)

        conn = None
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM employees WHERE staff_number = ? OR email = ?", (username, username))
            user = c.fetchone()

            if user and bcrypt.check_password_hash(user['password'], password):
                session['user_id'] = user['staff_number']  # Changed to user_id
                session['role'] = user['role']
                session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S SAST')
                session.permanent = remember  # Set session permanence based on checkbox
                print(f"Session after login: {session}")  # Debug print
                if user['role'] == 'receptionist':
                    return redirect(url_for('reception_dashboard'))
                elif user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'doctor':
                    return redirect(url_for('doctor_dashboard'))
                elif user['role'] == 'nurse':
                    return redirect(url_for('nurse_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
        finally:
            if conn:
                conn.close()
    return render_template('homepage/login_page.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        first_name = form.first_name.data.strip()
        last_name = form.last_name.data.strip()
        password = form.password.data.strip()
        email = form.email.data.strip()
        role = form.role.data.strip()
        terms = form.terms.data

        conn = None
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection failed.', 'error')
                logger.error("Failed to connect to database")
                return render_template('homepage/registerPage.html', form=form)
            c = conn.cursor()

            c.execute("SELECT id FROM employees WHERE email = ?", (email,))
            if c.fetchone():
                flash('Email address is already registered.', 'error')
                logger.error(f"Email already registered: {email}")
                return render_template('homepage/registerPage.html', form=form)

            c.execute("SELECT MAX(id) AS max_id FROM employees")
            max_id = c.fetchone()['max_id'] or 0
            staff_number = f"STAFF{str(max_id + 1).zfill(3)}"
            logger.debug(f"Generated staff_number: {staff_number}")

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            c.execute("""
                INSERT INTO employees (staff_number, first_name, last_name, email, password, role, availability, profile_image)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (staff_number, first_name, last_name, email, hashed_password, role, 'available', 'default.jpg'))
            conn.commit()
            logger.info(f"User registered successfully: {staff_number}")

            flash(f'Registration successful! Your staff number is: {staff_number}', 'success')
            return redirect(url_for('login_page'))
        except sqlite3.Error as e:
            logger.error(f"Database error in register: {e}")
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('homepage/registerPage.html', form=form)
        finally:
            if conn:
                conn.close()
    return render_template('homepage/registerPage.html', form=form)

@app.route('/edit_employee', methods=['GET', 'POST'])
def edit_employee():
    if 'user_id' not in session:  # Changed from 'username' to 'user_id'
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        if request.method == 'POST':
            email = request.form.get('email')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone = request.form.get('phone')
            address = request.form.get('address')
            if not all([email, first_name, last_name]):
                flash('Email, first name, and last name are required', 'error')
                return redirect(url_for('edit_employee'))
            profile_image = None
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename = f"{session['user_id']}_{filename}"  # Changed from session['username'] to session['user_id']
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    profile_image = filename
            update_query = """
                UPDATE employees 
                SET email = ?, first_name = ?, last_name = ?, phone = ?, address = ?
            """
            params = (email, first_name, last_name, phone, address)
            if profile_image:
                update_query += ", profile_image = ?"
                params += (profile_image,)
            update_query += " WHERE staff_number = ?"
            params += (session['user_id'],)  # Changed from session['username'] to session['user_id']
            c.execute(update_query, params)
            conn.commit()
            flash('Profile updated successfully!', 'success')
            role = session.get('role')
            return redirect(url_for(f'{role}_dashboard'))
        else:
            c.execute("SELECT staff_number, email, first_name, last_name, phone, address, profile_image FROM employees WHERE staff_number = ?", (session['user_id'],))
            user = c.fetchone()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('login_page'))
            user_details = {
                'staff_number': user['staff_number'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'phone': user['phone'],
                'address': user['address'],
                'profile_image': user['profile_image'] if user['profile_image'] else 'default.jpg'
            }
            return render_template('edit_employee.html', user_details=user_details, username=session['user_id'])  # Changed username to user_id
    except Exception as e:
        logger.error(f"Error in edit_employee: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/search_patient', methods=['GET', 'POST'])
def search_patient():
    if 'user_id' not in session or session.get('role') != 'receptionist':
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
            if action == 'book_appointment':
                patient_id = request.form.get('patient_id')
                appointment_time = request.form.get('appointment_time')
                reason = request.form.get('reason', '').strip()
                if not patient_id or not appointment_time:
                    return jsonify({'success': False, 'message': 'Patient and appointment time are required.', 'category': 'error'})
                c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
                if not c.fetchone():
                    return jsonify({'success': False, 'message': 'Selected patient does not exist.', 'category': 'error'})
                c.execute("SELECT id FROM appointments WHERE patient_id = ? AND status IN ('scheduled', 'waiting')", (patient_id,))
                if c.fetchone():
                    return jsonify({'success': False, 'message': 'Patient already has a scheduled or waiting appointment. Cancel it first.', 'category': 'error'})
                c.execute("INSERT INTO appointments (patient_id, appointment_date, status, reason) VALUES (?, ?, ?, ?)",
                          (patient_id, appointment_time, 'scheduled', reason))
                appointment_id = c.lastrowid
                c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (patient_id,))
                patient = c.fetchone()
                with queue_lock:
                    appointment_queue.put({
                        'id': appointment_id,
                        'patient_id': patient_id,
                        'first_name': row['first_name'],
                        'last_name': row['last_name'],
                        'appointment_date': appointment_time,
                        'reason': reason,
                        'status': 'scheduled'
                    })
                conn.commit()
                return jsonify({
                    'success': True,
                    'message': 'Appointment booked successfully!',
                    'category': 'success',
                    'appointment': {
                        'id': appointment_id,
                        'appointment_date': appointment_time,
                        'reason': reason
                    }
                })
            
            search_term = request.form.get('search_term', '').strip()
            if not search_term:
                flash('Please enter a search term.', 'error')
                return render_template('reception/search_patient.html', patients=[], username=session['user_id'], user_details=user_details)  # Changed username to user_id
            c.execute("""
                SELECT id, first_name, last_name FROM patients
                WHERE id LIKE ? OR LOWER(first_name) LIKE LOWER(?) OR LOWER(last_name) LIKE LOWER(?)
            """, (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
            results = c.fetchall()
            patients = []
            for row in results:
                c.execute("SELECT id, appointment_date, reason FROM appointments WHERE patient_id = ? AND status = 'scheduled'", (row['id'],))
                appointment = c.fetchone()
                patients.append({
                    'id': row['id'],
                    'first_name': row['first_name'],
                    'last_name': row['last_name'],
                    'appointment': {
                        'id': appointment['id'],
                        'appointment_date': appointment['appointment_date'],
                        'reason': appointment['reason']
                    } if appointment else None
                })
            if not patients:
                flash('No patients found matching your search.', 'info')
            return render_template('reception/search_patient.html', patients=patients, username=session['user_id'], user_details=user_details)  # Changed username to user_id
        
        return render_template('reception/search_patient.html', patients=[], username=session['user_id'], user_details=user_details)  # Changed username to user_id
    
    except Exception as e:
        logger.error(f"Error in search_patient: {str(e)}")
        if request.method == 'POST' and request.form.get('action') == 'book_appointment':
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}', 'category': 'error'})
        flash(f'An error occurred: {str(e)}', 'error')
        return render_template('reception/search_patient.html', patients=[], username=session.get('user_id', ''), user_details={})  # Changed username to user_id
    finally:
        if conn:
            conn.close()

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
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    
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

@app.route('/add_walkin', methods=['POST'])
def add_walkin():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        patient_id = request.form.get('patient_id')
        reason = request.form.get('reason', '').strip()
        if not patient_id:
            flash('Patient ID is required.', 'error')
            return redirect(url_for('check_in_page'))
        c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
        if not c.fetchone():
            flash('Selected patient does not exist.', 'error')
            return redirect(url_for('check_in_page'))
        appointment_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO appointments (patient_id, appointment_date, status, reason) VALUES (?, ?, ?, ?)",
                  (patient_id, appointment_time, 'waiting', reason))
        appointment_id = c.lastrowid
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (patient_id,))
        patient = c.fetchone()
        with queue_lock:
            appointment_queue.put({
                'id': appointment_id,
                'patient_id': patient_id,
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'appointment_date': appointment_time,
                'reason': reason,
                'status': 'waiting'
            })
            waiting_patients_queue.put({
                'id': appointment_id,
                'patient_id': patient_id,
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'appointment_date': appointment_time,
                'reason': reason,
                'status': 'waiting'
            })
        conn.commit()
        flash('Walk-in patient added successfully!', 'success')
        return redirect(url_for('check_in_page'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('check_in_page'))
    finally:
        if conn:
            conn.close()

@app.route('/check_in_page', methods=['GET'])
def check_in_page():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return jsonify({'error': 'Unauthorized'}), 403 if request.headers.get('Accept') == 'application/json' else redirect(url_for('login_page'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['user_id'])
        if not user_details:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'User details not found'}), 404
            else:
                flash('User details not found.', 'error')
                return redirect(url_for('login_page'))
        
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason,
                   e.first_name || ' ' || e.last_name AS helper_name, e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            WHERE a.appointment_date LIKE ? AND a.status = 'scheduled'
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        scheduled_appointments = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'appointment_date': row['appointment_date'],
                'status': row['status'],
                'reason': row['reason'] or 'Not specified',
                'helper_name': row['helper_name'],
                'helper_role': row['helper_role']
            } for row in c.fetchall()
        ]
        
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason,
                   e.first_name || ' ' || e.last_name AS helper_name, e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            WHERE a.appointment_date LIKE ? AND a.status = 'waiting'
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        waitlist = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'appointment_date': row['appointment_date'],
                'status': row['status'],
                'reason': row['reason'] or 'Not specified',
                'helper_name': row['helper_name'],
                'helper_role': row['helper_role']
            } for row in c.fetchall()
        ]
        
        c.execute("SELECT staff_number, first_name, last_name, role FROM employees WHERE availability = 'available'")
        available_staff = [
            {
                'staff_number': row['staff_number'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'role': row['role']
            } for row in c.fetchall()
        ]
        
        c.execute("""
            SELECT hp.id, hp.patient_id, p.first_name || ' ' || p.last_name AS patient_name,
                   hp.appointment_id, a.appointment_date, hp.nurse_id,
                   e.first_name || ' ' || e.last_name AS nurse_name,
                   hp.helped_timestamp, hp.notes, a.reason
            FROM helped_patients hp
            JOIN patients p ON hp.patient_id = p.id
            JOIN appointments a ON hp.appointment_id = a.id
            JOIN employees e ON hp.nurse_id = e.id
            ORDER BY hp.helped_timestamp DESC
        """)
        helped_patients = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'patient_name': row['patient_name'],
                'appointment_id': row['appointment_id'],
                'appointment_date': row['appointment_date'],
                'nurse_id': row['nurse_id'],
                'nurse_name': row['nurse_name'],
                'helped_timestamp': row['helped_timestamp'],
                'notes': row['notes'],
                'reason': row['reason'] or 'Not specified'
            } for row in c.fetchall()
        ]
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'scheduled_appointments': scheduled_appointments,
                'waitlist': waitlist,
                'available_staff': available_staff,
                'user_details': user_details,
                'helped_patients': helped_patients
            })
        else:
            return render_template('reception/checkInDesk.html',
                                  user_details=user_details,
                                  scheduled_appointments=scheduled_appointments,
                                  waitlist=waitlist,
                                  available_staff=available_staff,
                                  helped_patients=helped_patients)
    except sqlite3.Error as e:
        logger.error(f"Database error in check_in_page: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Database error occurred'}), 500
        else:
            flash('Database error occurred.', 'error')
            return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

#patient self-service appointment booking
@app.route('/patient_book_appointment', methods=['GET', 'POST'])
def patient_book_appointment():
    form = AppointmentForm()
    doctors = []
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT staff_number, first_name, last_name FROM employees WHERE role = 'doctor'")
        doctors = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Error fetching doctors: {e}")
    finally:
        if conn:
            conn.close()
    if form.validate_on_submit():
        patient_name = form.patient_name.data.strip()
        patient_phone = form.patient_phone.data.strip()
        patient_email = form.patient_email.data.strip()
        appointment_date = form.date.data.strftime('%Y-%m-%d %H:%M:%S')
        reason = form.reason.data.strip()
        doctor = request.form.get('doctor')
        conn = None
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection failed.', 'error')
                return render_template('homepage/patient_book_appointment.html', form=form, doctors=doctors)
            c = conn.cursor()
            c.execute("""
                INSERT INTO self_booked_appointments (patient_name, patient_phone, patient_email, appointment_date, reason, status, doctor_staff_number)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (patient_name, patient_phone, patient_email, appointment_date, reason, 'pending', doctor))
            appointment_id = c.lastrowid
            conn.commit()
            with queue_lock:
                appointment_queue.put({
                    'id': appointment_id,
                    'patient_name': patient_name,
                    'appointment_date': appointment_date,
                    'reason': reason,
                    'status': 'pending',
                    'type': 'self_booked',
                    'doctor': doctor
                })
            flash('Your appointment request has been submitted successfully! Please wait for confirmation.', 'success')
            return redirect(url_for('default_page'))
        except sqlite3.Error as e:
            logger.error(f"Database error in patient_book_appointment: {e}")
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('homepage/patient_book_appointment.html', form=form, doctors=doctors)
        finally:
            if conn:
                conn.close()
    return render_template('homepage/patient_book_appointment.html', form=form, doctors=doctors)

@app.route('/manage_appointments', methods=['GET', 'POST'])
def manage_appointments():
    if 'user_id' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        action = request.form.get('action')
        if action == 'book_appointment':
            patient_id = request.form.get('patient_id')
            appointment_time = request.form.get('appointment_time')
            reason = request.form.get('reason')
            helper_id = request.form.get('helper_id')
            conn = sqlite3.connect('clinicinfo.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO appointments (patient_id, appointment_date, reason, helper_id, status, created_at)
                VALUES (?, ?, ?, ?, 'scheduled', ?)
            """, (patient_id, appointment_time, reason or None, helper_id or None, datetime.now()))
            conn.commit()
            appointment_id = cursor.lastrowid
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Appointment booked successfully.',
                'appointment': {
                    'id': appointment_id,
                    'patient_first_name': request.form.get('patient_first_name', 'Unknown'),
                    'patient_last_name': request.form.get('patient_last_name', 'Patient'),
                    'appointment_date': appointment_time,
                    'reason': reason,
                    'helper_name': helper_id and 'Assigned' or 'Unassigned',
                    'helper_role': helper_id and 'Staff' or None,
                    'status': 'scheduled'
                }
            })
        elif action == 'convert_self_booked':
            self_booked_id = request.form.get('self_booked_id')
            patient_id = request.form.get('patient_id')
            appointment_time = request.form.get('appointment_time')
            reason = request.form.get('reason')
            helper_id = request.form.get('helper_id')
            conn = sqlite3.connect('clinicinfo.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE self_booked_appointments SET status = 'converted' WHERE id = ?", (self_booked_id,))
            cursor.execute("""
                INSERT INTO appointments (patient_id, appointment_date, reason, helper_id, status, created_at)
                VALUES (?, ?, ?, ?, 'scheduled', ?)
            """, (patient_id, appointment_time, reason or None, helper_id or None, datetime.now()))
            conn.commit()
            appointment_id = cursor.lastrowid
            conn.close()
            return jsonify({
                'success': True,
                'message': 'Self-booked appointment converted successfully.',
                'appointment': {
                    'id': appointment_id,
                    'patient_first_name': 'Converted',
                    'patient_last_name': 'Patient',
                    'appointment_date': appointment_time,
                    'reason': reason,
                    'helper_name': helper_id and 'Assigned' or 'Unassigned',
                    'helper_role': helper_id and 'Staff' or None,
                    'status': 'scheduled'
                }
            })
        elif action == 'cancel_appointment':
            appointment_id = request.form.get('appointment_id')
            conn = sqlite3.connect('clinicinfo.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", (appointment_id,))
            conn.commit()
            conn.close()
            return jsonify({
                'success': cursor.rowcount > 0,
                'message': cursor.rowcount > 0 and 'Appointment cancelled.' or 'Appointment not found.'
            })
        return jsonify({'success': False, 'message': 'Invalid action.'})
    conn = sqlite3.connect('clinicinfo.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments")
    appointments = cursor.fetchall()
    conn.close()
    return render_template('manage_appointments.html', appointments=appointments)

@app.route('/stream_appointments')
def stream_appointments():
    def event_stream():
        conn = sqlite3.connect('clinicinfo.db')
        cursor = conn.cursor()
        while True:
            cursor.execute("SELECT id, patient_id, appointment_date, reason, status FROM appointments WHERE status IN ('scheduled', 'waiting') ORDER BY appointment_date ASC LIMIT 1")
            appt = cursor.fetchone()
            if appt:
                yield f"data: {json.dumps({'id': appt[0], 'patient_id': appt[1], 'appointment_date': appt[2], 'reason': appt[3], 'status': appt[4]})}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/helped_patients_report')
def helped_patients_report():
    if 'user_id' not in session or session.get('role') != 'receptionist':  # Changed from 'username' to 'user_id'
        return redirect(url_for('login_page'))
    
    conn = sqlite3.connect('clinicinfo.db')  # Changed from 'clinic.db' to 'clinicinfo.db'
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM helped_patients")
    helped_patients = cursor.fetchall()
    conn.close()
    return render_template('helped_patients_report.html', helped_patients=helped_patients)

@app.route('/doctor_overview')
def doctor_overview():
    if 'username' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        c.execute("SELECT COUNT(*) FROM patients")
        total_patients = c.fetchone()[0]
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT p.first_name, p.last_name, a.id, a.appointment_date, a.status, a.reason
            FROM appointments a 
            JOIN patients p ON a.patient_id = p.id 
            WHERE a.appointment_date LIKE ?
        """, (f'{today}%',))
        patients_today = [
            {
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'id': row['id'],
                'appointment_time': datetime.strptime(row['appointment_date'], "%Y-%m-%d %H:%M:%S") if row['appointment_date'] else None,
                'appointment_reason': row['reason'],
                'urgent_flag': random.choice([True, False])
            } for row in c.fetchall()
        ]
        urgent_flags = sum(1 for patient in patients_today if patient.get('urgent_flag'))
        c.execute("SELECT COUNT(*) FROM messages WHERE title LIKE '%Doctor%'")
        unread_messages = c.fetchone()[0]
        health_alerts = [
            {
                'patient_name': f"{p['first_name']} {p['last_name']}",
                'alert_type': "High Blood Pressure",
                'message': "BP reading above safe limits.",
                'date_reported': datetime.now()
            } for p in patients_today if p['urgent_flag']
        ]
        recent_messages = [
            {
                'sender_profile': user_details.get('profile_image', 'default.jpg'),
                'sender_name': "Admin User",
                'timestamp': datetime.now(),
                'preview': "Don't forget the staff meeting at 10am."
            }
        ]
        return render_template('doctor/doctorOverview.html',
                              user_details=user_details,
                              now=datetime.now(),
                              total_patients=total_patients,
                              patients_today=patients_today,
                              urgent_flags=urgent_flags,
                              unread_messages=unread_messages,
                              health_alerts=health_alerts,
                              recent_messages=recent_messages)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

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

@app.route('/adminDashboard.html')
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
    logger.debug(f"Accessing doctor_dashboard: session={session}")
    if 'user_id' not in session or session.get('role') not in ['doctor', 'nurse']:
        logger.error(f"Unauthorized access: username={session.get('user_id')}, role={session.get('role')}")
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        employee_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['user_id'],)).fetchone()[0]
        logger.debug(f"Doctor dashboard for employee_id={employee_id}")
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
        flash('Please log in as a receptionist to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['user_id'])
        if not user_details:
            flash('User not found.', 'error')
            return redirect(url_for('login_page'))
        
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT a.id, p.first_name, p.last_name, a.appointment_date
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ?
        """, (f'{today}%',))
        patients_today = [
            {
                'id': row['id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'appointment_time': row['appointment_date']
            } for row in c.fetchall()
        ]
        logger.debug(f"patients_today sample: {patients_today if patients_today else 'Empty'}")
        
        c.execute("SELECT COUNT(*) FROM visits WHERE visit_time LIKE ?", (f'{today}%',))
        all_visits = c.fetchone()[0] or 0
        logger.debug(f"all_visits: {all_visits}")
        
        c.execute("SELECT id, title, message, timestamp FROM announcements ORDER BY pinned DESC, timestamp DESC")
        notes = [
            {
                'id': row['id'],
                'title': row['title'],
                'message': row['message'],
                'timestamp': datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%b %d, %H:%M') if row['timestamp'] else 'N/A'
            } for row in c.fetchall()
        ]
        
        return render_template('reception/reception.html',
                              user_details=user_details,
                              username=session['user_id'],
                              patients_today=patients_today,
                              all_visits=all_visits,
                              notes=notes)
    except Exception as e:
        logger.error(f"Unexpected error in reception_dashboard: {str(e)}. Traceback: {traceback.format_exc()}")
        flash('An error occurred while fetching dashboard data.', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/view_announcements')
def view_announcements():
    if 'user_id' not in session or session.get('role') not in ['doctor', 'nurse', 'receptionist']:
        flash('Please log in as a doctor, nurse, or receptionist to view announcements.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['user_id'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        c.execute("SELECT id, title, message, category, author, timestamp, pinned FROM announcements ORDER BY pinned DESC, timestamp DESC")
        announcements = [
            {
                'id': row['id'],
                'title': row['title'],
                'message': row['message'],
                'category': row['category'],
                'author': row['author'],
                'timestamp': datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%b %d, %H:%M') if row['timestamp'] else 'N/A'
            } for row in c.fetchall()
        ]
        return render_template('view_announcements.html',
                              announcements=announcements,
                              user_details=user_details,
                              username=session['user_id'])
    except sqlite3.Error as e:
        logger.error(f"Database error in view_announcements: {e}. Traceback: {traceback.format_exc()}")
        flash('An error occurred while fetching announcements.', 'error')
        return redirect(url_for('doctor_dashboard' if session.get('role') == 'doctor' else 'nurse_dashboard'))
    finally:
        if conn:
            conn.close()

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

@app.route('/nurse_overview')
def nurse_overview():
    if 'username' not in session or session.get('role') != 'nurse':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
        # Fetch assigned patients
        c.execute("""
            SELECT id, first_name, last_name 
            FROM patients 
            WHERE employee_id = (SELECT id FROM employees WHERE staff_number = ?)
        """, (session['username'],))
        assigned_patients = [
            {
                'id': row['id'],
                'first_name': row['first_name'],
                'last_name': row['last_name']
            } for row in c.fetchall()
        ]
        total_patients_today = len(assigned_patients)
        
        # Fetch visits for today
        today_date = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT COUNT(DISTINCT patient_id) 
            FROM visits 
            WHERE visit_time LIKE ? 
            AND patient_id IN (
                SELECT id 
                FROM patients 
                WHERE employee_id = (SELECT id FROM employees WHERE staff_number = ?)
            )
        """, (f'{today_date}%', session['username']))
        visits_today = c.fetchone()[0] or 0
        
        # Fetch pending appointments
        c.execute("""
            SELECT a.id, p.first_name, p.last_name, a.appointment_date, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ? 
            AND a.status = 'scheduled'
            AND p.employee_id = (SELECT id FROM employees WHERE staff_number = ?)
        """, (f'{today_date}%', session['username']))
        appointments = [
            {
                'id': row['id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'appointment_date': row['appointment_date'],
                'reason': row['reason'] or 'Not specified'
            } for row in c.fetchall()
        ]
        
        # Sample metrics
        pending_vitals = visits_today
        emergency_requests = 0  # Placeholder, adjust based on emergency_requests table if needed
        new_messages = 0  # Placeholder, adjust based on messages table if needed
        
        return render_template('nurse/nurseOverview.html',
                              user_details=user_details,
                              assigned_patients=assigned_patients,
                              total_patients_today=total_patients_today,
                              visits_today=visits_today,
                              appointments=appointments,
                              pending_vitals=pending_vitals,
                              emergency_requests=emergency_requests,
                              new_messages=new_messages)
    except Exception as e:
        logger.error(f"Error in nurse_overview: {e}")
        flash('An error occurred while fetching data.', 'error')
        return redirect(url_for('nurse_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Please log in as an admin to manage users.', 'error')
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
            action = request.form.get('action')
            staff_number = request.form.get('staff_number')
            if not staff_number:
                flash('Staff number is required.', 'error')
                return redirect(url_for('manage_users'))
            
            if action == 'delete':
                c.execute("DELETE FROM employees WHERE staff_number = ? AND role != 'admin'", (staff_number,))
                if c.rowcount > 0:
                    conn.commit()
                    flash('User deleted successfully!', 'success')
                else:
                    flash('User not found or cannot delete admin.', 'error')
            elif action == 'update':
                role = request.form.get('role')
                if role not in ['doctor', 'nurse', 'receptionist']:
                    flash('Invalid role selected.', 'error')
                    return redirect(url_for('manage_users'))
                c.execute("UPDATE employees SET role = ? WHERE staff_number = ?", (role, staff_number))
                if c.rowcount > 0:
                    conn.commit()
                    flash('User role updated successfully!', 'success')
                else:
                    flash('User not found.', 'error')
            return redirect(url_for('manage_users'))
        
        # Fetch all employees
        c.execute("SELECT staff_number, first_name, last_name, email, role FROM employees ORDER BY id")
        employees = [
            {
                'staff_number': row['staff_number'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'email': row['email'],
                'role': row['role']
            } for row in c.fetchall()
        ]
        return render_template('admin/manageUsers.html',
                              employees=employees,
                              user_details=user_details,
                              username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error in manage_users: {e}")
        flash('An error occurred while managing users.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/system_settings', methods=['GET', 'POST'])
def system_settings():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Please log in as an admin to manage system settings.', 'error')
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
            backup_frequency = request.form.get('backup_frequency')
            if backup_frequency not in ['daily', 'weekly', 'monthly']:
                flash('Invalid backup frequency selected.', 'error')
                return redirect(url_for('system_settings'))
            c.execute("UPDATE system_settings SET backup_frequency = ? WHERE id = 1", (backup_frequency,))
            conn.commit()
            flash('System settings updated successfully!', 'success')
            return redirect(url_for('system_settings'))
        
        c.execute("SELECT backup_frequency FROM system_settings WHERE id = 1")
        settings = c.fetchone()
        backup_frequency = settings['backup_frequency'] if settings else 'weekly'
        return render_template('admin/systemSettings.html',
                              backup_frequency=backup_frequency,
                              user_details=user_details,
                              username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error in system_settings: {e}")
        flash('An error occurred while updating settings.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

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
            title = request.form.get('title', '').strip()
            message = request.form.get('message', '').strip()
            category = request.form.get('category', '').strip()
            pinned = request.form.get('pinned') == 'on'
            if not title or not message or not category:
                flash('All fields are required.', 'error')
                return redirect(url_for('announcements'))
            c.execute("""
                INSERT INTO announcements (title, message, category, author, pinned)
                VALUES (?, ?, ?, ?, ?)
            """, (title, message, category, f"{user_details['first_name']} {user_details['last_name']}", pinned))
            conn.commit()
            flash('Announcement created successfully!', 'success')
            return redirect(url_for('announcements'))
        
        c.execute("SELECT id, title, message, category, author, timestamp, pinned FROM announcements ORDER BY pinned DESC, timestamp DESC")
        announcements = [
            {
                'id': row['id'],
                'title': row['title'],
                'message': row['message'],
                'category': row['category'],
                'author': row['author'],
                'timestamp': row['timestamp'],
                'pinned': row['pinned']
            } for row in c.fetchall()
        ]
        return render_template('admin/announcements.html',
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

@app.route('/delete_announcement/<int:announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized access.'}), 403
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,))
        if c.rowcount > 0:
            conn.commit()
            return jsonify({'success': True, 'message': 'Announcement deleted successfully!'})
        else:
            return jsonify({'success': False, 'message': 'Announcement not found.'}), 404
    except sqlite3.Error as e:
        logger.error(f"Database error in delete_announcement: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
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

# Run the Flask app
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    if init_db():
        print("Starting Flask application")
        app.run(debug=True)
    else:
        print("Failed to initialize database. Application not started.")