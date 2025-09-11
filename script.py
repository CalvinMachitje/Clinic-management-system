from flask import Flask, request, redirect, url_for, render_template, session, flash, Response, jsonify, json
import sqlite3
import hashlib
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
import requests
from dotenv import load_dotenv

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app.secret_key = secrets.token_hex(32)
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Load environment variables
load_dotenv()
NHS_API_KEY = os.environ.get('8211d59d664b4d3c9d539d663d8ee12b')
NEWS_API_KEY = os.environ.get('72214206cfad4127b56da4904509603f')

# Newsapi configuration
NEWS_API_URL = "https://newsapi.org/v2/top-headlines"

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
        logger.error(f"Database connection failed: {e}")
        return None

def get_user_details(conn, staff_number):
    c = conn.cursor()
    c.execute("SELECT staff_number, first_name, last_name, profile_image FROM employees WHERE staff_number = ?", (staff_number,))
    user = c.fetchone()
    return {
        'staff_number': user[0],
        'first_name': user[1],
        'last_name': user[2],
        'profile_image': user[3] if user[3] else 'default.jpg'
    } if user else None

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
                      FOREIGN KEY (employee_id) REFERENCES employees(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS appointments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      patient_id INTEGER NOT NULL,
                      appointment_date TEXT NOT NULL,
                      status TEXT DEFAULT 'scheduled',
                      reason TEXT,
                      created_by_role TEXT DEFAULT 'receptionist',
                      helper_id INTEGER,
                      FOREIGN KEY (patient_id) REFERENCES patients(id),
                      FOREIGN KEY (helper_id) REFERENCES employees(id))''')
        
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
        
        # Create announcements table
        c.execute('''CREATE TABLE IF NOT EXISTS announcements
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      message TEXT NOT NULL,
                      category TEXT NOT NULL,
                      author TEXT NOT NULL,
                      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                      pinned BOOLEAN DEFAULT FALSE)''')
        
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
                  ('Admin', 'User', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin@clinic.com', 'admin', 'STAFF001'))
        
        conn.commit()
        logger.info("Database initialized or migrated successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization or migration error: {e}")
        flash(f"Failed to initialize database: {str(e)}", 'error')
        return False
    finally:
        if conn:
            conn.close()
    return True

@app.route('/')
def default_page():
    if 'username' in session:
        role = session.get('role', 'user')
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'nurse':
            return redirect(url_for('nurse_dashboard'))
        elif role == 'receptionist':
            return redirect(url_for('reception_dashboard'))
    
    # Fetch news articles using News API
    news_params = {
        'apiKey': NEWS_API_KEY,
        'category': 'health',
        'country': 'za',
        'pageSize': 5
    }
    try:
        news_response = requests.get(NEWS_API_URL, params=news_params)
        news_response.raise_for_status()
        news_data = news_response.json()
        articles = news_data.get('articles', [])
    except requests.RequestException as e:
        logger.error(f"Error fetching news: {e}")
        articles = []
        flash('Failed to fetch news articles. Please try again later.', 'error')

    # Fetch OpenFDA drug safety events
    openfda_events = []
    openfda_api_key = os.environ.get('OPENFDA_API_KEY')
    if openfda_api_key:
        openfda_params = {
            'api_key': openfda_api_key,
            'search': 'receivedate:[20250101 TO 20250911]',  # Adjust date range as needed
            'limit': 5
        }
        try:
            openfda_response = requests.get('https://api.fda.gov/drug/event.json', params=openfda_params)
            openfda_response.raise_for_status()
            openfda_data = openfda_response.json()
            openfda_events = openfda_data.get('results', [])
        except requests.RequestException as e:
            logger.error(f"Error fetching OpenFDA events: {e}")
            flash('Failed to fetch drug safety reports. Please try again later.', 'error')

    return render_template('homepage/defaultPage.html', articles=articles, openfda_events=openfda_events)


@app.route('/appointments')
def appointment_homepage():
    if 'username' not in session or session.get('role') != 'receptionist':
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
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason,
                   e.first_name || ' ' || e.last_name AS helper_name, e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            ORDER BY a.appointment_date
        """)
        appointments = [
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
        
        c.execute("SELECT id, first_name, last_name, role FROM employees WHERE availability = 'available'")
        available_staff = [
            {
                'id': row['id'],
                'name': f"{row['first_name']} {row['last_name']}",
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
        
        return render_template('reception/manageAppointments.html',
                              appointments=appointments,
                              available_staff=available_staff,
                              helped_patients=helped_patients,
                              user_details=user_details,
                              username=session['username'])
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('reception_dashboard'))
    finally:
        if conn:
            conn.close()

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = None
    try:
        if request.method == 'POST':
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            email = request.form.get('email', '').strip()
            confirm_email = request.form.get('confirm_email', '').strip()
            role = request.form.get('role', '').strip()
            if not all([first_name, last_name, password, confirm_password, email, confirm_email, role]):
                flash('All required fields are required', 'error')
                return render_template('registerPage.html')
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('registerPage.html')
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', password):
                flash('Password must be at least 8 characters with 1 uppercase, 1 lowercase, and 1 number.', 'error')
                return render_template('registerPage.html')
            if email != confirm_email:
                flash('Emails do not match.', 'error')
                return render_template('registerPage.html')
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                flash('Please enter a valid email address.', 'error')
                return render_template('registerPage.html')
            staff_number = str(random.randint(10000000, 99999999))
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            conn = get_db_connection()
            c = conn.cursor()
            while True:
                c.execute("SELECT staff_number FROM employees WHERE staff_number = ?", (staff_number,))
                if not c.fetchone():
                    break
                staff_number = str(random.randint(10000000, 99999999))
            c.execute("INSERT INTO employees (first_name, last_name, staff_number, password, email, role) VALUES (?, ?, ?, ?, ?, ?)",
                      (first_name, last_name, staff_number, hashed_password, email, role))
            c.execute("INSERT INTO preferences (staff_number, theme) VALUES (?, ?)", (staff_number, 'dark'))
            conn.commit()
            flash(f'Registration successful! Staff Number: {staff_number}', 'success')
            return redirect(url_for('login_page'))
        return render_template('registerPage.html')
    except sqlite3.IntegrityError:
        flash('Email already exists. Please choose another.', 'error')
        return render_template('registerPage.html')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return render_template('registerPage.html')
    finally:
        if conn:
            conn.close()

@app.route('/login_page')
def login_page():
    return render_template('login_page.html')

@app.route('/login', methods=['POST'])
def login():
    conn = None
    try:
        staff_number = request.form.get('username')
        password = request.form.get('password')
        if not all([staff_number, password]):
            flash('All fields are required', 'error')
            return render_template('login_page.html')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM employees WHERE staff_number = ? AND password = ?", (staff_number, hashed_password))
        user = c.fetchone()
        if user:
            session['username'] = staff_number
            session['role'] = user['role']
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S SAST')
            if user['role'] in ['doctor', 'nurse']:
                c.execute("UPDATE employees SET availability = 'available' WHERE staff_number = ?", (staff_number,))
                notification = f"{user['first_name']} {user['last_name']} ({user['role']}) is now available."
                c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                         (f"{user['role'].capitalize()} Available", notification, 'System'))
                conn.commit()
            c.execute("SELECT theme FROM preferences WHERE staff_number = ?", (staff_number,))
            theme = c.fetchone()
            session['theme'] = theme['theme'] if theme else 'dark'
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user['role'] == 'nurse':
                return redirect(url_for('nurse_dashboard'))
            elif user['role'] == 'receptionist':
                return redirect(url_for('reception_dashboard'))
        else:
            flash('Invalid staff number or password.', 'error')
            return render_template('login_page.html')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return render_template('login_page.html')
    finally:
        if conn:
            conn.close()

@app.route('/edit_employee', methods=['GET', 'POST'])
def edit_employee():
    if 'username' not in session:
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
                    filename = f"{session['username']}_{filename}"
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
            params += (session['username'],)
            c.execute(update_query, params)
            conn.commit()
            flash('Profile updated successfully!', 'success')
            role = session.get('role')
            return redirect(url_for(f'{role}_dashboard'))
        else:
            c.execute("SELECT staff_number, email, first_name, last_name, phone, address, profile_image FROM employees WHERE staff_number = ?", (session['username'],))
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
            return render_template('edit_employee.html', user_details=user_details, username=session['username'])
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/search_patient', methods=['GET', 'POST'])
def search_patient():
    if 'username' not in session or session.get('role') != 'receptionist':
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
                        'first_name': patient['first_name'],
                        'last_name': patient['last_name'],
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
                return render_template('search_patient.html', patients=[], username=session['username'], user_details=user_details)
            
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
            return render_template('search_patient.html', patients=patients, username=session['username'], user_details=user_details)
        
        return render_template('search_patient.html', patients=[], username=session['username'], user_details=user_details)
    
    except Exception as e:
        logger.error(f"Error in search_patient: {str(e)}")
        if request.method == 'POST' and request.form.get('action') == 'book_appointment':
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}', 'category': 'error'})
        flash(f'An error occurred: {str(e)}', 'error')
        if request.method == 'GET':
            return render_template('search_patient.html', patients=[], username=session.get('username', ''), user_details={})
        return redirect(url_for('reception_dashboard'))
    
    finally:
        if conn:
            conn.close()

@app.route('/cancel_appointment', methods=['POST'])
def cancel_appointment():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        if not appointment_id:
            flash('Appointment ID is required.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ? AND status = 'scheduled'", (appointment_id,))
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
                    'appointment_date': appt['appointment_date'],
                    'reason': appt['reason'],
                    'status': 'cancelled'
                })
            conn.commit()
            flash('Appointment cancelled successfully!', 'success')
        else:
            flash('Appointment not found or already cancelled.', 'error')
        return redirect(url_for('appointment_homepage'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('appointment_homepage'))
    finally:
        if conn:
            conn.close()

@app.route('/reschedule_appointment', methods=['POST'])
def reschedule_appointment():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        new_time = request.form.get('new_time')
        if not all([appointment_id, new_time]):
            flash('Appointment ID and new time are required.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("SELECT patient_id, reason FROM appointments WHERE id = ? AND status = 'scheduled'", (appointment_id,))
        appt = c.fetchone()
        if not appt:
            flash('Appointment not found or not scheduled.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("UPDATE appointments SET appointment_date = ?, status = 'rescheduled' WHERE id = ?", (new_time, appointment_id))
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
                'status': 'rescheduled'
            })
        conn.commit()
        flash('Appointment rescheduled successfully!', 'success')
        return redirect(url_for('appointment_homepage'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('appointment_homepage'))
    finally:
        if conn:
            conn.close()

@app.route('/add_walkin', methods=['POST'])
def add_walkin():
    if 'username' not in session or session.get('role') != 'receptionist':
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
    if 'username' not in session or session.get('role') != 'receptionist':
        return jsonify({'error': 'Unauthorized'}), 403 if request.headers.get('Accept') == 'application/json' else redirect(url_for('login_page'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
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

@app.route('/reception_dashboard')
def reception_dashboard():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        month = datetime.now().strftime('%Y-%m')
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.status, a.appointment_date, a.reason,
                   e.first_name || ' ' || e.last_name AS helper_name, e.role AS helper_role
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN employees e ON a.helper_id = e.id
            WHERE a.appointment_date LIKE ?
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        patients_today = [
            {
                'id': row['id'],
                'patient_id': row['patient_id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'status': row['status'],
                'appointment_date': row['appointment_date'],
                'reason': row['reason'] or 'Not specified',
                'helper_name': row['helper_name'],
                'helper_role': row['helper_role']
            } for row in c.fetchall()
        ]
        waiting_patients = [
            p for p in patients_today if p['status'] in ['scheduled', 'waiting']
        ]
        c.execute("SELECT id FROM visits WHERE visit_time LIKE ?", (f"{month}%",))
        all_visits = c.fetchall()
        c.execute("SELECT staff_number, first_name, last_name FROM employees WHERE availability = 'available'")
        available_staff = c.fetchall()
        c.execute("SELECT id FROM appointments WHERE status = 'waiting' AND appointment_date LIKE ?", (f'{today}%',))
        walkins_waiting = c.fetchall()
        c.execute("SELECT id FROM appointments WHERE status = 'missed' AND appointment_date LIKE ?", (f'{today}%',))
        missed_appointments = c.fetchall()
        c.execute("SELECT id FROM patients WHERE medical_history IS NULL")
        pending_registrations = c.fetchall()
        checked_in_patients = len([a for a in patients_today if a['status'] == 'checked_in'])
        walkins_processed = len([a for a in patients_today if a['status'] == 'helped'])
        appointments_rescheduled = len([a for a in patients_today if a['status'] == 'rescheduled'])
        payments_processed = len(all_visits)
        c.execute("SELECT title, content, date FROM messages ORDER BY date DESC LIMIT 5")
        notifications = [
            {'title': row['title'], 'message': row['content'], 'timestamp': datetime.strptime(row['date'], '%Y-%m-%d %H:%M:%S')}
            for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        return render_template('reception/reception.html',
                              patients_today=patients_today,
                              waiting_patients=waiting_patients,
                              all_visits=all_visits,
                              available_staff=available_staff,
                              walkins_waiting=walkins_waiting,
                              missed_appointments=missed_appointments,
                              pending_registrations=pending_registrations,
                              checked_in_patients=checked_in_patients,
                              walkins_processed=walkins_processed,
                              appointments_rescheduled=appointments_rescheduled,
                              payments_processed=payments_processed,
                              notifications=notifications,
                              user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        patient_id = request.form.get('patient_id')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason', '').strip()
        if not patient_id or not appointment_time:
            flash('Patient and appointment time are required.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
        if not c.fetchone():
            flash('Selected patient does not exist.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("SELECT id FROM appointments WHERE patient_id = ? AND status IN ('scheduled', 'waiting')", (patient_id,))
        if c.fetchone():
            flash('Patient already has a scheduled or waiting appointment. Cancel it first.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("INSERT INTO appointments (patient_id, appointment_date, status, reason) VALUES (?, ?, ?, ?)",
                  (patient_id, appointment_time, 'scheduled', reason))
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
                'status': 'scheduled'
            })
        conn.commit()
        flash('Appointment booked successfully!', 'success')
        return redirect(url_for('appointment_homepage'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('appointment_homepage'))
    finally:
        if conn:
            conn.close()

@app.route('/stream_appointments')
def stream_appointments():
    if 'username' not in session or session.get('role') != 'receptionist':
        return Response(status=403)
    
    def generate():
        try:
            while True:
                with queue_lock:
                    if not appointment_queue.empty():
                        appointment = appointment_queue.get()
                        appointment_safe = appointment.copy()
                        if 'appointment_date' in appointment_safe:
                            appointment_safe['appointment_date'] = str(appointment_safe['appointment_date'])
                        yield f"data: {json.dumps(appointment_safe)}\n\n"
                time.sleep(1)
        except GeneratorExit:
            logger.debug("SSE connection closed by client")
            return
        except Exception as e:
            logger.error(f"Unexpected error in SSE stream: {e}")
            return
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/adminDashboard.html')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
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
        user_details = get_user_details(conn, session['username'])
        return render_template('admin/adminDashboard.html',
                              username=session['username'],
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
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        logger.error(f"Unauthorized access: username={session.get('username')}, role={session.get('role')}")
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        employee_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],)).fetchone()[0]
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
        user_details = get_user_details(conn, session['username'])
        logger.debug(f"Rendering dashboard for username={session['username']}, role={session['role']}")
        return render_template('doctor/doctorDashboard.html',
                              now=datetime.now(),
                              username=session['username'],
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

@app.route('/nurse_dashboard')
def nurse_dashboard():
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to access the dashboard.', 'error')
        return redirect(url_for('login_page'))
    conn = get_db_connection()
    try:
        user_details = get_user_details(conn, session['username'])
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

@app.route('/helped_patients_report')
def helped_patients_report():
    if 'username' not in session or session.get('role') != 'receptionist':
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Unauthorized'}), 403
        else:
            flash('Please log in as a receptionist to access reports.', 'error')
            return redirect(url_for('login_page'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details and request.headers.get('Accept') != 'application/json':
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
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
            return jsonify({'helped_patients': helped_patients})
        else:
            return render_template('reception/helped_patients_report.html', 
                                 helped_patients=helped_patients, 
                                 user_details=user_details or {})
    
    except sqlite3.Error as e:
        logger.error(f"Database error in helped_patients_report: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Database error occurred'}), 500
        else:
            flash('An error occurred while generating the report.', 'error')
            return render_template('reception/helped_patients_report.html', 
                                 helped_patients=[], 
                                 user_details=user_details or {})
    finally:
        if conn:
            conn.close()

@app.route('/nurse_assess_patient/<int:patient_id>', methods=['GET', 'POST'])
def nurse_assess_patient(patient_id):
    if 'username' not in session or session.get('role') != 'nurse':
        flash('Please log in as a nurse to assess patients.', 'error')
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
    except sqlite3.Error as e:
        logger.error(f"Database error in nurse_assess_patient: {e}")
        flash('An error occurred while processing the assessment.', 'error')
        return redirect(url_for('nurse_dashboard'))
    finally:
        conn.close()

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
        c.execute("""
            SELECT id, first_name, last_name 
            FROM patients 
            WHERE employee_id = (SELECT id FROM employees WHERE staff_number = ?)
        """, (session['username'],))
        assigned_patients = c.fetchall()
        total_patients_today = len(assigned_patients)
        today_date = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT COUNT(DISTINCT patient_id) FROM visits 
            WHERE visit_time >= ? 
            AND patient_id IN (SELECT id FROM patients WHERE employee_id = (SELECT id FROM employees WHERE staff_number = ?))
        """, (today_date, session['username']))
        vitals_recorded_today = c.fetchone()[0] or 0
        c.execute("""
            SELECT COUNT(*) FROM visits
            WHERE visit_time >= ? AND notes LIKE '%medicat%'
        """, (today_date,))
        meds_administered = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM emergency_requests WHERE status='pending'")
        alerts_pending = c.fetchone()[0] or 0
        shift_start = datetime.now().replace(hour=7, minute=0)
        shift_end = datetime.now().replace(hour=19, minute=0)
        shift_hours_left = max(0, int((shift_end - datetime.now()).total_seconds() // 3600))
        active_patients = []
        for pat in assigned_patients:
            c.execute("SELECT visit_time FROM visits WHERE patient_id = ? ORDER BY visit_time DESC LIMIT 1", (pat['id'],))
            last_vitals_row = c.fetchone()
            last_vitals_time = last_vitals_row['visit_time'] if last_vitals_row else "N/A"
            condition_status = "Stable"
            bed_number = random.randint(1, 20)
            active_patients.append({                'id': pat['id'],
                'first_name': pat['first_name'],
                'last_name': pat['last_name'],
                'last_vitals_time': last_vitals_time,
                'condition_status': condition_status,
                'bed_number': bed_number
            })
        return render_template('nurse/nurseOverview.html',
                              user_details=user_details,
                              total_patients_today=total_patients_today,
                              vitals_recorded_today=vitals_recorded_today,
                              meds_administered=meds_administered,
                              alerts_pending=alerts_pending,
                              shift_start=shift_start.strftime('%I:%M %p'),
                              shift_end=shift_end.strftime('%I:%M %p'),
                              shift_hours_left=shift_hours_left,
                              active_patients=active_patients)
    except sqlite3.Error as e:
        logger.error(f"Database error in nurse_overview: {e}")
        flash('An error occurred while fetching nurse overview data.', 'error')
        return redirect(url_for('nurse_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/assign_staff', methods=['POST'])
def assign_staff():
    if 'username' not in session or session.get('role') != 'receptionist':
        return jsonify({'success': False, 'message': 'Unauthorized access.', 'category': 'error'}), 403
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        staff_id = request.form.get('staff_id')  # Changed from staff_number to staff_id to match template
        if not appointment_id or not staff_id:
            return jsonify({'success': False, 'message': 'Appointment ID and staff ID are required.', 'category': 'error'}), 400
        c.execute("SELECT id FROM employees WHERE id = ? AND availability = 'available'", (staff_id,))
        staff = c.fetchone()
        if not staff:
            return jsonify({'success': False, 'message': 'Selected staff not found or unavailable.', 'category': 'error'}), 404
        c.execute("SELECT patient_id, appointment_date, reason FROM appointments WHERE id = ?", (appointment_id,))
        appt = c.fetchone()
        if not appt:
            return jsonify({'success': False, 'message': 'Appointment not found.', 'category': 'error'}), 404
        c.execute("UPDATE appointments SET helper_id = ? WHERE id = ?", (staff_id, appointment_id))
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appt['patient_id'],))
        patient = c.fetchone()
        c.execute("SELECT first_name, last_name, role FROM employees WHERE id = ?", (staff_id,))
        staff_data = c.fetchone()
        with queue_lock:
            appointment_queue.put({
                'id': appointment_id,
                'patient_id': appt['patient_id'],
                'first_name': patient['first_name'],
                'last_name': patient['last_name'],
                'appointment_date': appt['appointment_date'],
                'reason': appt['reason'] or 'Not specified',
                'status': 'assigned',
                'helper_name': f"{staff_data['first_name']} {staff_data['last_name']}",
                'helper_role': staff_data['role']
            })
        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Staff assigned successfully!',
            'category': 'success',
            'appointment': {
                'id': appointment_id,
                'helper_name': f"{staff_data['first_name']} {staff_data['last_name']}",
                'helper_role': staff_data['role']
            }
        })
    except sqlite3.Error as e:
        logger.error(f"Database error in assign_staff: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.', 'category': 'error'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/reception_announcements', methods=['GET', 'POST'])
def reception_announcements():
    if 'username' not in session or session.get('role') != 'receptionist':
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Unauthorized'}), 403
        else:
            return redirect(url_for('login_page'))
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'error': 'User details not found'}), 404
            else:
                flash('User details not found. Please log in again.', 'error')
                return redirect(url_for('login_page'))
        
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            message = request.form.get('message', '').strip()
            category = request.form.get('category', '').strip()
            pinned = request.form.get('pinned') == 'on'
            if not title or not message or not category:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Title, message, and category are required.', 'category': 'error'}), 400
                else:
                    flash('Title, message, and category are required.', 'error')
            else:
                author = f"{user_details['first_name']} {user_details['last_name']}"
                c.execute("""
                    INSERT INTO announcements (title, message, category, author, pinned)
                    VALUES (?, ?, ?, ?, ?)
                """, (title, message, category, author, pinned))
                conn.commit()
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': True, 'message': 'Announcement created successfully!', 'category': 'success'})
                else:
                    flash('Announcement created successfully!', 'success')
        
        c.execute("""
            SELECT id, title, message, category, author, timestamp, pinned
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
                'pinned': row['pinned']
            } for row in c.fetchall()
        ]
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'announcements': announcements, 'user_details': user_details})
        else:
            return render_template('reception/announcement.html',
                                  announcements=announcements,
                                  user_details=user_details,
                                  username=session['username'])
    
    except sqlite3.Error as e:
        logger.error(f"Database error in reception_announcements: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Database error occurred'}), 500
        else:
            flash('An error occurred while fetching announcements.', 'error')
            return render_template('reception/announcement.html',
                                  announcements=[],
                                  user_details=user_details or {},
                                  username=session.get('username', ''))
    finally:
        if conn:
            conn.close()

@app.route('/add_patient', methods=['POST'])
def add_patient():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        date_of_birth = request.form.get('date_of_birth', '').strip()
        gender = request.form.get('gender', '').strip()
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        emergency_contact_name = request.form.get('emergency_contact_name', '').strip()
        emergency_contact_phone = request.form.get('emergency_contact_phone', '').strip()
        medical_history = request.form.get('medical_history', '').strip()
        allergies = request.form.get('allergies', '').strip()
        current_medications = request.form.get('current_medications', '').strip()
        if not all([first_name, last_name, date_of_birth]):
            flash('First name, last name, and date of birth are required.', 'error')
            return redirect(url_for('reception_dashboard'))
        c.execute("""
            INSERT INTO patients (first_name, last_name, date_of_birth, gender, address, phone, email,
                                 emergency_contact_name, emergency_contact_phone, medical_history, allergies, current_medications)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (first_name, last_name, date_of_birth, gender, address, phone, email,
              emergency_contact_name, emergency_contact_phone, medical_history, allergies, current_medications))
        conn.commit()
        flash('Patient added successfully!', 'success')
        return redirect(url_for('reception_dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in add_patient: {e}")
        flash('An error occurred while adding the patient.', 'error')
        return redirect(url_for('reception_dashboard'))
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

@app.route('/change_theme', methods=['POST'])
def change_theme():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    theme = request.form.get('theme', 'dark')
    if theme not in ['dark', 'light']:
        theme = 'dark'
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE preferences SET theme = ? WHERE staff_number = ?", (theme, session['username']))
        if c.rowcount == 0:
            c.execute("INSERT INTO preferences (staff_number, theme) VALUES (?, ?)", (session['username'], theme))
        conn.commit()
        session['theme'] = theme
        return jsonify({'success': True, 'theme': theme})
    except sqlite3.Error as e:
        logger.error(f"Database error in change_theme: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        conn.close()

@app.route('/search_nhs', methods=['POST'])
def search_nhs():
    query = request.form.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query is required'}), 400
    try:
        url = f"https://api.nhs.uk/conditions/{query}/"
        headers = {'subscription-key': NHS_API_KEY}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return jsonify({'results': data})
    except requests.RequestException as e:
        logger.error(f"Error fetching NHS data: {e}")
        return jsonify({'error': 'Failed to fetch NHS data'}), 500

@app.route('/emergency_request', methods=['POST'])
def emergency_request():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    patient_id = request.form.get('patient_id')
    reason = request.form.get('reason', '').strip()
    if not patient_id or not reason:
        return jsonify({'success': False, 'message': 'Patient ID and reason are required.'}), 400
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM patients WHERE id = ?", (patient_id,))
        if not c.fetchone():
            return jsonify({'success': False, 'message': 'Patient not found.'}), 404
        c.execute("INSERT INTO emergency_requests (patient_id, reason, request_time, status) VALUES (?, ?, ?, ?)",
                  (patient_id, reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'pending'))
        conn.commit()
        return jsonify({'success': True, 'message': 'Emergency request submitted successfully!'})
    except sqlite3.Error as e:
        logger.error(f"Database error in emergency_request: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred.'}), 500
    finally:
        conn.close()

@app.route('/admin_manage_users', methods=['GET', 'POST'])
def admin_manage_users():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            action = request.form.get('action')
            staff_number = request.form.get('staff_number')
            if not staff_number:
                flash('Staff number is required.', 'error')
                return redirect(url_for('admin_manage_users'))
            if action == 'delete':
                c.execute("DELETE FROM employees WHERE staff_number = ?", (staff_number,))
                c.execute("DELETE FROM preferences WHERE staff_number = ?", (staff_number,))
                conn.commit()
                flash('User deleted successfully!', 'success')
            elif action == 'update':
                first_name = request.form.get('first_name', '').strip()
                last_name = request.form.get('last_name', '').strip()
                email = request.form.get('email', '').strip()
                role = request.form.get('role', '').strip()
                if not all([first_name, last_name, email, role]):
                    flash('All fields are required for update.', 'error')
                    return redirect(url_for('admin_manage_users'))
                c.execute("""
                    UPDATE employees SET first_name = ?, last_name = ?, email = ?, role = ?
                    WHERE staff_number = ?
                """, (first_name, last_name, email, role, staff_number))
                conn.commit()
                flash('User updated successfully!', 'success')
            return redirect(url_for('admin_manage_users'))
        c.execute("SELECT staff_number, first_name, last_name, email, role, availability FROM employees")
        users = [
            {
                'staff_number': row['staff_number'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'email': row['email'],
                'role': row['role'],
                'availability': row['availability']
            } for row in c.fetchall()
        ]
        return render_template('admin/adminManageUsers.html', users=users, user_details=user_details)
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_manage_users: {e}")
        flash('An error occurred while managing users.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/admin_system_settings', methods=['GET', 'POST'])
def admin_system_settings():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            backup_frequency = request.form.get('backup_frequency', 'weekly')
            c.execute("UPDATE system_settings SET backup_frequency = ? WHERE id = 1", (backup_frequency,))
            conn.commit()
            flash('System settings updated successfully!', 'success')
            return redirect(url_for('admin_system_settings'))
        c.execute("SELECT backup_frequency FROM system_settings WHERE id = 1")
        settings = c.fetchone()
        backup_frequency = settings['backup_frequency'] if settings else 'weekly'
        return render_template('admin/adminSystemSettings.html',
                              backup_frequency=backup_frequency,
                              user_details=user_details)
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_system_settings: {e}")
        flash('An error occurred while updating system settings.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()
            
@app.route('/doctor_report')
def doctor_report():
    if 'username' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        # Example: Fetch recent patient visits
        c.execute("""
            SELECT p.id, p.first_name, p.last_name, v.visit_time, v.notes
            FROM patients p
            JOIN visits v ON p.id = v.patient_id
            WHERE v.visit_time LIKE ?
            ORDER BY v.visit_time DESC
            LIMIT 10
        """, (f"{datetime.now().strftime('%Y-%m-%d')}%",))
        report_data = [
            {
                'patient_id': row['id'],
                'first_name': row['first_name'],
                'last_name': row['last_name'],
                'visit_time': row['visit_time'],
                'notes': row['notes'] or 'No notes'
            } for row in c.fetchall()
        ]
        return render_template('doctor/doctor_report.html',
                              report_data=report_data,
                              user_details=user_details,
                              username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error in doctor_report: {e}")
        flash('An error occurred while generating the report.', 'error')
        return redirect(url_for('doctor_dashboard'))
    finally:
        if conn:
            conn.close()
            
@app.route('/admin_report')
def admin_report():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        # Example: Fetch system usage stats
        c.execute("SELECT COUNT(*) FROM employees WHERE role IN ('doctor', 'nurse', 'receptionist')")
        active_staff = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date LIKE ?", (f"{datetime.now().strftime('%Y-%m-%d')}%",))
        appointments_today = c.fetchone()[0]
        report_data = {
            'active_staff': active_staff,
            'appointments_today': appointments_today
        }
        return render_template('admin/admin_report.html',
                              report_data=report_data,
                              user_details=user_details,
                              username=session['username'])
    except sqlite3.Error as e:
        logger.error(f"Database error in admin_report: {e}")
        flash('An error occurred while generating the report.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    if not os.path.exists('clinicinfo.db'):
        if init_db():
            logger.info("Database initialized successfully")
        else:
            logger.error("Failed to initialize database")
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)