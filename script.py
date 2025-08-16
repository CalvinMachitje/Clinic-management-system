from flask import Flask, request, redirect, url_for, render_template, session, flash, Response, jsonify, json
import sqlite3
import hashlib
import os
from datetime import datetime, date, timedelta
import logging
from werkzeug.utils import secure_filename
import secrets
import random
import re
from queue import Queue
from threading import Lock
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(32)
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# In-memory queue for new appointment notifications
appointment_queue = Queue()
queue_lock = Lock()

# Add new queue for waiting patients notifications
waiting_patients_queue = Queue()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('clinicinfo.db')
    conn.row_factory = sqlite3.Row
    return conn

# Helper function to get user details
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

# Initialize or migrate the database
def init_db():
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
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
                      FOREIGN KEY (patient_id) REFERENCES patients(id))''')
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
        c.execute("INSERT OR REPLACE INTO system_settings (id, backup_frequency) VALUES (1, 'weekly')")
        c.execute("INSERT OR IGNORE INTO employees (first_name, last_name, password, email, role, staff_number) VALUES (?, ?, ?, ?, ?, ?)",
                  ('Admin', 'User', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin@clinic.com', 'admin', 'STAFF001'))
        conn.commit()
        logger.info("Database initialized or migrated successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization or migration error: {e}")
        raise
    finally:
        if conn:
            conn.close()

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
    return render_template('homepage/defaultPage.html')

@app.route('/appointments')
def appointment_homepage():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            ORDER BY a.appointment_date
        """)
        appointments = [
            {
                'id': row[0],
                'patient_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'appointment_date': row[4],
                'status': row[5],
                'reason': row[6]
            } for row in c.fetchall()
        ]
        return render_template('reception/manageAppointments.html',
                              appointments=appointments,
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
            conn = sqlite3.connect('clinicinfo.db')
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
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT * FROM employees WHERE staff_number = ? AND password = ?", (staff_number, hashed_password))
        user = c.fetchone()
        if user:
            session['username'] = staff_number
            session['role'] = user[7]
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S SAST')
            if user[7] in ['doctor', 'nurse']:
                c.execute("UPDATE employees SET availability = 'available' WHERE staff_number = ?", (staff_number,))
                notification = f"{user[1]} {user[2]} ({user[7]}) is now available."
                c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                         (f"{user[7].capitalize()} Available", notification, 'System'))
                conn.commit()
            c.execute("SELECT theme FROM preferences WHERE staff_number = ?", (staff_number,))
            theme = c.fetchone()
            session['theme'] = theme[0] if theme else 'dark'
            if user[7] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user[7] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user[7] == 'nurse':
                return redirect(url_for('nurse_dashboard'))
            elif user[7] == 'receptionist':
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
        conn = sqlite3.connect('clinicinfo.db')
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
                'staff_number': user[0],
                'email': user[1],
                'first_name': user[2],
                'last_name': user[3],
                'phone': user[4],
                'address': user[5],
                'profile_image': user[6] if user[6] else 'default.jpg'
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
        conn = sqlite3.connect('clinicinfo.db')
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
                        'appointment_id': appointment_id,
                        'patient_id': patient_id,
                        'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
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
                c.execute("SELECT id, appointment_date, reason FROM appointments WHERE patient_id = ? AND status = 'scheduled'", (row[0],))
                appointment = c.fetchone()
                patients.append({
                    'id': row[0],
                    'first_name': row[1],
                    'last_name': row[2],
                    'appointment': {
                        'id': appointment[0],
                        'appointment_date': appointment[1],
                        'reason': appointment[2]
                    } if appointment else None
                })
            if not patients:
                flash('No patients found matching your search.', 'info')
            return render_template('search_patient.html', patients=patients, username=session['username'], user_details=user_details)
        
        # Handle GET request
        return render_template('search_patient.html', patients=[], username=session['username'], user_details=user_details)
    
    except Exception as e:
        logger.error(f"Error in search_patient: {str(e)}")
        if request.method == 'POST' and request.form.get('action') == 'book_appointment':
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}', 'category': 'error'})
        flash(f'An error occurred: {str(e)}', 'error')
        # Ensure a response for GET requests
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
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        if not appointment_id:
            flash('Appointment ID is required.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ? AND status = 'scheduled'", (appointment_id,))
        if c.rowcount > 0:
            c.execute("SELECT patient_id, appointment_date, reason FROM appointments WHERE id = ?", (appointment_id,))
            appt = c.fetchone()
            c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appt[0],))
            patient = c.fetchone()
            with queue_lock:
                appointment_queue.put({
                    'appointment_id': appointment_id,
                    'patient_id': appt[0],
                    'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
                    'appointment_date': appt[1],
                    'reason': appt[2],
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
        conn = sqlite3.connect('clinicinfo.db')
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
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appt[0],))
        patient = c.fetchone()
        with queue_lock:
            appointment_queue.put({
                'appointment_id': appointment_id,
                'patient_id': appt[0],
                'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
                'appointment_date': new_time,
                'reason': appt[1],
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
        conn = sqlite3.connect('clinicinfo.db')
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
                'appointment_id': appointment_id,
                'patient_id': patient_id,
                'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
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

@app.route('/check_in_patient', methods=['POST'])
def check_in_patient():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        appointment_id = request.form.get('appointment_id')
        if not appointment_id:
            flash('Appointment ID is required.', 'error')
            return redirect(url_for('check_in_page'))
        c.execute("SELECT patient_id, appointment_date, reason FROM appointments WHERE id = ? AND status IN ('scheduled', 'waiting')", (appointment_id,))
        appt = c.fetchone()
        if not appt:
            flash('Appointment not found or not eligible for check-in.', 'error')
            return redirect(url_for('check_in_page'))
        c.execute("UPDATE appointments SET status = 'checked_in' WHERE id = ?", (appointment_id,))
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (appt[0],))
        patient = c.fetchone()
        with queue_lock:
            appointment_queue.put({
                'appointment_id': appointment_id,
                'patient_id': appt[0],
                'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
                'appointment_date': appt[1],
                'reason': appt[2],
                'status': 'checked_in'
            })
        conn.commit()
        flash('Patient checked in successfully!', 'success')
        return redirect(url_for('check_in_page'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('check_in_page'))
    finally:
        if conn:
            conn.close()

@app.route('/reception_dashboard')
def reception_dashboard():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        month = datetime.now().strftime('%Y-%m')
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.status, a.appointment_date, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ?
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        patients_today = [
            {
                'id': row[0],
                'patient_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'status': row[4],
                'appointment_date': row[5],
                'reason': row[6]
            } for row in c.fetchall()
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
        walkins_processed = len([a for a in patients_today if a['status'] == 'completed'])
        appointments_rescheduled = len([a for a in patients_today if a['status'] == 'rescheduled'])
        payments_processed = len(all_visits)
        c.execute("SELECT title, content, date FROM messages ORDER BY date DESC LIMIT 5")
        notifications = [
            {'title': row[0], 'message': row[1], 'timestamp': datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S')}
            for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        return render_template('reception/reception.html',
                              patients_today=patients_today,
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

@app.route('/reception_overview')
def reception_overview():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        month = datetime.now().strftime('%Y-%m')
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.status, a.appointment_date, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ?
        """, (f'{today}%',))
        patients_today = [
            {
                'id': row[0],
                'patient_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'status': row[4],
                'appointment_date': row[5],
                'reason': row[6]
            } for row in c.fetchall()
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
        date_3days = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%d')
        c.execute("""
            SELECT a.appointment_date, p.first_name, p.last_name, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date > ? AND a.appointment_date <= ?
            ORDER BY a.appointment_date
        """, (today, date_3days))
        upcoming_appointments = [
            {
                "date": datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S"),
                "patient_name": f"{row[1]} {row[2]}",
                "reason": row[3]
            } for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        return render_template('reception/receptionOverview.html',
                              patients_today=patients_today,
                              all_visits=all_visits,
                              available_staff=available_staff,
                              walkins_waiting=walkins_waiting,
                              missed_appointments=missed_appointments,
                              pending_registrations=pending_registrations,
                              upcoming_appointments=upcoming_appointments,
                              user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/check_in_page')
def check_in_page():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if not user_details:
            flash('User details not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ? AND a.status = 'scheduled'
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        scheduled_appointments = [
            {
                'id': row[0],
                'patient_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'appointment_date': row[4],
                'status': row[5],
                'reason': row[6]
            } for row in c.fetchall()
        ]
        c.execute("""
            SELECT a.id, a.patient_id, p.first_name, p.last_name, a.appointment_date, a.status, a.reason
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.appointment_date LIKE ? AND a.status = 'waiting'
            ORDER BY a.appointment_date
        """, (f'{today}%',))
        waitlist = [
            {
                'id': row[0],
                'patient_id': row[1],
                'first_name': row[2],
                'last_name': row[3],
                'appointment_date': row[4],
                'status': row[5],
                'reason': row[6]
            } for row in c.fetchall()
        ]
        return render_template('reception/checkInDesk.html',
                              scheduled_appointments=scheduled_appointments,
                              waitlist=waitlist,
                              user_details=user_details,
                              username=session['username'])
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('reception_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
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
        c.execute("SELECT id FROM appointments WHERE patient_id = ? AND status = 'scheduled'", (patient_id,))
        if c.fetchone():
            flash('Patient already has a scheduled appointment. Cancel it first.', 'error')
            return redirect(url_for('appointment_homepage'))
        c.execute("INSERT INTO appointments (patient_id, appointment_date, status, reason) VALUES (?, ?, ?, ?)",
                  (patient_id, appointment_time, 'scheduled', reason))
        appointment_id = c.lastrowid
        c.execute("SELECT first_name, last_name FROM patients WHERE id = ?", (patient_id,))
        patient = c.fetchone()
        with queue_lock:
            appointment_queue.put({
                'appointment_id': appointment_id,
                'patient_id': patient_id,
                'patient_name': f"{patient[0]} {patient[1]}" if patient else "Unknown",
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
                        # Ensure JSON-serializable data
                        try:
                            appointment_safe = appointment.copy()
                            if 'appointment_date' in appointment_safe:
                                appointment_safe['appointment_date'] = str(appointment_safe['appointment_date'])
                            yield f"data: {json.dumps(appointment_safe)}\n\n"
                        except (TypeError, ValueError) as e:
                            logger.error(f"Error serializing appointment data: {e}, appointment: {appointment}")
                            continue  # Skip invalid data
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
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM employees")
        total_users = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role IN ('doctor', 'nurse', 'receptionist')")
        active_staff = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'pending'")
        system_alerts = c.fetchone()[0]
        c.execute("SELECT staff_number, email, role FROM employees ORDER BY id DESC LIMIT 5")
        recent_users = [{'staff_number': row[0], 'email': row[1], 'role': row[2]} for row in c.fetchall()]
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
    if 'username' not in session or session.get('role') not in ['doctor', 'nurse']:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        employee_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],)).fetchone()[0]
        c.execute("SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender FROM patients p WHERE p.employee_id = ?", (employee_id,))
        patients = [{'id': row[0], 'first_name': row[1], 'last_name': row[2], 'date_of_birth': row[3], 'gender': row[4]} for row in c.fetchall()]
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute("SELECT p.id, p.first_name, p.last_name FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.appointment_date LIKE ? AND p.employee_id = ?", (f'{today}%', employee_id))
        patients_today = [{'id': row[0], 'first_name': row[1], 'last_name': row[2]} for row in c.fetchall()]
        c.execute("SELECT COUNT(*) FROM patients WHERE employee_id = ?", (employee_id,))
        total_patients = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM patients WHERE medical_history LIKE '%chronic%' AND employee_id = ?", (employee_id,))
        chronic_patients = c.fetchone()[0]
        c.execute("SELECT AVG(length(current_medications) - length(replace(current_medications, ',', '')) + 1) FROM patients WHERE current_medications IS NOT NULL AND employee_id = ?", (employee_id,))
        avg_medications = c.fetchone()[0] or 0
        health_trends = "Stable, with a slight increase in chronic condition cases this month."
        user_details = get_user_details(conn, session['username'])
        return render_template('doctor/doctorDashboard.html',
                              now=datetime.now(),
                              username=session['username'],
                              patients=patients,
                              patients_today=patients_today,
                              total_patients=total_patients,
                              chronic_patients=chronic_patients,
                              avg_medications=avg_medications,
                              health_trends=health_trends,
                              user_details=user_details)
    except Exception as e:
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
        conn = sqlite3.connect('clinicinfo.db')
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
                'first_name': row[0],
                'last_name': row[1],
                'id': row[2],
                'appointment_time': datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S") if row[3] else None,
                'appointment_reason': row[5],
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
        conn = sqlite3.connect('clinicinfo.db')
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
        """, (appointment[0], appointment_id, nurse[0], datetime.now(), 'Patient helped by nurse'))
        c.execute("UPDATE appointments SET status = 'helped' WHERE id = ?", (appointment_id,))
        conn.commit()
        with queue_lock:
            waiting_patients_queue.put({
                'id': appointment_id,
                'status': 'helped',
                'patient_id': appointment[0],
                'timestamp': datetime.now().isoformat()
            })
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
        flash('Please log in as a receptionist to access reports.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("""
            SELECT hp.id, hp.patient_id, p.first_name || ' ' || p.last_name AS patient_name,
                   hp.appointment_id, a.appointment_date, hp.nurse_id,
                   e.first_name || ' ' || e.last_name AS nurse_name,
                   hp.helped_timestamp, hp.notes
            FROM helped_patients hp
            JOIN patients p ON hp.patient_id = p.id
            JOIN appointments a ON hp.appointment_id = a.id
            JOIN employees e ON hp.nurse_id = e.id
            ORDER BY hp.helped_timestamp DESC
        """)
        helped_patients = [
            {
                'id': row[0],
                'patient_id': row[1],
                'patient_name': row[2],
                'appointment_id': row[3],
                'appointment_date': row[4],
                'nurse_id': row[5],
                'nurse_name': row[6],
                'helped_timestamp': row[7],
                'notes': row[8]
            } for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        return render_template('helped_patients_report.html', helped_patients=helped_patients, user_details=user_details)
    except sqlite3.Error as e:
        logger.error(f"Database error in helped_patients_report: {e}")
        flash('An error occurred while generating the report.', 'error')
        return render_template('helped_patients_report.html', helped_patients=[], user_details={})
    finally:
        if conn:
            conn.close()
            
# New route for assessing patients
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
                INSERT INTO visits (patient_id, visit_time, vitals, notes)
                VALUES (?, ?, ?, ?)
            """, (patient_id, visit_time, vitals, notes))
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

# New route for viewing medical history
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

# New route for prescribing medications
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
            # Optionally update patient's current_medications
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
        conn = sqlite3.connect('clinicinfo.db')
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
            c.execute("SELECT visit_time FROM visits WHERE patient_id = ? ORDER BY visit_time DESC LIMIT 1", (pat[0],))
            last_vitals_row = c.fetchone()
            last_vitals_time = last_vitals_row[0] if last_vitals_row else "N/A"
            condition_status = "Stable"
            bed_number = random.randint(1, 20)
            active_patients.append({
                'id': pat[0],
                'name': f"{pat[1]} {pat[2]}",
                'bed_number': bed_number,
                'condition_status': condition_status,
                'last_vitals_time': last_vitals_time
            })
        reminders = [
            "Complete daily rounds before noon",
            "Double-check allergy warnings before medication",
            "Report to nurse station for shift handover"
        ]
        return render_template('nurse/nurseOverview.html',
                              user_details=user_details,
                              vitals_recorded_today=vitals_recorded_today,
                              total_patients_today=total_patients_today,
                              meds_administered=meds_administered,
                              alerts_pending=alerts_pending,
                              shift_hours_left=shift_hours_left,
                              active_patients=active_patients,
                              reminders=reminders)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/patients_list.html')
def patients_list():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("""
            SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender, e.first_name || ' ' || e.last_name AS assigned_doctor
            FROM patients p LEFT JOIN employees e ON p.employee_id = e.id
        """)
        patients = [
            {
                'id': row[0],
                'first_name': row[1],
                'last_name': row[2],
                'date_of_birth': row[3],
                'gender': row[4],
                'assigned_doctor': row[5]
            } for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        return render_template('patients_list.html', patients=patients, username=session['username'], user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/addPatient.html', methods=['GET', 'POST'])
def add_patient():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        if request.method == 'POST':
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            address = request.form.get('address')
            phone = request.form.get('phone')
            email = request.form.get('email')
            emergency_contact_name = request.form.get('emergency_contact_name')
            emergency_contact_phone = request.form.get('emergency_contact_phone')
            medical_history = request.form.get('medical_history')
            allergies = request.form.get('allergies')
            current_medications = request.form.get('current_medications')
            employee_id = request.form.get('employee_id')
            if not all([first_name, last_name]):
                flash('First name and last name are required', 'error')
                return render_template('patientRegistration.html')
            conn = sqlite3.connect('clinicinfo.db')
            c = conn.cursor()
            c.execute("""
                INSERT INTO patients (first_name, last_name, date_of_birth, gender, address, phone, email,
                                     emergency_contact_name, emergency_contact_phone, medical_history, allergies, current_medications, employee_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, date_of_birth, gender, address, phone, email, emergency_contact_name,
                  emergency_contact_phone, medical_history, allergies, current_medications, employee_id))
            conn.commit()
            flash('Patient added successfully!', 'success')
            return redirect(url_for('patients_list'))
        else:
            conn = sqlite3.connect('clinicinfo.db')
            c = conn.cursor()
            c.execute("SELECT id, first_name || ' ' || last_name AS full_name FROM employees WHERE role IN ('doctor', 'nurse')")
            employees = [{'id': row[0], 'full_name': row[1]} for row in c.fetchall()]
            user_details = get_user_details(conn, session['username'])
            return render_template('patientRegistration.html', employees=employees, user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return render_template('patientRegistration.html')
    finally:
        if conn:
            conn.close()

@app.route('/edit_patient/<int:id>', methods=['GET', 'POST'])
def edit_patient(id):
    if 'username' not in session or session.get('role') not in ['receptionist', 'nurse', 'doctor']:
        flash('Access restricted to receptionists, nurses, and doctors.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("""
            SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender, p.address, p.phone, p.email,
                   p.emergency_contact_name, p.emergency_contact_phone, p.medical_history, p.allergies,
                   p.current_medications, p.employee_id
            FROM patients p
            WHERE p.id = ?
        """, (id,))
        patient = c.fetchone()
        if not patient:
            flash('Patient not found.', 'error')
            return redirect(url_for('patients_list'))
        patient_data = {
            'id': patient[0],
            'first_name': patient[1],
            'last_name': patient[2],
            'date_of_birth': patient[3],
            'gender': patient[4],
            'address': patient[5],
            'phone': patient[6],
            'email': patient[7],
            'emergency_contact_name': patient[8],
            'emergency_contact_phone': patient[9],
            'medical_history': patient[10],
            'allergies': patient[11],
            'current_medications': patient[12],
            'employee_id': patient[13]
        }
        if request.method == 'POST':
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            date_of_birth = request.form.get('date_of_birth') or None
            gender = request.form.get('gender') or None
            address = request.form.get('address') or None
            phone = request.form.get('phone') or None
            email = request.form.get('email') or None
            emergency_contact_name = request.form.get('emergency_contact_name') or None
            emergency_contact_phone = request.form.get('emergency_contact_phone') or None
            medical_history = request.form.get('medical_history') or None
            allergies = request.form.get('allergies') or None
            current_medications = request.form.get('current_medications') or None
            employee_id = request.form.get('employee_id') or None
            if session.get('role') not in ['nurse', 'doctor']:
                medical_history = patient_data['medical_history']
                allergies = patient_data['allergies']
                current_medications = patient_data['current_medications']
                employee_id = patient_data['employee_id']
            c.execute("""
                UPDATE patients
                SET first_name = ?, last_name = ?, date_of_birth = ?, gender = ?, address = ?, phone = ?, email = ?,
                    emergency_contact_name = ?, emergency_contact_phone = ?, medical_history = ?, allergies = ?,
                    current_medications = ?, employee_id = ?
                WHERE id = ?
            """, (first_name, last_name, date_of_birth, gender, address, phone, email,
                  emergency_contact_name, emergency_contact_phone, medical_history, allergies,
                  current_medications, employee_id, id))
            conn.commit()
            flash('Patient updated successfully!', 'success')
            return redirect(url_for('patients_list'))
        c.execute("SELECT id, first_name, last_name FROM employees WHERE role = 'doctor'")
        doctors = [{'id': row[0], 'first_name': row[1], 'last_name': row[2]} for row in c.fetchall()]
        user_details = get_user_details(conn, session['username'])
        return render_template('edit_patient.html', patient=patient_data, doctors=doctors, user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('patients_list'))
    finally:
        if conn:
            conn.close()

@app.route('/delete_patient/<int:id>')
def delete_patient(id):
    if 'username' not in session or session.get('role') not in ['receptionist', 'nurse', 'doctor']:
        flash('Access restricted to receptionists, nurses, and doctors.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT id FROM patients WHERE id = ?", (id,))
        if not c.fetchone():
            flash('Patient not found.', 'error')
            return redirect(url_for('patients_list'))
        c.execute("DELETE FROM patients WHERE id = ?", (id,))
        conn.commit()
        flash('Patient deleted successfully!', 'success')
        return redirect(url_for('patients_list'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('patients_list'))
    finally:
        if conn:
            conn.close()

@app.route('/userManagement.html')
def user_management():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT id, first_name, last_name, staff_number, email, role FROM employees")
        employees = [
            {
                'id': row[0],
                'first_name': row[1],
                'last_name': row[2],
                'staff_number': row[3],
                'email': row[4],
                'role': row[5]
            } for row in c.fetchall()
        ]
        user_details = get_user_details(conn, session['username'])
        return render_template('admin/user_management.html', employees=employees, username=session['username'], user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        staff_number = request.form.get('staff_number')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')
        if not all([first_name, last_name, staff_number, password, email, role]):
            flash('All required fields are required', 'error')
            return redirect(url_for('user_management'))
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("INSERT INTO employees (first_name, last_name, staff_number, password, email, role) VALUES (?, ?, ?, ?, ?, ?)",
                  (first_name, last_name, staff_number, hashed_password, email, role))
        c.execute("INSERT INTO preferences (staff_number, theme) VALUES (?, ?)", (staff_number, 'dark'))
        conn.commit()
        flash('Employee added successfully!', 'success')
        return redirect(url_for('user_management'))
    except sqlite3.IntegrityError:
        flash('Staff number or email already exists. Please choose another.', 'error')
        return redirect(url_for('user_management'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('user_management'))
    finally:
        if conn:
            conn.close()

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        user_id = request.form.get('user_id')
        reason = request.form.get('reason')
        if not user_id or not reason:
            flash('User ID and reason are required.', 'error')
            return redirect(url_for('user_management'))
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("DELETE FROM employees WHERE id = ?", (user_id,))
        c.execute("DELETE FROM preferences WHERE staff_number = (SELECT staff_number FROM employees WHERE id = ?)", (user_id,))
        if c.rowcount > 0:
            flash(f'User deleted successfully. Reason: {reason}', 'success')
        else:
            flash('User not found.', 'error')
        conn.commit()
        return redirect(url_for('user_management'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('user_management'))
    finally:
        if conn:
            conn.close()

@app.route('/system_setting.html')
def system_settings():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT backup_frequency FROM system_settings WHERE id = 1")
        result = c.fetchone()
        system_settings = {'backup_frequency': result[0] if result else 'weekly'}
        user_details = get_user_details(conn, session['username'])
        return render_template('admin/system_setting.html', system_settings=system_settings, username=session['username'], user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/save_settings', methods=['POST'])
def save_settings():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        backup_frequency = request.form.get('backup_frequency')
        if not backup_frequency:
            flash('Backup frequency is required', 'error')
            return redirect(url_for('system_settings'))
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("UPDATE system_settings SET backup_frequency = ? WHERE id = 1", (backup_frequency,))
        conn.commit()
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('system_settings'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('system_settings'))
    finally:
        if conn:
            conn.close()

@app.route('/admin_report')
def admin_report():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM employees")
        total_users = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role = 'doctor'")
        total_doctors = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role = 'nurse'")
        total_nurses = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role = 'receptionist'")
        total_receptionists = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role = 'admin'")
        total_admins = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM employees WHERE role NOT IN ('doctor','nurse','receptionist','admin')")
        total_others = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM patients")
        total_patients = c.fetchone()[0]
        today = datetime.now()
        month_start = today.replace(day=1).strftime('%Y-%m-%d')
        c.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date >= ?", (month_start,))
        monthly_appointments_total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'pending'")
        pending_appointments = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'completed'")
        completed_appointments = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'missed'")
        missed_appointments = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE status = 'cancelled'")
        cancelled_appointments = c.fetchone()[0]
        monthly_revenue = 50000
        months_labels = []
        monthly_appointments_data = []
        for i in range(12):
            date = (today.replace(day=1) - timedelta(days=30*i))
            month_str = date.strftime('%Y-%m')
            months_labels.append(date.strftime('%b %Y'))
            c.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date LIKE ?", (month_str + '%',))
            count = c.fetchone()[0]
            monthly_appointments_data.append(count)
        months_labels.reverse()
        monthly_appointments_data.reverse()
        staff_data = {
            "labels": ['Doctors', 'Nurses', 'Receptionists', 'Admins', 'Others'],
            "datasets": [{
                "data": [total_doctors, total_nurses, total_receptionists, total_admins, total_others],
                "backgroundColor": ['#3f51b5', '#e91e63', '#ffc107', '#009688', '#9c27b0']
            }]
        }
        appointment_status_data = {
            "labels": ['Pending', 'Completed', 'Missed', 'Cancelled'],
            "datasets": [{
                "label": "Appointments",
                "data": [pending_appointments, completed_appointments, missed_appointments, cancelled_appointments],
                "backgroundColor": ['#fbc02d', '#4caf50', '#f44336', '#9e9e9e']
            }]
        }
        monthly_appointments_chart_data = {
            "labels": months_labels,
            "datasets": [{
                "label": "Appointments",
                "data": monthly_appointments_data,
                "fill": False,
                "borderColor": '#3f51b5',
                "tension": 0.4
            }]
        }
        user_details = get_user_details(conn, session['username'])
        return render_template(
            'admin/admin_report.html',
            username=session['username'],
            total_users=total_users,
            total_doctors=total_doctors,
            total_nurses=total_nurses,
            total_receptionists=total_receptionists,
            total_admins=total_admins,
            total_others=total_others,
            total_patients=total_patients,
            monthly_appointments_total=monthly_appointments_total,
            pending_appointments=pending_appointments,
            completed_appointments=completed_appointments,
            missed_appointments=missed_appointments,
            cancelled_appointments=cancelled_appointments,
            monthly_revenue=monthly_revenue,
            staff_pie_data_json=json.dumps(staff_data),
            appointment_bar_data_json=json.dumps(appointment_status_data),
            monthly_appointments_data_json=json.dumps(monthly_appointments_chart_data),
            user_details=user_details
        )
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/doctor_report')
def doctor_report():
    if 'username' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        doctor_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],)).fetchone()[0]
        c.execute("SELECT COUNT(*) FROM patients WHERE employee_id = ?", (doctor_id,))
        total_patients = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM appointments WHERE patient_id IN (SELECT id FROM patients WHERE employee_id = ?) AND appointment_date LIKE ?", (doctor_id, datetime.now().strftime('%Y-%m-%d') + '%'))
        today_appointments = c.fetchone()[0]
        user_details = get_user_details(conn, session['username'])
        return render_template('doctor/doctor_report.html',
                              username=session['username'],
                              total_patients=total_patients,
                              today_appointments=today_appointments,
                              user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/record_visit', methods=['POST'])
def record_visit():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        patient_id = request.form.get('visit_patient_id')
        visit_time = request.form.get('visit_time')
        notes = request.form.get('notes')
        if not all([patient_id, visit_time]):
            flash('Patient ID and visit time are required.', 'error')
            return redirect(url_for('reception_dashboard'))
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("INSERT INTO visits (patient_id, visit_time, notes) VALUES (?, ?, ?)", (patient_id, visit_time, notes))
        conn.commit()
        flash('Visit recorded successfully!', 'success')
        return redirect(url_for('reception_dashboard'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('reception_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/view_patient/<int:id>')
def view_patient(id):
    if 'username' not in session or session.get('role') not in ['nurse', 'doctor', 'receptionist']:
        flash('Access restricted to nurses, doctors, and receptionists.', 'error')
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("""
            SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender, p.address, p.phone, p.email,
                   p.emergency_contact_name, p.emergency_contact_phone, p.medical_history, p.allergies,
                   p.current_medications, e.first_name || ' ' || e.last_name AS assigned_doctor
            FROM patients p
            LEFT JOIN employees e ON p.employee_id = e.id
            WHERE p.id = ?
        """, (id,))
        patient = c.fetchone()
        if not patient:
            flash('Patient not found.', 'error')
            return redirect(url_for('patients_list'))
        patient_data = {
            'id': patient[0],
            'first_name': patient[1],
            'last_name': patient[2],
            'date_of_birth': patient[3],
            'gender': patient[4],
            'address': patient[5],
            'phone': patient[6],
            'email': patient[7],
            'emergency_contact_name': patient[8],
            'emergency_contact_phone': patient[9],
            'medical_history': patient[10],
            'allergies': patient[11],
            'current_medications': patient[12],
            'assigned_doctor': patient[13]
        }
        appointments = []
        if session.get('role') == 'receptionist':
            c.execute("""
                SELECT id, appointment_date, status
                FROM appointments
                WHERE patient_id = ?
                ORDER BY appointment_date DESC
            """, (id,))
            appointments = [{'id': row[0], 'appointment_date': row[1], 'status': row[2]} for row in c.fetchall()]
        user_details = get_user_details(conn, session['username'])
        return render_template('view_patient.html', patient=patient_data, appointments=appointments, user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('patients_list'))
    finally:
        if conn:
            conn.close()

@app.route('/transfer_patient', methods=['POST'])
def transfer_patient():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        patient_id = request.form.get('transfer_patient_id')
        to_clinic = request.form.get('to_clinic')
        if not all([patient_id, to_clinic]):
            flash('Patient ID and destination clinic are required.', 'error')
            return redirect(url_for('reception_dashboard'))
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("UPDATE patients SET clinic = ? WHERE id = ?", (to_clinic, patient_id))
        if c.rowcount > 0:
            flash(f'Patient transferred to {to_clinic} successfully!', 'success')
        else:
            flash('Patient not found.', 'error')
        conn.commit()
        return redirect(url_for('reception_dashboard'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('reception_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/request_ambulance', methods=['POST'])
def request_ambulance():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        patient_id = request.form.get('emergency_patient_id')
        reason = request.form.get('emergency_reason')
        if not all([patient_id, reason]):
            flash('Patient ID and reason are required.', 'error')
            return redirect(url_for('reception_dashboard'))
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("INSERT INTO emergency_requests (patient_id, reason) VALUES (?, ?)", (patient_id, reason))
        conn.commit()
        flash('Ambulance requested successfully!', 'success')
        return redirect(url_for('reception_dashboard'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('reception_dashboard'))
    finally:
        if conn:
            conn.close()

@app.route('/generate_daily_report')
def generate_daily_report():
    if 'username' not in session or session.get('role') != 'receptionist':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        today = datetime(2025, 7, 18, 20, 32, 0).strftime('%Y-%m-%d')
        c.execute("SELECT p.id AS patient_id, p.first_name AS patient_first_name, p.last_name AS patient_last_name, v.visit_time, v.notes FROM visits v JOIN patients p ON v.patient_id = p.id WHERE v.visit_time LIKE ?", (today + '%',))
        visits_today = [{'patient_id': row[0], 'patient_first_name': row[1], 'patient_last_name': row[2], 'visit_time': row[3], 'notes': row[4]} for row in c.fetchall()]
        user_details = get_user_details(conn, session['username'])
        return render_template('daily_report.html', username=session['username'], visits_today=visits_today, date=today, user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/logout')
def logout():
    conn = None
    try:
        if 'username' in session and session.get('role') in ['doctor', 'nurse']:
            conn = sqlite3.connect('clinicinfo.db')
            c = conn.cursor()
            c.execute("UPDATE employees SET availability = 'unavailable' WHERE staff_number = ?", (session['username'],))
            c.execute("SELECT first_name, last_name, role FROM employees WHERE staff_number = ?", (session['username'],))
            user = c.fetchone()
            if user:
                notification = f"{user[0]} {user[1]} ({user[2]}) is now unavailable."
                c.execute("INSERT INTO messages (title, content, sender) VALUES (?, ?, ?)",
                         (f"{user[2].capitalize()} Unavailable", notification, 'System'))
            conn.commit()
        session.pop('username', None)
        session.pop('role', None)
        session.pop('login_time', None)
        session.pop('theme', None)
        return redirect(url_for('login_page'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

# New Routes for Sidebar Items
@app.route('/overview')
def overview():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        role = session.get('role')
        if role == 'admin':
            c.execute("SELECT COUNT(*) FROM employees")
            total_users = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM employees WHERE role IN ('doctor', 'nurse', 'receptionist')")
            active_staff = c.fetchone()[0]
            return render_template('overview.html', total_users=total_users, active_staff=active_staff, user_details=user_details)
        elif role == 'doctor':
            doctor_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],)).fetchone()[0]
            c.execute("SELECT COUNT(*) FROM patients WHERE employee_id = ?", (doctor_id,))
            total_patients = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM appointments WHERE patient_id IN (SELECT id FROM patients WHERE employee_id = ?) AND appointment_date = ?", (doctor_id, datetime(2025, 7, 18, 20, 32, 0).strftime('%Y-%m-%d')))
            today_appointments = c.fetchone()[0]
            return render_template('overview.html', total_patients=total_patients, today_appointments=today_appointments, user_details=user_details)
        elif role == 'nurse':
            employee_id = c.execute("SELECT id FROM employees WHERE staff_number = ?", (session['username'],)).fetchone()[0]
            c.execute("SELECT p.id, p.first_name, p.last_name, p.date_of_birth, p.gender FROM patients p WHERE p.employee_id = ?", (employee_id,))
            patients = c.fetchall()
            todays_patients = len(patients)
            pending_vitals = len(patients)
            return render_template('overview.html', pending_vitals=pending_vitals, todays_patients=todays_patients, user_details=user_details)
        elif role == 'receptionist':
            today = datetime(2025, 7, 18, 20, 32, 0).strftime('%Y-%m-%d')
            c.execute("""
                SELECT p.id, p.first_name, p.last_name, a.appointment_date 
                FROM appointments a 
                JOIN patients p ON a.patient_id = p.id 
                WHERE a.appointment_date LIKE ?
            """, (today + '%',))
            patients_today = [{'id': row[0], 'first_name': row[1], 'last_name': row[2], 'appointment_date': row[3]} for row in c.fetchall()]
            c.execute("""
                SELECT p.id AS patient_id, p.first_name AS patient_first_name, p.last_name AS patient_last_name, v.visit_time, v.notes
                FROM visits v 
                JOIN patients p ON v.patient_id = p.id 
                WHERE v.visit_time LIKE ?
            """, (today + '%',))
            all_visits = [{'patient_id': row[0], 'patient_first_name': row[1], 'patient_last_name': row[2], 'visit_time': row[3], 'notes': row[4]} for row in c.fetchall()]
            return render_template('overview.html', patients_today=patients_today, all_visits=all_visits, user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/staff_counseling')
def staff_counseling():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        return render_template('staff_counseling.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/calendar')
def calendar():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        today = datetime(2025, 7, 18, 20, 32, 0).strftime('%Y-%m-%d')
        user_details = get_user_details(conn, session['username'])
        role = session.get('role')
        if role == 'receptionist':
            c.execute("""
                SELECT p.id, p.first_name, p.last_name, a.appointment_date 
                FROM appointments a 
                JOIN patients p ON a.patient_id = p.id 
                WHERE a.appointment_date LIKE ?
                ORDER BY a.appointment_date ASC
            """, (today + '%',))
            patients_today = [{'id': row[0], 'first_name': row[1], 'last_name': row[2], 'appointment_date': row[3]} for row in c.fetchall()]
            return render_template('calendar.html', patients_today=patients_today, now=datetime(2025, 7, 18, 20, 32, 0), user_details=user_details)
        return render_template('calendar.html', now=datetime(2025, 7, 18, 20, 32, 0), user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/announcements')
def announcements():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        c.execute("SELECT title, content, date FROM messages ORDER BY date DESC LIMIT 5")
        messages = [{'title': row[0], 'content': row[1], 'date': row[2]} for row in c.fetchall()]
        user_details = get_user_details(conn, session['username'])
        return render_template('announcement.html', messages=messages, now=datetime(2025, 7, 18, 20, 32, 0), user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            theme = request.form.get('theme')
            if theme:
                c.execute("INSERT OR REPLACE INTO preferences (staff_number, theme) VALUES (?, ?)", (session['username'], theme))
                conn.commit()
                session['theme'] = theme
                flash('Theme preference saved!', 'success')
            return redirect(url_for('preferences'))
        c.execute("SELECT theme FROM preferences WHERE staff_number = ?", (session['username'],))
        theme = c.fetchone()
        current_theme = theme[0] if theme else 'dark'
        session['theme'] = current_theme
        return render_template('preferences.html', user_details=user_details, current_theme=current_theme)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/worksite_setup', methods=['GET', 'POST'])
def worksite_setup():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            clinic_name = request.form.get('clinic_name')
            if clinic_name:
                c.execute("UPDATE system_settings SET backup_frequency = ? WHERE id = 1", (clinic_name,))
                conn.commit()
                flash('Worksite setup updated!', 'success')
            return redirect(url_for('worksite_setup'))
        return render_template('worksite_setup.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/trusted_application', methods=['GET', 'POST'])
def trusted_application():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        if request.method == 'POST':
            app_name = request.form.get('app_name')
            if app_name:
                flash('Trusted application added!', 'success')
            return redirect(url_for('trusted_application'))
        return render_template('trusted_application.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/system_guides')
def system_guides():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        return render_template('system_guides.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/email_info')
def email_info():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        return render_template('email_info.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

@app.route('/help')
def help():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    conn = None
    try:
        conn = sqlite3.connect('clinicinfo.db')
        c = conn.cursor()
        user_details = get_user_details(conn, session['username'])
        return render_template('help.html', user_details=user_details)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login_page'))
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    try:
        init_db()
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        logger.error(f"Error during initialization: {e}")
        raise