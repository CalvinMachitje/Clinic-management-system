-- ========================================
-- ClinicCare Pro™ – PostgreSQL Dump
-- Database: postclinic
-- User: clinicuser
-- Port: 5433
-- ========================================

BEGIN;

-- Drop tables if they exist (clean start)
DROP TABLE IF EXISTS appointments_new, appointments, patients, employees, prescriptions, visits, emergency_requests, messages, system_settings, preferences, announcements, payments, notifications, helped_patients, self_booked_appointments, walkin_queue, audit_log CASCADE;

-- ========================================
-- 1. EMPLOYEES
-- ========================================
CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
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
    staff_number TEXT UNIQUE NOT NULL DEFAULT 'TEMPSTAFF',
    specialization TEXT
);

INSERT INTO employees VALUES(1,'Admin','User','admin@clinic.com','$2b$12$m5g/lQc4k8sIB.wf72e4uu9hxsLjO9TCqfyxdsFDpbrh0FURS7nu6',NULL,NULL,'admin',NULL,'available','default.jpg','STAFF001',NULL);
INSERT INTO employees VALUES(15,'Onke','Makuoa','Onke.doctor@clinic.ac.za','$2b$12$F2Nik0HlpMfkXm9IHiWmsuuaE40CTj49OOXemhdVgwLnyO2gJrUL2',NULL,NULL,'doctor',NULL,'available','default.jpg','STAFF002',NULL);
INSERT INTO employees VALUES(23,'Joe','Molapo','Joe.nurse@clinic.ac.za','$2b$12$BD8Hmb3xWo8pk4Lfsdnw5uUBfKZpy0DmeYtQcabNbLC3OSN2YDOt.',NULL,NULL,'nurse',NULL,'available','default.jpg','STAFF016',NULL);
INSERT INTO employees VALUES(24,'Commander','Morning','commander.reception@clinic.ac.za','$2b$12$N5fl53mr9GVJX93Xx9PL6OnWg.vNXF37eMsiV8QKvuGvHaTpyd3uq',NULL,NULL,'receptionist',NULL,'available','default.jpg','STAFF024',NULL);
INSERT INTO employees VALUES(33,'Calvin','Machitje','test36@gmail.com','$2b$12$UXnF325QeNSgG9EZdyp0MOXG.RLJ0V73zDgvSeW/2DR9jFRyqJ2he',NULL,NULL,'admin',NULL,'available','default.jpg','STAFF025',NULL);
INSERT INTO employees VALUES(34,'sam','mas','sam.mas@clinic.ac.za','$2b$12$z9XOonHXCjzpsOH.W7T7Meybcfcxyi5ydZlmizEVZwFb4e6BwGOIq',NULL,NULL,'receptionist',NULL,'available','default.jpg','STAFF034',NULL);
INSERT INTO employees VALUES(52,'Oupa','Makie','oupa.makie@clinic.ac.za','$2b$12$nDMkz2NizLniX3rzPIw6uO4kHuELE0Lkz4aft.B8my9ssabsyBMCO',NULL,NULL,'doctor',NULL,'unavailable','default.jpg','STAFF035',NULL);
INSERT INTO employees VALUES(53,'Lerato','Melane','lerato.melane@clinic.ac.za','$2b$12$haWuVgKJwp/dueugc3//ZOgGRnEn9GS2HuwJOaFhRsoRT7.qYzZja',NULL,NULL,'nurse',NULL,'unavailable','default.jpg','STAFF053',NULL);
INSERT INTO employees VALUES(81,'Neo','Malema','neo.malema@clinic.ac.za','$2b$12$wakpo3sM0to38a6F7r2EduhChCIipmFjezpHAzdGlm0GzgrXtuAfu',NULL,NULL,'receptionist',NULL,'available','default.jpg','STAFF054',NULL);
INSERT INTO employees VALUES(93,'Siya','Dlamini','siya.admin@clinic.ac.za','$2b$12$IKvr6dY/QONzVXplbZH2Z.fmrZ7lfSEuo5UMQv9jYjcm8tXTa3ECy',NULL,NULL,'admin',NULL,'available','default.jpg','STAFF082',NULL);
INSERT INTO employees VALUES(94,'Colbert','Dhladlha','colbert.dladla@clinic.ac.za','$2b$12$mOlxeLPRxlbCyzyiUIkC1eFt2o7aGJL3Fav5h56E4eiHCJKGGwrSq',NULL,NULL,'doctor',NULL,'unavailable','default.jpg','STAFF094',NULL);
INSERT INTO employees VALUES(95,'Maki','Makhe','maki.nurse@clinic.ac.za','$2b$12$1iLAX/Xknjrek3Vbp63dEeHjCUbYmAh.QQ.1QwJadYzHS1i8sAFmK',NULL,NULL,'nurse',NULL,'unavailable','default.jpg','STAFF095',NULL);
INSERT INTO employees VALUES(96,'Sello','Mayors','sello.reception@clinic.ac.za','$2b$12$EL/T9hiOutmIb3ODmIKx/umat.MaQOtyZQVKhtkuQkRh8HByUCnHu',NULL,NULL,'receptionist',NULL,'available','default.jpg','STAFF096',NULL);
INSERT INTO employees VALUES(140,'Steven','MacTak','Steven.MacTak@clinic.ac.za','$2b$12$vjm932nrvIeXjArfSHZ2OOkEF20qn1rwTyrH3scDU.2L9ZDd0u.1W',NULL,NULL,'admin',NULL,'available','default.jpg','STAFF097',NULL);
INSERT INTO employees VALUES(141,'Mzilomba','MacTak','doctor@clinic.ac.za','$2b$12$L.P8vUP1vBECqPyYy0fmkutU9PyUiFBI8PPB7gNx5ET4pvUnVMBk.',NULL,NULL,'doctor',NULL,'unavailable','default.jpg','STAFF141',NULL);
INSERT INTO employees VALUES(142,'Oliver','Smiley','Oliver.Smiley@clinic.ac.za','$2b$12$JJ/7lNSWJb1W52/yDLNzvuzEnzAgD1Kl66H.bEh8kwuVNPldFmTg2',NULL,NULL,'receptionist',NULL,'available','default.jpg','STAFF142',NULL);

-- ========================================
-- 2. PATIENTS
-- ========================================
CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY (employee_id) REFERENCES employees(id)
);

INSERT INTO patients VALUES(1,'Maki','Makhe','2021-07-14','Female','1774 Hendrick van eck','0169103326','jack.sparrow@gmail.com','Mother','0169103326','Diabetic','Peanut ','Allergex',NULL,'Clinic A','2025-11-01 12:09:54','active');
INSERT INTO patients VALUES(2,'Lucky','Mayors','2005-11-14','Male','1774 Hendrick van eck','0835337645','jack.sparrow@gmail.com','Mother','07452103356','None','Fish','None',NULL,'Clinic A','2025-11-01 20:45:03','active');

-- ========================================
-- 3. APPOINTMENTS (helper_id → staff_number)
-- ========================================
CREATE TABLE appointments (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    appointment_date TEXT NOT NULL,
    status TEXT DEFAULT 'scheduled',
    reason TEXT,
    created_by_role TEXT DEFAULT 'receptionist',
    helper_id TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (helper_id) REFERENCES employees(staff_number)
);

INSERT INTO appointments VALUES(1,1,'2025-11-01 17:45:46','assigned','Walk-in','receptionist','STAFF002');
INSERT INTO appointments VALUES(2,1,'2025-11-01 17:47:15','assigned','Walk-in','receptionist','STAFF016');
INSERT INTO appointments VALUES(3,1,'2025-11-03T10:00','scheduled','Appointment for month regular doctor visit','receptionist','STAFF002');
INSERT INTO appointments VALUES(4,2,'2025-11-01T23:01','scheduled','Doctor consultation','receptionist','STAFF002');
INSERT INTO appointments VALUES(5,2,'2025-11-01T12:37','scheduled','Doctor''s consultation','receptionist','STAFF002');
INSERT INTO appointments VALUES(6,2,'2025-11-01T12:28','scheduled','Doctor''s consultation','receptionist','STAFF002');
INSERT INTO appointments VALUES(7,2,'2025-11-01 21:40:10','waiting','Walk-in','receptionist',NULL);
INSERT INTO appointments VALUES(8,2,'2025-11-01 22:04:54','waiting','Walk-in','receptionist',NULL);
INSERT INTO appointments VALUES(9,2,'2025-11-14T16:54','scheduled','Doctor consultation','receptionist','STAFF002');

-- ========================================
-- 4. OTHER TABLES
-- ========================================
CREATE TABLE prescriptions (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    nurse_id INTEGER,
    medication_name TEXT NOT NULL,
    dosage TEXT NOT NULL,
    instructions TEXT,
    prescribed_date TEXT NOT NULL,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (nurse_id) REFERENCES employees(id)
);

CREATE TABLE visits (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    visit_time TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE emergency_requests (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sender TEXT NOT NULL
);

INSERT INTO messages VALUES(1,'Doctor Unavailable','Oupa Makie (doctor) is now unavailable.','2025-10-23 17:54:49','System');
INSERT INTO messages VALUES(2,'Nurse Unavailable','Lerato Melane (nurse) is now unavailable.','2025-10-23 17:59:58','System');
INSERT INTO messages VALUES(3,'Doctor Unavailable','Oupa Makie (doctor) is now unavailable.','2025-10-23 18:07:11','System');
INSERT INTO messages VALUES(4,'Nurse Unavailable','Lerato Melane (nurse) is now unavailable.','2025-10-23 18:14:43','System');
INSERT INTO messages VALUES(5,'Nurse Unavailable','Lerato Melane (nurse) is now unavailable.','2025-10-23 18:24:29','System');
INSERT INTO messages VALUES(6,'Doctor Unavailable','Oupa Makie (doctor) is now unavailable.','2025-10-23 18:24:56','System');
INSERT INTO messages VALUES(7,'Nurse Unavailable','Lerato Melane (nurse) is now unavailable.','2025-10-24 10:27:50','System');
INSERT INTO messages VALUES(8,'Doctor Unavailable','Oupa Makie (doctor) is now unavailable.','2025-10-24 14:05:11','System');
INSERT INTO messages VALUES(9,'Doctor Unavailable','Colbert Dhladlha (doctor) is now unavailable.','2025-10-25 12:17:52','System');
INSERT INTO messages VALUES(10,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-10-25 12:18:53','System');
INSERT INTO messages VALUES(11,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-10-25 13:52:25','System');
INSERT INTO messages VALUES(12,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-10-25 13:59:27','System');
INSERT INTO messages VALUES(13,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-10-25 14:31:49','System');
INSERT INTO messages VALUES(14,'Doctor Unavailable','Colbert Dhladlha (doctor) is now unavailable.','2025-10-25 15:53:21','System');
INSERT INTO messages VALUES(15,'Doctor Unavailable','Colbert Dhladlha (doctor) is now unavailable.','2025-10-25 15:54:23','System');
INSERT INTO messages VALUES(16,'Doctor Unavailable','Colbert Dhladlha (doctor) is now unavailable.','2025-11-01 17:01:52','System');
INSERT INTO messages VALUES(17,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-11-01 17:02:01','System');
INSERT INTO messages VALUES(18,'Doctor Unavailable','Colbert Dhladlha (doctor) is now unavailable.','2025-11-01 17:48:44','System');
INSERT INTO messages VALUES(19,'Nurse Unavailable','Maki Makhe (nurse) is now unavailable.','2025-11-01 17:49:02','System');
INSERT INTO messages VALUES(20,'Doctor Unavailable','Mzilomba MacTak (doctor) is now unavailable.','2025-11-07 09:54:49','System');
INSERT INTO messages VALUES(21,'Doctor Unavailable','Mzilomba MacTak (doctor) is now unavailable.','2025-11-07 10:13:28','System');
INSERT INTO messages VALUES(22,'Doctor Unavailable','Mzilomba MacTak (doctor) is now unavailable.','2025-11-07 12:15:37','System');
INSERT INTO messages VALUES(23,'Doctor Unavailable','Mzilomba MacTak (doctor) is now unavailable.','2025-11-07 12:21:53','System');
INSERT INTO messages VALUES(24,'Doctor Unavailable','Mzilomba MacTak (doctor) is now unavailable.','2025-11-07 12:46:19','System');

CREATE TABLE system_settings (
    id INTEGER PRIMARY KEY,
    backup_frequency TEXT
);
INSERT INTO system_settings VALUES(1,'weekly');

CREATE TABLE preferences (
    id SERIAL PRIMARY KEY,
    staff_number TEXT UNIQUE,
    theme TEXT DEFAULT 'dark'
);

CREATE TABLE announcements (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    category TEXT NOT NULL,
    author TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pinned BOOLEAN DEFAULT FALSE,
    target_role TEXT DEFAULT 'all'
);

CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE helped_patients (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL,
    nurse_id INTEGER,
    appointment_date TEXT,
    helped_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (nurse_id) REFERENCES employees(id)
);

CREATE TABLE IF NOT EXISTS self_booked_appointments (
    id SERIAL PRIMARY KEY,
    patient_name TEXT NOT NULL,
    patient_phone TEXT,
    patient_email TEXT,
    appointment_date TEXT NOT NULL,
    reason TEXT,
    doctor_staff_number TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO self_booked_appointments VALUES(1,'Topper','0736953254','test@gmail.com','2025-11-03 10:00:00','Appointment for month regular doctor visit','STAFF002','converted','2025-11-01 20:24:50');
INSERT INTO self_booked_appointments VALUES(2,'Lucky Martins','0736953254','test@gmail.com','2025-11-01 12:28:00','Doctor''s consultation','STAFF002','converted','2025-11-01 21:28:52');
INSERT INTO self_booked_appointments VALUES(3,'Lucky Martins','0736953254','test@gmail.com','2025-11-01 12:37:00','Doctor''s consultation','STAFF002','converted','2025-11-01 21:37:31');

CREATE TABLE walkin_queue (
    id SERIAL PRIMARY KEY,
    patient_id TEXT NOT NULL,
    patient_name TEXT NOT NULL,
    priority TEXT NOT NULL,
    reason TEXT,
    arrived_at TEXT NOT NULL
);

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    target_user TEXT,
    details TEXT,
    timestamp TEXT NOT NULL
);

INSERT INTO audit_log VALUES(1,'create_user','STAFF097','STAFF142','Temp: STAFF142/Temp123!','2025-11-07 11:49:56');

-- Index
CREATE INDEX idx_appointments_date_status ON appointments(appointment_date, status);

-- 1. attendance
CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY,
    staff_id INTEGER,
    date TEXT,
    status TEXT
);

-- 2. billing
CREATE TABLE IF NOT EXISTS billing (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER,
    appointment_id INTEGER,
    cost REAL DEFAULT 0,
    billing_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY(patient_id) REFERENCES patients(id),
    FOREIGN KEY(appointment_id) REFERENCES appointments(id)
);

-- 3. certifications
CREATE TABLE IF NOT EXISTS certifications (
    id SERIAL PRIMARY KEY,
    staff_id INTEGER,
    name TEXT,
    staff TEXT,
    expiry TEXT,
    days_left INTEGER
);

-- 4. clinic_reports
CREATE TABLE IF NOT EXISTS clinic_reports (
    id SERIAL PRIMARY KEY,
    report_date DATE DEFAULT CURRENT_DATE,
    patients_seen INTEGER,
    revenue REAL,
    expenses REAL,
    staff_on_duty INTEGER,
    low_stock_items INTEGER,
    notes TEXT
);

-- 5. inventory
CREATE TABLE IF NOT EXISTS inventory (
    id SERIAL PRIMARY KEY,
    item_name TEXT NOT NULL,
    category TEXT,
    quantity INTEGER DEFAULT 0,
    unit TEXT,
    min_stock INTEGER DEFAULT 10,
    avg_daily_use REAL DEFAULT 0.0,
    supplier TEXT,
    cost_per_unit REAL DEFAULT 0.0,
    last_restocked DATE,
    expiry_date DATE,
    reorder_qty INTEGER DEFAULT 50
);

-- 6. leave_requests
CREATE TABLE IF NOT EXISTS leave_requests (
    id SERIAL PRIMARY KEY,
    staff_id INTEGER,
    name TEXT,
    role TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'pending'
);

-- 7. performance_reviews
CREATE TABLE IF NOT EXISTS performance_reviews (
    id SERIAL PRIMARY KEY,
    staff_id INTEGER,
    name TEXT,
    role TEXT,
    score INTEGER,
    last_review TEXT
);

-- 8. staff_schedule
CREATE TABLE IF NOT EXISTS staff_schedule (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER NOT NULL,
    shift_date DATE NOT NULL,
    shift_type TEXT NOT NULL,
    status TEXT DEFAULT 'scheduled',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    UNIQUE(employee_id, shift_date, shift_type)
);

-- 9. tasks
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    assigned_to INTEGER,
    status TEXT DEFAULT 'pending',
    priority TEXT DEFAULT 'medium',
    due_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES employees(id)
);

-- 10. training_sessions
CREATE TABLE IF NOT EXISTS training_sessions (
    id SERIAL PRIMARY KEY,
    title TEXT,
    date TEXT,
    enrolled INTEGER
);

COMMIT;