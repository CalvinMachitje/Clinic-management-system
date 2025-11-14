# utils/backup.py
import os
import shutil
from datetime import datetime
from models import db
import sqlalchemy

def backup_database():
    backup_dir = "backups"
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"clinic_backup_{timestamp}.db")
    
    # For SQLite
    if db.engine.url.drivername == 'sqlite':
        shutil.copy2(db.engine.url.database, backup_path)
    
    # For PostgreSQL (later)
    elif db.engine.url.drivername.startswith('postgresql'):
        import subprocess
        cmd = [
            "pg_dump",
            f"--dbname={db.engine.url.database}",
            f"--username={db.engine.url.username}",
            f"--host={db.engine.url.host}",
            f"--port={db.engine.url.port or 5432}",
            f"--file={backup_path}.sql"
        ]
        subprocess.run(cmd, env={**os.environ, "PGPASSWORD": db.engine.url.password})
    
    print(f"Backup created: {backup_path}")
    keep_last_n_backups(backup_dir, keep=10)  # Keep only 10

def keep_last_n_backups(directory, keep=10):
    files = sorted(
        [f for f in os.listdir(directory) if f.startswith("clinic_backup")],
        key=lambda x: os.path.getmtime(os.path.join(directory, x)),
        reverse=True
    )
    for old in files[keep:]:
        os.remove(os.path.join(directory, old))