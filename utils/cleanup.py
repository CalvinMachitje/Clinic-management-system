# utils/cleanup.py
import os
from datetime import datetime, timedelta

def cleanup_old_logs():
    log_dir = "logs"
    cutoff = datetime.now() - timedelta(days=30)
    for f in os.listdir(log_dir):
        path = os.path.join(log_dir, f)
        if os.path.getmtime(path) < cutoff.timestamp():
            os.remove(path)