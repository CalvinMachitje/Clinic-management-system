# scheduler.py
from apscheduler.schedulers.background import BackgroundScheduler
from utils.backup import backup_database
from utils.reminders import send_reminders
from utils.reports import generate_daily_report

def start_scheduler():
    scheduler = BackgroundScheduler()
    
    scheduler.add_job(backup_database, 'interval', hours=6)
    scheduler.add_job(send_reminders, 'cron', hour=8, minute=0)  # 8 AM daily
    scheduler.add_job(generate_daily_report, 'cron', hour=20, minute=0)  # 8 PM
    scheduler.add_job(cleanup_old_logs, 'cron', hour=2, minute=0)  # 2 AM
    
    scheduler.start()