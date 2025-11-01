# models.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Announcement(db.Model):
    __tablename__ = 'announcements'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)      # general|urgent|policy|meeting
    target_role = db.Column(db.String(50), nullable=False)   # all|doctor|nurse|receptionist
    pinned = db.Column(db.Boolean, default=False)
    author = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Announcement {self.id}: {self.title}>'