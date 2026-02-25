from .database import db
from datetime import datetime, timedelta
import pytz
from flask_login import UserMixin

def get_ist():
    """Returns Indian Standard Time without the timezone 'baggage'"""
    return datetime.now(pytz.timezone('Asia/Kolkata')).replace(tzinfo=None)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    account_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(20), unique=True, nullable=False)
    copies = db.Column(db.Integer, default=1) 
    # FIX: Changed to get_ist
    date_added = db.Column(db.DateTime, default=get_ist)

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # FIX: Changed to get_ist
    timestamp = db.Column(db.DateTime, default=get_ist)
    
    user = db.relationship('User', backref=db.backref('logs', lazy=True))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    # FIX: Changed to get_ist
    issue_date = db.Column(db.DateTime, default=get_ist)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)
    reminder_sent = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='transactions', lazy=True)

    book = db.relationship('Book', backref='transactions', lazy=True)
    
    @property
    def calculate_fine(self):
       now = get_ist().replace(tzinfo=None) # Ensure this is naive
       end_date = self.return_date if self.return_date else now
    
    # Ensure end_date is naive
       end_date_naive = end_date.replace(tzinfo=None)
       due_date_naive = self.due_date.replace(tzinfo=None)

       if end_date_naive > due_date_naive:
        return (end_date_naive - due_date_naive).days * 5
       return 0

class BookRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    # FIX: Changed to get_ist
    request_date = db.Column(db.DateTime, default=get_ist)
    status = db.Column(db.String(20), default='Pending')

    user = db.relationship('User', backref='book_requests', lazy=True)
    book = db.relationship('Book', backref='book_requests', lazy=True)

class Waitlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    # FIX: Changed to get_ist
    date_joined = db.Column(db.DateTime, default=get_ist)

    user = db.relationship('User', backref='waitlists', lazy=True)
    book = db.relationship('Book', backref='waitlists', lazy=True)