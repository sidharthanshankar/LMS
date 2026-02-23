from .database import db
from datetime import datetime, timedelta
from flask_login import UserMixin

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
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)

    reminder_sent = db.Column(db.Boolean, default=False)

    # Relationships - Defined only once per link
    user = db.relationship('User', backref='transactions', lazy=True)
    book = db.relationship('Book', backref='transactions', lazy=True)

    @property
    def calculate_fine(self):
        end_date = self.return_date if self.return_date else datetime.utcnow()
        if end_date > self.due_date:
            overdue_days = (end_date - self.due_date).days
            return overdue_days * 5
        return 0
    
class BookRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')

    user = db.relationship('User', backref='book_requests', lazy=True)
    book = db.relationship('Book', backref='book_requests', lazy=True)

class Waitlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='waitlists', lazy=True)
    book = db.relationship('Book', backref='waitlists', lazy=True)