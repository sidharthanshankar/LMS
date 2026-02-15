from .database import db
from datetime import datetime, timedelta
from flask_login import UserMixin # <--- Add this import

class User(db.Model, UserMixin): # <--- Add UserMixin here
    id = db.Column(db.Integer, primary_key=True)
    account_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'librarian', 'staff', 'student'
    
    rentals = db.relationship('Transaction', backref='borrower', lazy=True)

# ... keep Book and Transaction models the same as we wrote earlier ...

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    isbn = db.Column(db.String(13), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100))
    total_copies = db.Column(db.Integer, default=1)
    available_copies = db.Column(db.Integer, default=1)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True) # Null until returned
    reminder_sent = db.Column(db.Boolean, default=False)

    @property
    def calculate_fine(self):
        """Dynamic Fine Logic: ₹5.00/day"""
        # If not returned, compare due_date with 'today'
        # If returned, compare due_date with 'return_date'
        end_date = self.return_date if self.return_date else datetime.utcnow()
        
        if end_date > self.due_date:
            overdue_days = (end_date - self.due_date).days
            return overdue_days * 5  # Updated to ₹5
        return 0
    
class BookRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending') # Pending, Approved, Rejected

    # Relationships
    user = db.relationship('User', backref='requests')
    book = db.relationship('Book', backref='requests')

    def __repr__(self):
        return f'<Request: User {self.user_id} -> Book {self.book_id} [{self.status}]>'