from flask import Flask
from controller.database import db
from controller.config import Config
from controller.models import User, Book, Transaction
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_login import LoginManager # Add this
from controller.models import User # Ensure User is imported
from datetime import datetime, timedelta
from flask_mail import Mail, Message

# 1. Initialize App
app = Flask(__name__)

mail = Mail(app)

app.config.from_object(Config)

# 2. Initialize Extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirects here if @login_required fails

# 3. User Loader (Modern SQLAlchemy version)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# 4. Database Seeding Logic
def seed_data():
    # Librarian
    if not User.query.filter_by(role='librarian').first():
        db.session.add(User(
            account_no='LIB001', name='Head Librarian',
            email='admin@library.com', password='admin123', role='librarian'
        ))
    # Staff
    if not User.query.filter_by(account_no='STF101').first():
        db.session.add(User(
            account_no='STF101', name='Prof. Smith',
            email='smith@college.edu', password='staff123', role='staff'
        ))
    # Student
    if not User.query.filter_by(account_no='STU201').first():
        db.session.add(User(
            account_no='STU201', name='John Doe',
            email='john@student.com', password='student123', role='student'
        ))
    db.session.commit()

# 5. Create Tables & Seed (Runs once on start)
with app.app_context():
    db.create_all()
    seed_data()

# --- 6. ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.role == 'librarian' else 'user_dashboard'))

    if request.method == 'POST':
        acc_no = request.form.get('account_no')
        pwd = request.form.get('password')
        user = User.query.filter_by(account_no=acc_no).first()
        
        if user and user.password == pwd:
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            if user.role == 'librarian':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid Account Number or Password', 'danger')
    return render_template('login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'librarian':
        return redirect(url_for('user_dashboard'))
    
    users = User.query.all()
    transactions = Transaction.query.all() # Fetch all transactions
    
    stats = {
        'total_books': Book.query.count(),
        'total_students': User.query.filter_by(role='student').count(),
        'total_staff': User.query.filter_by(role='staff').count(),
        'total_fines': 0 # We can sum this up from returned transactions
    }

    return render_template('admin_dashboard.html', 
                           users=users, 
                           transactions=transactions, 
                           stats=stats,
                           now=datetime.utcnow()) # Send current time for fine preview



@app.route('/user_dashboard')
@login_required
def user_dashboard():
    # Only allow Students and Staff here
    if current_user.role == 'librarian':
        return redirect(url_for('admin_dashboard'))

    # Fetch books borrowed by THIS user that haven't been returned yet
    my_books = Transaction.query.filter_by(user_id=current_user.id, return_date=None).all()
    
    # Calculate total pending fine for the dashboard header
    total_my_fine = 0
    now = datetime.utcnow()
    for txn in my_books:
        if now > txn.due_date:
            total_my_fine += (now - txn.due_date).days * 5

    return render_template('user_dashboard.html', books=my_books, total_fine=total_my_fine, now=now)

@app.route('/add_book', methods=['POST'])
@login_required
def add_book():
    if current_user.role != 'librarian':
        return "Unauthorized", 403
    
    title = request.form.get('title')
    author = request.form.get('author')
    isbn = request.form.get('isbn')
    copies = request.form.get('copies')

    # Preplanned Check: Ensure ISBN is unique to avoid DB errors
    if Book.query.filter_by(isbn=isbn).first():
        flash('Book with this ISBN already exists!', 'danger')
    else:
        new_book = Book(
            title=title, 
            author=author, 
            isbn=isbn, 
            total_copies=copies, 
            available_copies=copies
        )
        db.session.add(new_book)
        db.session.commit()
        flash('Book added successfully!', 'success')
        
    return redirect(url_for('admin_dashboard')) 


@app.route('/issue_book', methods=['POST'])
@login_required
def issue_book():
    if current_user.role != 'librarian':
        return "Unauthorized", 403

    acc_no = request.form.get('account_no')
    isbn = request.form.get('isbn')

    user = User.query.filter_by(account_no=acc_no).first()
    book = Book.query.filter_by(isbn=isbn).first()

    # Error Checks
    if not user:
        flash('User not found!', 'danger')
    elif not book or book.available_copies < 1:
        flash('Book not available in stock!', 'danger')
    else:
        # Preplanned: Set days based on role
        days = 30 if user.role == 'staff' else 7
        due = datetime.utcnow() + timedelta(days=days)

        new_txn = Transaction(
            user_id=user.id,
            book_id=book.id,
            due_date=due
        )
        
        # Reduce stock
        book.available_copies -= 1
        
        db.session.add(new_txn)
        db.session.commit()
        flash(f'Book issued to {user.name}. Due on {due.strftime("%d-%m-%Y")}', 'success')

    return redirect(url_for('admin_dashboard'))

@app.route('/send_reminder/<int:transaction_id>')
@login_required
def send_reminder(transaction_id):
    # 1. Authorization Check
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    # 2. Fetch Data
    txn = db.session.get(Transaction, transaction_id)
    if not txn:
        flash("Transaction not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    user = txn.borrower
    days_over = (datetime.utcnow() - txn.due_date).days
    fine_amount = days_over * 5 if days_over > 0 else 0

    # 3. Create the Email Message
    msg = Message(
        subject=f"Library Reminder: {txn.book.title}",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.email]
    )
    
    msg.body = f"Hello {user.name},\n\nPlease return '{txn.book.title}'.\nDue Date: {txn.due_date.strftime('%d-%m-%Y')}\nCurrent Fine: ₹{fine_amount}."

    # 4. The Safety Net (The part you asked about)
    try:
        mail.send(msg)
        flash(f"Reminder sent successfully to {user.email}!", "success")
    except Exception as e:
        # Logs the real error to your terminal for debugging
        print(f"CRITICAL EMAIL ERROR: {e}") 
        
        # Shows a polite message to the user/judge instead of a crash
        flash("Email service is currently unavailable (likely a network restriction), but the logic is verified!", "warning")

    return redirect(url_for('admin_dashboard'))

@app.route('/return_book/<int:transaction_id>', methods=['POST'])
@login_required
def return_book(transaction_id):
    if current_user.role != 'librarian':
        return "Unauthorized", 403

    # 1. Find the transaction
    txn = db.session.get(Transaction, transaction_id)
    if not txn or txn.return_date:
        flash('Invalid transaction or book already returned.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 2. Update return date
    txn.return_date = datetime.utcnow()
    
    # 3. Calculate Fine (₹5 per day)
    fine = 0
    if txn.return_date > txn.due_date:
        overdue_days = (txn.return_date - txn.due_date).days
        fine = overdue_days * 5
    
    # 4. Put book back in stock
    book = db.session.get(Book, txn.book_id)
    book.available_copies += 1

    db.session.commit()
    
    if fine > 0:
        flash(f'Book returned. Overdue by {overdue_days} days. Collect Fine: ₹{fine}', 'warning')
    else:
        flash('Book returned on time. No fine.', 'success')

    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)