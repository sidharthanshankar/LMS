from flask import Flask
from controller.database import db
import pytz
import os
from controller.config import Config
from controller.models import *
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_login import LoginManager # Add this
from controller.models import User # Ensure User is imported
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()  # This loads the variables from .env
print(f"DEBUG: Password found: {os.environ.get('MAIL_PASSWORD')}")

# 1. Initialize App
app = Flask(__name__)
app.config.from_object(Config)

# 2. Initialize Extensions
mail = Mail(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirects here if @login_required fails

# 3. User Loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# 4. Database Seeding Logic
def seed_data():
    # Only keep the Librarian
    if not User.query.filter_by(role='librarian').first():
        secure_password = generate_password_hash('admin123')
        
        db.session.add(User(
            account_no='LIB001', 
            name='Head Librarian',
            email='admin@library.com', 
            password=secure_password, 
            role='librarian'
        ))
        db.session.commit()
        print("Librarian seeded successfully!")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/profile')
@login_required
def profile():
    # Fetch this specific user's requests
    user_requests = BookRequest.query.filter_by(user_id=current_user.id).order_by(BookRequest.request_date.desc()).all()
    
    # Fetch this specific user's active borrowed books
    active_borrows = Transaction.query.filter_by(user_id=current_user.id, return_date=None).all()
    
    # Fetch history (returned books)
    borrow_history = Transaction.query.filter_by(user_id=current_user.id).filter(Transaction.return_date != None).all()

    return render_template('profile.html', 
                           requests=user_requests, 
                           active_borrows=active_borrows, 
                           history=borrow_history,
                           now=get_ist()) 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        acc_no = request.form.get('account_no')
        role = request.form.get('role')
        plain_password = request.form.get('password')

        # 1. Check if user already exists
        user_exists = User.query.filter_by(account_no=acc_no).first()
        if user_exists:
            flash('Account Number already registered!', 'danger')
            return redirect(url_for('register'))

        # 2. Hash the password for security
        hashed_password = generate_password_hash(plain_password)

        # 3. Create and save user
        new_user = User(
            name=name, 
            email=email, 
            account_no=acc_no, 
            role=role, 
            password=hashed_password
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        acc_no = request.form.get('account_no')
        pwd = request.form.get('password')
        
        user = User.query.filter_by(account_no=acc_no).first()
        
        if user and check_password_hash(user.password, pwd):
            login_user(user)
            
            # --- ADD THIS: Record the visit in the database ---
            new_log = VisitorLog(user_id=user.id)
            db.session.add(new_log)
            db.session.commit()
            
            flash(f'Welcome back, {user.name}!', 'success')
            # Consistent role naming: 'librarian'
            return redirect(url_for('admin_dashboard' if user.role == 'librarian' else 'user_dashboard'))
        
        flash('Invalid Account Number or Password', 'danger')
    return render_template('login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # 1. Authorization Check
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('user_dashboard'))

    # 2. Fetch search query
    search_query = request.args.get('search_user', '')
    
    # 3. Fetch Users
    if search_query:
        users = User.query.filter(User.name.contains(search_query) | User.account_no.contains(search_query)).all()
    else:
        users = User.query.all()
    
    # 4. Fetch Inventory, Requests, and Active Transactions
    all_books = Book.query.all()
    pending_requests = BookRequest.query.filter_by(status='Pending').all()
    transactions = Transaction.query.filter_by(return_date=None).all()

    # 5. Visitor Monitoring (Recent logs)
    recent_logs = VisitorLog.query.order_by(VisitorLog.timestamp.desc()).limit(5).all()
    
    # 6. Today's Visitor Count (Handled safely for 2026 standards)
    # We strip the timezone info (.replace(tzinfo=None)) to match typical DB storage
    now_ist = get_ist()
    today_start = now_ist.replace(hour=0, minute=0, second=0, microsecond=0).replace(tzinfo=None)
    visitor_count = VisitorLog.query.filter(VisitorLog.timestamp >= today_start).count()
    
    # 7. Optimized Fine Calculation
    # FIX: Use the property from the model instead of manual loop to reduce logic errors
    live_fines = sum(txn.calculate_fine for txn in transactions)
    
    # 8. Stats
    stats = {
        'total_books': Book.query.count(),
        'total_students': User.query.filter_by(role='student').count(),
        'total_staff': User.query.filter_by(role='staff').count(),
        'total_fines': live_fines,
        'visitor_count': visitor_count
    }

    # 9. Return Template
    return render_template('admin_dashboard.html', 
                           users=users, 
                           books=all_books, 
                           pending_requests=pending_requests, 
                           transactions=transactions,
                           recent_logs=recent_logs,
                           search_query=search_query,
                           stats=stats,
                           now=get_ist().replace(tzinfo=None))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'librarian':
        return redirect(url_for('user_dashboard'))
    
    user_to_delete = User.query.get_or_404(user_id)
    
    # Safety Check: Don't let the librarian delete themselves!
    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own admin account.", "danger")
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"Member {user_to_delete.name} removed successfully.", "success")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/manage_request/<int:req_id>/<string:action>')
@login_required
def manage_request(req_id, action):
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))
        
    req = BookRequest.query.get_or_404(req_id)
    
    if action == 'approve':
        if req.book.copies > 0:
            req.status = 'Approved'
            req.book.copies -= 1
            
            # --- FIXED TIME LOGIC ---
            now_in_india = get_ist()
            
            new_txn = Transaction(
                user_id=req.user_id,
                book_id=req.book_id,
                issue_date=now_in_india, 
                due_date=now_in_india + timedelta(days=14)
            )
            # ------------------------
            
            db.session.add(new_txn)
            
            try:
                msg = Message(subject="Book Request Approved!",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[req.user.email])
                msg.body = f"Hello {req.user.name},\n\nYour request for '{req.book.title}' has been approved!\nDue Date: {new_txn.due_date.strftime('%d-%b-%Y')}."
                mail.send(msg)
            except Exception as e:
                print(f"Email error: {e}")
                
            flash(f"Approved! {req.book.title} issued to {req.user.name}.", "success")
        else:
            flash(f"Failed! No copies of '{req.book.title}' available.", "danger")

    elif action == 'reject':
        req.status = 'Rejected'
        flash(f"Request for {req.book.title} has been rejected.", "warning")
        
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/join_waitlist/<int:book_id>', methods=['POST'])
@login_required
def join_waitlist(book_id):
    book = Book.query.get_or_404(book_id)
    
    # Check if already waiting or already requested
    already_waiting = Waitlist.query.filter_by(user_id=current_user.id, book_id=book.id).first()
    if already_waiting:
        flash("You are already on the waiting list for this book.", "info")
        return redirect(url_for('user_dashboard'))
        
    new_wait = Waitlist(user_id=current_user.id, book_id=book.id)
    db.session.add(new_wait)
    db.session.commit()
    flash(f"You have joined the waitlist for '{book.title}'. We will email you when it's returned!", "success")
    return redirect(url_for('user_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role == 'librarian':
        return redirect(url_for('admin_dashboard'))

    search_query = request.args.get('search_book', '')
    if search_query:
        all_books = Book.query.filter(
            (Book.title.ilike(f'%{search_query}%')) | 
            (Book.author.ilike(f'%{search_query}%')) |
            (Book.isbn.ilike(f'%{search_query}%'))
        ).all()
    else:
        all_books = Book.query.all()

    my_books = Transaction.query.filter_by(user_id=current_user.id, return_date=None).all()
    
    # FIX: Use the property from the model to avoid the subtraction crash
    total_my_fine = sum(txn.calculate_fine for txn in my_books)
    now = get_ist()

    # Pass 'books' instead of 'inventory' to match your HTML template
    return render_template('user_dashboard.html', 
                           books=all_books, 
                           my_books=my_books, 
                           total_fine=total_my_fine, 
                           search_query=search_query,
                           now=get_ist().replace(tzinfo=None))


@app.route('/visitor-history')
@login_required
def visitor_history():
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('user_dashboard'))
    
    # This fetches all records and passes them to your template
    all_logs = VisitorLog.query.order_by(VisitorLog.timestamp.desc()).all()
    return render_template('visitor_history.html', all_logs=all_logs)

@app.route('/clear-visitor-history', methods=['POST'])
@login_required
def clear_visitor_history():
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))
    
    try:
        # Deletes all rows in the VisitorLog table
        VisitorLog.query.delete()
        db.session.commit()
        flash("Library history has been successfully cleared for the new session.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error: Could not clear history.", "danger")
        print(f"Database Error: {e}")
        
    return redirect(url_for('visitor_history'))

@app.route('/browse_books')
def browse_books():
    search_query = request.args.get('search', '')
    if search_query:
        books = Book.query.filter(Book.title.contains(search_query) | Book.author.contains(search_query)).all()
    else:
        books = Book.query.all()
    # Ensure this points to your NEW browse_books.html file, NOT index.html
    return render_template('browse_books.html', books=books)


@app.route('/request_book/<int:book_id>', methods=['POST'])
@login_required
def request_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    existing_request = BookRequest.query.filter_by(
        user_id=current_user.id, 
        book_id=book_id, 
        status='Pending'
    ).first()
    
    if existing_request:
        flash(f"You already have a pending request for '{book.title}'.", "warning")
    else:
        new_req = BookRequest(user_id=current_user.id, book_id=book_id, status='Pending')
        db.session.add(new_req)
        db.session.commit()
        flash(f"Request for '{book.title}' sent to Librarian!", "success")
    
    # FIX: Redirect back to user_dashboard instead of browse_books
    return redirect(url_for('user_dashboard'))

@app.route('/cancel_request/<int:req_id>', methods=['POST'])
@login_required
def cancel_request(req_id):
    req = BookRequest.query.get_or_404(req_id)
    if req.user_id == current_user.id and req.status == 'Pending':
        db.session.delete(req)
        db.session.commit()
        flash("Request cancelled successfully.", "info")
    return redirect(url_for('profile'))

@app.route('/add_book', methods=['POST'])
@login_required
def add_book():
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))
        
    # 1. Fetch data from form (Matching your HTML 'name' attributes)
    title = request.form.get('title')
    author = request.form.get('author')
    isbn = request.form.get('isbn')
    copies_val = request.form.get('copies')
    
    # 2. Safety Check for empty fields
    if not all([title, author, isbn, copies_val]):
        flash("All fields are required!", "warning")
        return redirect(url_for('admin_dashboard'))

    try:
        copies = int(copies_val)
        # Check if ISBN already exists to prevent a crash
        existing_book = Book.query.filter_by(isbn=isbn).first()
        if existing_book:
            existing_book.copies += copies # Increase stock if book exists
            flash(f"Updated stock for '{title}'. Total copies: {existing_book.copies}", "info")
        else:
            new_book = Book(title=title, author=author, isbn=isbn, copies=copies)
            db.session.add(new_book)
            flash(f"Book '{title}' added to inventory!", "success")
            
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"Database Error: {str(e)}", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/issue_book', methods=['POST'])
@login_required
def issue_book():
    if current_user.role != 'librarian':
        flash("Unauthorized!", "danger")
        return redirect(url_for('index'))
    
    account_no = request.form.get('account_no')
    isbn = request.form.get('isbn')
    
    # 1. Validate existence
    user = User.query.filter_by(account_no=account_no).first()
    book = Book.query.filter_by(isbn=isbn).first()

    if not user:
        flash(f"Error: Account '{account_no}' not found.", "danger")
    elif not book:
        flash(f"Error: ISBN '{isbn}' not found.", "danger")
    elif book.copies < 1:
        flash(f"Error: '{book.title}' is out of stock!", "warning")
    else:
        try:
            # NEW FEATURE: Capture the exact Indian time for the record
            india_now = get_ist()
            
            # Preplanning: Check if the student already has an active copy of THIS book
            active_txn = Transaction.query.filter_by(user_id=user.id, book_id=book.id, return_date=None).first()
            if active_txn:
                flash(f"Error: {user.name} already has an unreturned copy of this book.", "warning")
                return redirect(url_for('admin_dashboard'))

            # 2. Process Issue
            book.copies -= 1
            
            # Calculate due date: 15 days from now in IST
            future_due_date = india_now + timedelta(days=14)
            
            new_txn = Transaction(
                user_id=user.id,
                book_id=book.id,
                issue_date=india_now,
                due_date=future_due_date
            )
            
            db.session.add(new_txn)
            db.session.commit()
            
            # Format time for the flash message to look professional
            formatted_time = india_now.strftime('%I:%M %p')
            flash(f"Success! {book.title} issued to {user.name} at {formatted_time}.", "success")
            
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while issuing the book.", "danger")
            print(f"Issue Error: {e}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/send_reminder/<int:transaction_id>')
@login_required
def send_reminder(transaction_id):
    # 1. Authorization Check
    if current_user.role != 'librarian':
        flash("Unauthorized!", "danger")
        return redirect(url_for('index'))

    txn = db.session.get(Transaction, transaction_id)
    
    # 2. Safety Check 1: Does the transaction exist?
    if not txn:
        flash("Transaction not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    # 3. Safety Check 2: Don't remind for books already back!
    if txn.return_date:
        flash("Cannot send reminder for a returned book.", "warning")
        return redirect(url_for('admin_dashboard'))
        
    # 4. The Actual Email Logic
    try:
        fine = txn.calculate_fine
        msg = Message(
            subject=f"Manual Reminder: '{txn.book.title}' is Overdue",
            sender=app.config['MAIL_USERNAME'],
            recipients=[txn.user.email]
        )
        msg.body = f"Hello {txn.user.name},\n\nThis is a direct reminder from the librarian. The book '{txn.book.title}' was due on {txn.due_date.strftime('%d-%m-%Y')}.\nCurrent Fine: ₹{fine}.\n\nPlease return it to the library immediately."
        
        mail.send(msg)
        
        # Update our pre-planned tracking flag
        txn.reminder_sent = True
        db.session.commit()
        
        flash(f"Reminder sent to {txn.user.name} for '{txn.book.title}'.", "success")
    except Exception as e:
        print(f"Failed manual email to {txn.user.email}: {e}")
        flash("Error sending email. Please check server logs.", "danger")
        
    # 5. The crucial final return statement to prevent crashes
    return redirect(url_for('admin_dashboard'))

@app.route('/run_daily_notifications', methods=['POST'])
@login_required
def run_daily_notifications():
    if current_user.role != 'librarian':
        flash("Unauthorized!", "danger")
        return redirect(url_for('index'))

    now = get_ist().replace(tzinfo=None)
    # Find all books that are overdue and not yet returned
    overdue_txns = Transaction.query.filter(
        Transaction.return_date == None,
        Transaction.due_date < now
    ).all()

    if not overdue_txns:
        flash("No overdue books found today.", "info")
        return redirect(url_for('admin_dashboard'))

    sent_count = 0
    for txn in overdue_txns:
        try:
            # Using your model property for the fine
            fine = txn.calculate_fine 
            
            msg = Message(
                subject=f"Library Overdue Reminder: {txn.book.title}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[txn.user.email]
            )
            msg.body = f"Hello {txn.user.name},\n\nThis is a reminder that '{txn.book.title}' is overdue.\nDue Date: {txn.due_date.strftime('%d-%m-%Y')}\nCurrent Fine: ₹{fine}.\n\nPlease return it to the library."
            
            mail.send(msg)
            
            # Update the flag we preplanned in models.py
            txn.reminder_sent = True 
            sent_count += 1
        except Exception as e:
            print(f"Failed email to {txn.user.email}: {e}")

    db.session.commit() # Save the 'reminder_sent' updates
    flash(f"Success! {sent_count} members notified.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/return_book/<int:transaction_id>', methods=['POST'])
@login_required
def return_book(transaction_id):
    if current_user.role != 'librarian':
        return "Unauthorized", 403

    txn = db.session.get(Transaction, transaction_id)
    if not txn or txn.return_date:
        flash('Invalid transaction or book already returned.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # 1. Update return date
    txn.return_date = get_ist()
    
    # 2. Calculate Fine (₹5 per day)
    fine = 0
    if txn.return_date > txn.due_date:
        overdue_days = (txn.return_date - txn.due_date).days
        fine = overdue_days * 5
    
    # 3. Put book back in stock
    book = db.session.get(Book, txn.book_id)
    # FIXED: Changed 'available_copies' to 'copies' to match your model
    book.copies += 1

    # --- NEW WAITLIST CHECKER ---
    next_in_line = Waitlist.query.filter_by(book_id=book.id).order_by(Waitlist.date_joined.asc()).first()
    if next_in_line:
        try:
            msg = Message(subject="Waitlist Alert: Book Available!",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[next_in_line.user.email])
            msg.body = f"Hello {next_in_line.user.name},\n\nGreat news! The book '{book.title}' you were waiting for has just been returned. Please log in to request it before someone else does!"
            mail.send(msg)
            
            # Remove them from waitlist since they've been notified
            db.session.delete(next_in_line) 
        except Exception as e:
            print(f"Waitlist Email Error: {e}")
    # ----------------------------

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
    with app.app_context():
        db.create_all()
        seed_data()
    app.run(debug=True)