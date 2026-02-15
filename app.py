from flask import Flask
from controller.database import db
from controller.config import Config
from controller.models import *
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_login import LoginManager # Add this
from controller.models import User # Ensure User is imported
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

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
                           now=datetime.utcnow()) 

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
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('admin_dashboard' if user.role == 'librarian' else 'user_dashboard'))
        
        flash('Invalid Account Number or Password', 'danger')
    return render_template('login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # 1. Fetch search query
    search_query = request.args.get('search_user', '')
    
    # 2. Fetch Users (with search filter)
    if search_query:
        users = User.query.filter(User.name.contains(search_query) | User.account_no.contains(search_query)).all()
    else:
        users = User.query.all()
    
    # 3. Fetch Pending Requests
    pending_requests = BookRequest.query.filter_by(status='Pending').all()
    
    # 4. Fetch Active Transactions
    transactions = Transaction.query.filter_by(return_date=None).all()
    
    # --- START OF FINE CALCULATION ---
    current_time = datetime.utcnow()
    live_fines = 0
    for txn in transactions:
        if current_time > txn.due_date:
            days_overdue = (current_time - txn.due_date).days
            live_fines += (days_overdue * 5)  # ₹5 per day
    # --- END OF FINE CALCULATION ---
    
    # 5. Stats
    stats = {
        'total_books': Book.query.count(),
        'total_students': User.query.filter_by(role='student').count(),
        'total_staff': User.query.filter_by(role='staff').count(),
        'total_fines': live_fines # Now reflects the live calculation
    }

    return render_template('admin_dashboard.html', 
                           users=users, 
                           pending_requests=pending_requests, 
                           transactions=transactions,
                           search_query=search_query,
                           stats=stats,
                           now=current_time)

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
            
            # Record both Issue and Due dates to keep history accurate
            new_txn = Transaction(
                user_id=req.user_id,
                book_id=req.book_id,
                issue_date=datetime.utcnow(),
                due_date=datetime.utcnow() + timedelta(days=14)
            )
            db.session.add(new_txn)
            flash(f"Approved! {req.book.title} issued to {req.user.name}.", "success")
        else:
            flash("Error: Out of stock!", "danger")
            
    elif action == 'reject':
        req.status = 'Rejected'
        flash(f"Request for {req.book.title} rejected.", "info")
        
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

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
    
    # Calculate total fine for display
    total_my_fine = 0
    now = datetime.utcnow()
    for txn in my_books:
        if now > txn.due_date:
            total_my_fine += (now - txn.due_date).days * 5

    # Pass 'books' instead of 'inventory' to match your HTML template
    return render_template('user_dashboard.html', 
                           books=all_books, 
                           my_books=my_books, 
                           total_fine=total_my_fine, 
                           search_query=search_query,
                           now=now)

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
    # 1. Verification
    book = Book.query.get_or_404(book_id)
    
    # 2. Prevent Duplicate Pending Requests
    existing_request = BookRequest.query.filter_by(
        user_id=current_user.id, 
        book_id=book_id, 
        status='Pending'
    ).first()
    
    if existing_request:
        flash(f"You already have a pending request for '{book.title}'.", "warning")
    else:
        # 3. Create the Database Record
        # Ensure your Model uses 'Pending' as the default status
        new_req = BookRequest(user_id=current_user.id, book_id=book_id, status='Pending')
        db.session.add(new_req)
        db.session.commit()
        flash(f"Request for '{book.title}' sent to Librarian!", "success")
    
    # 4. Redirect (Choose one)
    return redirect(url_for('browse_books'))

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
            # 2. Process Issue
            book.copies -= 1
            new_txn = Transaction(
                user_id=user.id,
                book_id=book.id,
                issue_date=datetime.utcnow(),
                due_date=datetime.utcnow() + timedelta(days=14)
            )
            db.session.add(new_txn)
            db.session.commit()
            flash(f"Success! {book.title} issued to {user.name}.", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while issuing the book.", "danger")
            print(f"Issue Error: {e}")
        
    return redirect(url_for('admin_dashboard'))


@app.route('/send_reminder/<int:transaction_id>')
@login_required
def send_reminder(transaction_id):
    if current_user.role != 'librarian':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('index'))

    txn = db.session.get(Transaction, transaction_id)
    if not txn:
        flash("Transaction not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    # FIXED: Changed 'txn.borrower' to 'txn.user'
    user = txn.user 
    days_over = (datetime.utcnow() - txn.due_date).days
    fine_amount = days_over * 5 if days_over > 0 else 0

    msg = Message(
        subject=f"Library Reminder: {txn.book.title}",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.email]
    )
    
    msg.body = f"Hello {user.name},\n\nPlease return '{txn.book.title}'.\nDue Date: {txn.due_date.strftime('%d-%m-%Y')}\nCurrent Fine: ₹{fine_amount}."

    try:
        mail.send(msg)
        flash(f"Reminder sent successfully to {user.email}!", "success")
    except Exception as e:
        print(f"CRITICAL EMAIL ERROR: {e}") 
        flash("Email service is currently unavailable.", "warning")

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
    txn.return_date = datetime.utcnow()
    
    # 2. Calculate Fine (₹5 per day)
    fine = 0
    if txn.return_date > txn.due_date:
        overdue_days = (txn.return_date - txn.due_date).days
        fine = overdue_days * 5
    
    # 3. Put book back in stock
    book = db.session.get(Book, txn.book_id)
    # FIXED: Changed 'available_copies' to 'copies' to match your model
    book.copies += 1

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