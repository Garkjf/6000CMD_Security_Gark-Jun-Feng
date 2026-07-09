from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
from datetime import datetime, timedelta
from functools import wraps
import re
import bleach
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(APP_DIR, 'database.db')
UPLOAD_FOLDER = os.path.join(APP_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = app.config['SECRET_KEY']
app.permanent_session_lifetime = timedelta(hours=1)
csrf = CSRFProtect(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'customer', -- customer, seller, admin
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS seller_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            business_name TEXT NOT NULL,
            reason TEXT,
            status TEXT DEFAULT 'pending', -- pending, approved, rejected
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            image_url TEXT,
            stock INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'placed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            seller_id INTEGER,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            rating INTEGER CHECK (rating BETWEEN 1 AND 5),
            body TEXT,
            image_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL, -- 'customer','seller','admin'
            user_id INTEGER,
            action TEXT NOT NULL,
            meta TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            path TEXT,
            user_agent TEXT, 
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

# Security 
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Validation and Sanitization
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,30}$')
EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

def validate_username(username):
    return bool(USERNAME_RE.match(username))


def validate_email(email):
    return bool(EMAIL_RE.match(email))


def validate_password_strength(pw):
    if len(pw) < 8:
        return False, 'Password must be at least 8 characters.'
    if not re.search(r'\d', pw):
        return False, 'Password must include at least one number.'
    if not re.search(r'[A-Za-z]', pw):
        return False, 'Password must include at least one letter.'
    return True, ''


def sanitize_text(user_text, allowed_tags=None):
    if allowed_tags is None:
        allowed_tags = ['b', 'i', 'strong', 'em', 'ul', 'ol', 'li', 'p']
    return bleach.clean(user_text or '', tags=allowed_tags, strip=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Authorization decorators 
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def seller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['seller', 'admin']:
            flash('You must be a seller or admin to access that page.')
            return redirect(url_for('profile'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin only area.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# Logging  
def log_action(user_type, user_id, action, meta=None):
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO system_logs (user_type, user_id, action, meta) VALUES (?, ?, ?, ?)',
                     (user_type, user_id, action, meta))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error('Failed to write log: %s', e)


@app.before_request
def track_page_view():
    path = request.path
    if path.startswith('/static') or path.startswith('/uploads'):
        return
    user_id = session.get('user_id')
    ua = request.headers.get('User-Agent')
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO page_views (user_id, path, user_agent) VALUES (?, ?, ?)',
                     (user_id, path, ua))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.debug('analytics error: %s', e)


# Public routes 
@app.route('/')
def index():
    q = request.args.get('q', '').strip()
    conn = get_db_connection()
    if q:
        products = conn.execute("SELECT p.*, u.username AS seller_name FROM products p LEFT JOIN users u ON p.seller_id=u.id WHERE p.name LIKE ? OR p.description LIKE ?", (f'%{q}%', f'%{q}%')).fetchall()
    else:
        products = conn.execute('SELECT p.*, u.username AS seller_name FROM products p LEFT JOIN users u ON p.seller_id=u.id').fetchall()
    conn.close()
    return render_template('index.html', products=products, q=q, username=session.get('username'))

@app.route('/about')
def about():
     return render_template('about.html')


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT p.*, u.username AS seller_name FROM products p LEFT JOIN users u ON p.seller_id=u.id WHERE p.id=?', (product_id,)).fetchone()
    reviews = conn.execute('SELECT r.*, u.username FROM reviews r JOIN users u ON r.user_id=u.id WHERE r.product_id=? ORDER BY r.created_at DESC', (product_id,)).fetchall()
    conn.close()
    if not product:
        return 'Product not found', 404
    return render_template('product.html', product=product, reviews=reviews)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not email or not password:
            return render_template('signup.html', error='All fields required')
        if not validate_username(username):
            return render_template('signup.html', error='Invalid username')
        if not validate_email(email):
            return render_template('signup.html', error='Invalid email')
        ok, msg = validate_password_strength(password)
        if not ok:
            return render_template('signup.html', error=msg)
        if password != confirm:
            return render_template('signup.html', error='Passwords do not match')

        username = bleach.clean(username, tags=[], strip=True)
        email = bleach.clean(email, tags=[], strip=True)

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                         (username, generate_password_hash(password), email))
            conn.commit()
            user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            session.clear()
            session['user_id'] = user['id']
            session['username'] = username
            session['role'] = 'customer'
            log_action('customer', user['id'], 'Signed up')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error='Username already exists')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        username = bleach.clean(username, tags=[], strip=True)
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if not user or not check_password_hash(user['password_hash'], pw):
            return render_template('login.html', error='Invalid credentials')
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        app.permanent_session = True
        log_action(session['role'], user['id'], 'Logged in')
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        log_action(session.get('role', 'customer'), session['user_id'], 'Logged out')
    session.clear()
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    seller_request = conn.execute('''
        SELECT * FROM seller_requests 
        WHERE user_id=? AND status='pending' 
        ORDER BY created_at DESC LIMIT 1
    ''', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user, seller_request=seller_request)

@app.route('/upgrade_to_seller', methods=['GET', 'POST'])
@login_required
def upgrade_to_seller():
    if session.get('role') == 'seller':
        return redirect(url_for('seller_dashboard'))

    if request.method == 'POST':
        business_name = bleach.clean(request.form.get('business_name', ''), tags=[], strip=True)
        reason = bleach.clean(request.form.get('reason', ''), tags=[], strip=True)
        
        conn = get_db_connection()

        existing = conn.execute("SELECT * FROM seller_requests WHERE user_id=? AND status='pending'", (session['user_id'],)).fetchone()
        
        if not existing:
            conn.execute('INSERT INTO seller_requests (user_id, business_name, reason) VALUES (?, ?, ?)',
                         (session['user_id'], business_name, reason))
            conn.commit()
            log_action('customer', session['user_id'], 'Requested seller upgrade')
            flash('Application submitted! Please wait for admin approval.')
        else:
            flash('You already have a pending application.')
            
        conn.close()
        return redirect(url_for('profile'))

    return render_template('upgrade_to_seller.html')


# Cart & Orders 
@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    product_id = int(request.form.get('product_id'))
    qty = int(request.form.get('quantity', 1))
    conn = get_db_connection()
    product = conn.execute('SELECT stock FROM products WHERE id=?', (product_id,)).fetchone()
    if not product or product['stock'] < qty:
        conn.close()
        flash('Not enough stock')
        return redirect(url_for('product_detail', product_id=product_id))
    existing = conn.execute('SELECT * FROM cart WHERE user_id=? AND product_id=?', (session['user_id'], product_id)).fetchone()
    if existing:
        conn.execute('UPDATE cart SET quantity=quantity+? WHERE id=?', (qty, existing['id']))
    else:
        conn.execute('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', (session['user_id'], product_id, qty))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    cart_id = request.form.get('cart_id')
    new_qty = int(request.form.get('quantity'))
    
    conn = get_db_connection()
    cart_item = conn.execute('''
        SELECT c.*, p.stock 
        FROM cart c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.id = ? AND c.user_id = ?
    ''', (cart_id, session['user_id'])).fetchone()
    
    if cart_item:
        if new_qty <= 0:
            conn.execute('DELETE FROM cart WHERE id=?', (cart_id,))
            flash('Item removed from cart')
        elif new_qty > cart_item['stock']:
            flash(f'Only {cart_item["stock"]} items in stock!')
            conn.execute('UPDATE cart SET quantity=? WHERE id=?', (cart_item['stock'], cart_id))
        else:
            conn.execute('UPDATE cart SET quantity=? WHERE id=?', (new_qty, cart_id))
        conn.commit()
    
    conn.close()
    return redirect(url_for('cart'))

@app.route('/remove_from_cart', methods=['POST'])
@login_required
def remove_from_cart():
    cart_id = request.form.get('cart_id')
    conn = get_db_connection()
    conn.execute('DELETE FROM cart WHERE id=? AND user_id=?', (cart_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('cart'))


@app.route('/cart')
@login_required
def cart():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT c.id as cart_id, p.*, c.quantity FROM cart c JOIN products p ON c.product_id=p.id WHERE c.user_id=?
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('cart.html', cart_items=items)


@app.route('/checkout', methods=['GET', 'POST']) 
@login_required
def checkout():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT c.*, p.name, p.price, p.stock, p.seller_id 
        FROM cart c 
        JOIN products p ON c.product_id=p.id 
        WHERE c.user_id=?
    ''', (session['user_id'],)).fetchall()

    if not items:
        conn.close()
        flash('Cart empty')
        return redirect(url_for('cart'))

    total = sum(item['price'] * item['quantity'] for item in items)

    if request.method == 'POST':
        for it in items:
            if it['quantity'] > it['stock']:
                conn.close()
                flash(f"Not enough stock for product {it['name']}")
                return redirect(url_for('cart'))

        cur = conn.cursor()
        cur.execute('INSERT INTO orders (user_id, total) VALUES (?, ?)', (session['user_id'], total))
        order_id = cur.lastrowid
        
        for it in items:
            cur.execute('''INSERT INTO order_items (order_id, product_id, seller_id, quantity, price) 
                           VALUES (?, ?, ?, ?, ?)''',
                        (order_id, it['product_id'], it['seller_id'], it['quantity'], it['price']))
            
            cur.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (it['quantity'], it['product_id']))
        
        cur.execute('DELETE FROM cart WHERE user_id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        
        log_action('customer', session['user_id'], f'Placed order {order_id}')
        return redirect(url_for('orders'))
    
    conn.close()
    return render_template('checkout.html', items=items, total=total)


@app.route('/orders')
@login_required
def orders():
    conn = get_db_connection()
    orders = conn.execute('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('orders.html', orders=orders)


#  Reviews 
@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def leave_review(product_id):
    rating = int(request.form.get('rating', 5))
    body = sanitize_text(request.form.get('body', ''), allowed_tags=['b','i','strong','em','ul','li','p'])
    image_url = None
    file = request.files.get('image')
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(f"{session['user_id']}_" + file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_url = url_for('uploaded_file', filename=filename)

    conn = get_db_connection()
    conn.execute('INSERT INTO reviews (user_id, product_id, rating, body, image_url) VALUES (?, ?, ?, ?, ?)',
                 (session['user_id'], product_id, rating, body, image_url))
    conn.commit()
    conn.close()
    log_action('customer', session['user_id'], f'Left review for product {product_id}')
    return redirect(url_for('product_detail', product_id=product_id))


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#  Seller area 
@app.route('/seller/dashboard')
@login_required
@seller_required
def seller_dashboard():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE seller_id=? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    transactions = conn.execute('''
        SELECT oi.*, o.created_at as order_date, u.username as buyer
        FROM order_items oi
        JOIN orders o ON oi.order_id=o.id
        LEFT JOIN users u ON o.user_id=u.id
        WHERE oi.seller_id=? ORDER BY o.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('seller_dashboard.html', products=products, transactions=transactions)


@app.route('/seller/add_product', methods=['GET', 'POST'])
@login_required
@seller_required
def seller_add_product():
    if request.method == 'POST':
        name = bleach.clean(request.form.get('name', ''), tags=[], strip=True)
        price = float(request.form.get('price', 0))
        description = sanitize_text(request.form.get('description', ''), allowed_tags=['p','b','i','ul','li'])
        stock = int(request.form.get('stock', 0))
        image_url = None
        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"{session['user_id']}_" + file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('uploaded_file', filename=filename)

        conn = get_db_connection()
        conn.execute('INSERT INTO products (seller_id, name, price, description, stock, image_url) VALUES (?, ?, ?, ?, ?, ?)',
                     (session['user_id'], name, price, description, stock, image_url))
        conn.commit()
        conn.close()
        log_action('seller', session['user_id'], f'Added product {name}')
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('seller_dashboard'))
    return render_template('seller_add_product.html')


@app.route('/seller/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@seller_required
def seller_edit_product(product_id):
    conn = get_db_connection()
    try:
        if session.get('role') == 'admin':
            product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
            return_url = url_for('admin_dashboard')
        else:
            product = conn.execute('SELECT * FROM products WHERE id=? AND seller_id=?', (product_id, session['user_id'])).fetchone()
            return_url = url_for('seller_dashboard') 

        if not product:
            if session.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('seller_dashboard'))

        if request.method == 'POST':
            try:
                name = bleach.clean(request.form.get('name', ''), tags=[], strip=True)
                price = float(request.form.get('price', 0) or 0)
                description = sanitize_text(request.form.get('description', ''))
                stock = int(request.form.get('stock', 0) or 0)

                image_url = product['image_url']
                file = request.files.get('image')
                
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(f"{session['user_id']}_" + file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_url = url_for('uploaded_file', filename=filename)
                conn.execute('UPDATE products SET name=?, price=?, description=?, stock=?, image_url=? WHERE id=?',
                             (name, price, description, stock, image_url, product_id))
                conn.commit()
                log_action(session.get('role'), session['user_id'], f'Edited product {product_id}')
                if session.get('role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('seller_dashboard'))
            except Exception as e:
                app.logger.exception('Failed to update product: %s', e)
                flash('Failed to update product. Check your inputs and try again.')
                return redirect(return_url)
        return render_template('edit_product.html', product=product, return_url=return_url)
    except Exception as e:
        app.logger.exception('Error in seller_edit_product route: %s', e)
        flash('An unexpected error occurred while trying to edit the product.')
        return redirect(url_for('seller_dashboard') if session.get('role') != 'admin' else url_for('admin_dashboard'))
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.route('/seller/delete_product', methods=['POST'])
@login_required
@seller_required
def seller_delete_product():
    pid = int(request.form.get('product_id'))
    conn = get_db_connection()
    if session.get('role') == 'admin':
        conn.execute('DELETE FROM products WHERE id=?', (pid,))
        log_action('admin', session['user_id'], f'Force deleted product {pid}')
    else:
        conn.execute('DELETE FROM products WHERE id=? AND seller_id=?', (pid, session['user_id']))
        log_action('seller', session['user_id'], f'Deleted product {pid}')
    conn.commit()
    conn.close()
    
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('seller_dashboard'))


#  Admin 
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username=? AND role="admin"', (username,)).fetchone()
        conn.close()
        if not user or not check_password_hash(user['password_hash'], pw):
            return render_template('admin_login.html', error='Invalid admin credentials')
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = 'admin'
        log_action('admin', user['id'], 'Admin logged in')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC').fetchall()
    products = conn.execute('SELECT p.*, u.username AS seller_name FROM products p LEFT JOIN users u ON p.seller_id=u.id').fetchall()
    logs = conn.execute('SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 50').fetchall()

    requests = conn.execute('''
        SELECT r.*, u.username, u.email 
        FROM seller_requests r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.status = 'pending'
    ''').fetchall()

    conn.close()
    return render_template('admin_dashboard.html', users=users, products=products, logs=logs,requests=requests)

@app.route('/admin/approve_seller/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_seller(request_id):
    conn = get_db_connection()
    req = conn.execute('SELECT * FROM seller_requests WHERE id=?', (request_id,)).fetchone()
    
    if req:
        conn.execute('UPDATE users SET role="seller" WHERE id=?', (req['user_id'],))
        conn.execute('UPDATE seller_requests SET status="approved" WHERE id=?', (request_id,))
        conn.commit()
        
        log_action('admin', session['user_id'], f"Approved seller request {request_id}")
        flash(f"User has been upgraded to Seller.")
        
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_seller/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_seller(request_id):
    conn = get_db_connection()
    conn.execute('UPDATE seller_requests SET status="rejected" WHERE id=?', (request_id,))
    conn.commit()
    conn.close()
    flash("Seller request rejected.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_user():
    if request.method == 'POST':
        username = bleach.clean(request.form.get('username'), tags=[], strip=True)
        email = bleach.clean(request.form.get('email'), tags=[], strip=True)
        role = request.form.get('role', 'customer')
        password = request.form.get('password')
        pw_hash = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
                         (username, pw_hash, email, role))
            conn.commit()
            conn.close()
            log_action('admin', session['user_id'], f'Created user {username}')
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('admin_create_user.html', error='Username exists')
    return render_template('admin_create_user.html')


@app.route('/admin/delete_user', methods=['POST'])
@login_required
@admin_required
def admin_delete_user():
    uid = int(request.form.get('user_id'))
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    log_action('admin', session['user_id'], f'Deleted user {uid}')
    flash('User deleted')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def admin_create_account():
    if request.method == 'POST':
        username = request.form.get("username").strip()
        email = request.form.get("email").strip()
        password = request.form.get("password")

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO users (username, email, password_hash, role) 
            VALUES (?, ?, ?, 'admin')
        """, (username, email, password_hash))
        conn.commit()
        conn.close()

        return render_template("admin_create.html", success="New admin created successfully!")

    return render_template("admin_create.html")

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/analytics')
@login_required
@admin_required
def analytics():
    conn = get_db_connection()
    total_views = conn.execute('SELECT COUNT(*) as cnt FROM page_views').fetchone()['cnt']
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    top_paths = conn.execute('SELECT path, COUNT(*) as cnt FROM page_views GROUP BY path ORDER BY cnt DESC LIMIT 10').fetchall()
    conn.close()
    return render_template('analytics.html', total_views=total_views, total_users=total_users, top_paths=top_paths)

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
