"""
E-Commerce Flask Application with Intentional Security Vulnerabilities
This application contains 25+ security vulnerabilities for DevSecOps testing
"""
import os
import sqlite3
import hashlib
import secrets
import pickle
import subprocess
import shlex
import json
import time
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

# Prometheus monitoring
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'dev-key-change-in-production'  # VULN-1: Weak secret key

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'json', 'xml', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# VULN-2: Debug mode enabled in production
app.config['DEBUG'] = True

# VULN-3: No CSRF protection
# app.config['WTF_CSRF_ENABLED'] = False  # Commented out but should be enabled

# Prometheus metrics
if PROMETHEUS_AVAILABLE:
    http_requests_total = Counter(
        'ecommerce_http_requests_total',
        'Total HTTP requests',
        ['method', 'endpoint', 'status']
    )
    
    orders_total = Counter(
        'ecommerce_orders_total',
        'Total orders placed',
        ['status']
    )
    
    payments_total = Counter(
        'ecommerce_payments_total',
        'Total payments processed',
        ['status']
    )

def init_db():
    """Initialize SQLite database with e-commerce tables"""
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, 
                       username TEXT UNIQUE, 
                       password TEXT, 
                       email TEXT,
                       role TEXT DEFAULT 'customer',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Products table
    cursor.execute('''CREATE TABLE IF NOT EXISTS products 
                      (id INTEGER PRIMARY KEY,
                       name TEXT,
                       description TEXT,
                       price REAL,
                       stock INTEGER,
                       category TEXT,
                       image_url TEXT)''')
    
    # Orders table
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders 
                      (id INTEGER PRIMARY KEY,
                       user_id INTEGER,
                       total_amount REAL,
                       status TEXT DEFAULT 'pending',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Order items table
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_items 
                      (id INTEGER PRIMARY KEY,
                       order_id INTEGER,
                       product_id INTEGER,
                       quantity INTEGER,
                       price REAL,
                       FOREIGN KEY (order_id) REFERENCES orders (id),
                       FOREIGN KEY (product_id) REFERENCES products (id))''')
    
    # Payments table
    cursor.execute('''CREATE TABLE IF NOT EXISTS payments 
                      (id INTEGER PRIMARY KEY,
                       order_id INTEGER,
                       amount REAL,
                       payment_method TEXT,
                       status TEXT DEFAULT 'pending',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (order_id) REFERENCES orders (id))''')
    
    # Insert sample data
    cursor.execute('SELECT COUNT(*) FROM products')
    if cursor.fetchone()[0] == 0:
        sample_products = [
            ('Laptop Pro', 'High-performance laptop', 1299.99, 10, 'Electronics', '/static/images/laptop.jpg'),
            ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 50, 'Electronics', '/static/images/mouse.jpg'),
            ('Office Chair', 'Comfortable office chair', 199.99, 15, 'Furniture', '/static/images/chair.jpg'),
            ('Coffee Maker', 'Automatic coffee maker', 89.99, 25, 'Appliances', '/static/images/coffee.jpg'),
            ('Desk Lamp', 'LED desk lamp', 45.99, 30, 'Furniture', '/static/images/lamp.jpg')
        ]
        cursor.executemany('INSERT INTO products (name, description, price, stock, category, image_url) VALUES (?, ?, ?, ?, ?, ?)', sample_products)
    
    conn.commit()
    conn.close()

init_db()

def record_metrics():
    """Decorator to record metrics"""
    if not PROMETHEUS_AVAILABLE:
        return lambda func: func
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                response = func(*args, **kwargs)
                status = 'success'
                if isinstance(response, tuple):
                    status_code = response[1] if len(response) > 1 else 200
                else:
                    status_code = 200
                
                if status_code >= 500:
                    status = 'server_error'
                elif status_code >= 400:
                    status = 'client_error'
                else:
                    status = 'success'
                
                return response
            except Exception as e:
                status = 'server_error'
                raise
            finally:
                duration = time.time() - start_time
                endpoint = request.endpoint or 'unknown'
                method = request.method
                
                if PROMETHEUS_AVAILABLE:
                    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

@app.route('/')
@record_metrics()
def index():
    """Homepage"""
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products LIMIT 6')
    products = cursor.fetchall()
    conn.close()
    
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
@record_metrics()
def login():
    """Login page with SQL injection vulnerability"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULN-4: SQL Injection vulnerability
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        # Registration stores passwords as MD5; hash the incoming password to match
        password_hash = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@record_metrics()
def register():
    """Registration page with weak password hashing"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # VULN-5: Weak password hashing (MD5)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                           (username, password_hash, email))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
@record_metrics()
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Get user orders
    cursor.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    orders = cursor.fetchall()
    
    # Get user info
    cursor.execute('SELECT username, email, role FROM users WHERE id = ?', (session['user_id'],))
    user_info = cursor.fetchone()
    
    conn.close()
    
    return render_template('dashboard.html', orders=orders, user_info=user_info)

@app.route('/products')
@record_metrics()
def products():
    """Products listing page"""
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # VULN-6: SQL Injection in search
    if search:
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
        cursor.execute(query)
    elif category:
        query = f"SELECT * FROM products WHERE category = '{category}'"
        cursor.execute(query)
    else:
        cursor.execute('SELECT * FROM products')
    
    products = cursor.fetchall()
    conn.close()
    
    return render_template('products.html', products=products, search=search, category=category)

@app.route('/product/<int:product_id>')
@record_metrics()
def product_detail(product_id):
    """Product detail page"""
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if not product:
        flash('Product not found', 'error')
        return redirect(url_for('products'))
    
    return render_template('product_detail.html', product=product)

@app.route('/cart')
@record_metrics()
def cart():
    """Shopping cart page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULN-7: Session fixation - no session regeneration
    cart_items = session.get('cart', [])
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cart_products = []
    total = 0
    for item in cart_items:
        cursor.execute('SELECT * FROM products WHERE id = ?', (item['product_id'],))
        product = cursor.fetchone()
        if product:
            cart_products.append({
                'product': product,
                'quantity': item['quantity']
            })
            total += product[3] * item['quantity']
    
    conn.close()
    
    return render_template('cart.html', cart_products=cart_products, total=total)

@app.route('/add_to_cart', methods=['POST'])
@record_metrics()
def add_to_cart():
    """Add product to cart"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))
    
    # VULN-8: No input validation for quantity
    if 'cart' not in session:
        session['cart'] = []
    
    # Check if product already in cart
    for item in session['cart']:
        if item['product_id'] == int(product_id):
            item['quantity'] += quantity
            break
    else:
        session['cart'].append({
            'product_id': int(product_id),
            'quantity': quantity
        })
    
    session.modified = True
    return jsonify({'success': True, 'message': 'Product added to cart'})

@app.route('/checkout', methods=['GET', 'POST'])
@record_metrics()
def checkout():
    """Checkout process"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get cart items
        cart_items = session.get('cart', [])
        if not cart_items:
            flash('Cart is empty', 'error')
            return redirect(url_for('cart'))
        
        # Calculate total
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        
        total = 0
        for item in cart_items:
            cursor.execute('SELECT price FROM products WHERE id = ?', (item['product_id'],))
            product = cursor.fetchone()
            if product:
                total += product[0] * item['quantity']
        
        # Create order
        cursor.execute('INSERT INTO orders (user_id, total_amount) VALUES (?, ?)',
                       (session['user_id'], total))
        order_id = cursor.lastrowid
        
        # Add order items
        for item in cart_items:
            cursor.execute('SELECT price FROM products WHERE id = ?', (item['product_id'],))
            product = cursor.fetchone()
            if product:
                cursor.execute('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                               (order_id, item['product_id'], item['quantity'], product[0]))
        
        conn.commit()
        conn.close()
        
        # Clear cart
        session['cart'] = []
        session.modified = True
        
        if PROMETHEUS_AVAILABLE:
            orders_total.labels(status='created').inc()
        
        flash('Order placed successfully!', 'success')
        return redirect(url_for('order_success', order_id=order_id))
    
    # GET request - show checkout form
    cart_items = session.get('cart', [])
    if not cart_items:
        return redirect(url_for('cart'))
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cart_products = []
    total = 0
    for item in cart_items:
        cursor.execute('SELECT * FROM products WHERE id = ?', (item['product_id'],))
        product = cursor.fetchone()
        if product:
            cart_products.append({
                'product': product,
                'quantity': item['quantity']
            })
            total += product[3] * item['quantity']
    
    conn.close()
    
    return render_template('checkout.html', cart_products=cart_products, total=total)

@app.route('/payment', methods=['POST'])
@record_metrics()
def payment():
    """Payment processing with vulnerabilities"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    order_id = data.get('order_id')
    payment_method = data.get('payment_method')
    card_number = data.get('card_number')
    cvv = data.get('cvv')
    
    # VULN-9: Logging sensitive payment data
    app.logger.info(f"Payment attempt - Order: {order_id}, Card: {card_number}, CVV: {cvv}")
    
    # VULN-10: No payment validation
    # VULN-11: Storing sensitive data in database
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    cursor.execute('INSERT INTO payments (order_id, amount, payment_method, status) VALUES (?, ?, ?, ?)',
                   (order_id, data.get('amount'), payment_method, 'completed'))
    
    # Update order status
    cursor.execute('UPDATE orders SET status = ? WHERE id = ?', ('paid', order_id))
    
    conn.commit()
    conn.close()
    
    if PROMETHEUS_AVAILABLE:
        payments_total.labels(status='success').inc()
    
    return jsonify({'success': True, 'message': 'Payment processed successfully'})

@app.route('/order_success/<int:order_id>')
@record_metrics()
def order_success(order_id):
    """Order success page"""
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    conn.close()
    
    if not order:
        flash('Order not found', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('order_success.html', order=order)

@app.route('/admin')
@record_metrics()
def admin():
    """Admin panel with authorization bypass"""
    # VULN-12: Weak authorization check
    if session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    
    # Get all orders
    cursor.execute('SELECT * FROM orders ORDER BY created_at DESC')
    orders = cursor.fetchall()
    
    # Get all users
    cursor.execute('SELECT id, username, email, role, created_at FROM users')
    users = cursor.fetchall()
    
    # Get all products
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', orders=orders, users=users, products=products)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@record_metrics()
def delete_user(user_id):
    """Delete user endpoint"""
    # VULN-13: No CSRF protection
    if session.get('role') != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/upload', methods=['POST'])
@record_metrics()
def upload_file():
    """File upload endpoint with multiple vulnerabilities"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    comment = request.form.get('comment', '')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # VULN-14: No file type validation
    # VULN-15: No file size limit
    # VULN-16: Path traversal vulnerability
    filename = file.filename  # Not using secure_filename()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # VULN-17: Reflected XSS in response
    return jsonify({
        'message': f'File uploaded: {filename}',
        'comment': comment,  # Direct echo without sanitization
        'status': 'success'
    })

@app.route('/api/user/<int:user_id>')
@record_metrics()
def api_user(user_id):
    """API endpoint with weak authentication"""
    # VULN-18: Missing authentication check
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        })
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/process', methods=['POST'])
@record_metrics()
def process_data():
    """Data processing endpoint with deserialization vulnerability"""
    data = request.get_json()
    
    # VULN-19: Unsafe deserialization
    if 'command' in data:
        eval(data['command'])  # Dangerous!
    
    # VULN-20: Command injection
    if 'system_command' in data:
        os.system(data['system_command'])
    
    return jsonify({'status': 'processed'})

@app.route('/api/search')
@record_metrics()
def api_search():
    """Search API with SQL injection"""
    query = request.args.get('q', '')
    
    # VULN-21: SQL Injection in API
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    sql_query = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    cursor.execute(sql_query)
    results = cursor.fetchall()
    conn.close()
    
    return jsonify({'results': results})

@app.route('/api/orders')
@record_metrics()
def api_orders():
    """Orders API with IDOR vulnerability"""
    user_id = request.args.get('user_id')
    
    # VULN-22: Insecure Direct Object Reference (IDOR)
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM orders WHERE user_id = ?', (user_id,))
    orders = cursor.fetchall()
    conn.close()
    
    return jsonify({'orders': orders})

@app.route('/api/payment/process', methods=['POST'])
@record_metrics()
def api_payment_process():
    """Payment processing API with vulnerabilities"""
    data = request.get_json()
    
    # VULN-23: No rate limiting
    # VULN-24: Weak encryption for sensitive data
    card_data = {
        'number': data.get('card_number'),
        'cvv': data.get('cvv'),
        'expiry': data.get('expiry')
    }
    
    # Store encrypted data (weak encryption)
    encrypted_data = hashlib.md5(str(card_data).encode()).hexdigest()
    
    return jsonify({
        'status': 'success',
        'transaction_id': encrypted_data,
        'message': 'Payment processed'
    })

@app.route('/api/export')
@record_metrics()
def api_export():
    """Data export endpoint with vulnerabilities"""
    format_type = request.args.get('format', 'json')
    
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    
    # VULN-25: Information disclosure - exporting all user data
    if format_type == 'json':
        return jsonify({'users': users})
    elif format_type == 'xml':
        root = ET.Element('users')
        for user in users:
            user_elem = ET.SubElement(root, 'user')
            user_elem.set('id', str(user[0]))
            user_elem.set('username', user[1])
            user_elem.set('email', user[2])
            user_elem.set('role', user[4])
        
        return ET.tostring(root, encoding='unicode'), 200, {'Content-Type': 'application/xml'}

@app.route('/logout')
@record_metrics()
def logout():
    """Logout"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/metrics')
@record_metrics()
def metrics():
    """Prometheus metrics endpoint"""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
    return 'Prometheus not available', 404

if __name__ == '__main__':
    # VULN-26: Running with debug mode and on all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000)