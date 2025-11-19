import os
import sqlite3
import logging
import smtplib
import secrets
import string
import time
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from datetime import datetime, timedelta
import hashlib
from pathlib import Path
from functools import wraps
import pyotp
import qrcode
import base64
from io import BytesIO
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# ===== CONFIGURATION =====
# Production configuration
app.secret_key = os.environ.get('SECRET_KEY', 'your-strong-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email Configuration
class EmailConfig:
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@iqubledger.com')

# Configure logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Database configuration
BASE_DIR = Path(__file__).parent
DATABASE_PATH = BASE_DIR / 'iqub_ledger.db'

# Rate limiting storage (temporarily disabled)
login_attempts = {}

# ===== UTILITY FUNCTIONS =====
def get_db_connection():
    """Get database connection with absolute path"""
    try:
        conn = sqlite3.connect(str(DATABASE_PATH))
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        app.logger.error(f"Database connection failed: {str(e)}")
        raise

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token():
    """Generate a secure reset token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(32))

def rate_limit(key_prefix, max_attempts=5, time_window=900):  # 15 minutes
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Temporarily bypass rate limiting
            return f(*args, **kwargs)
            
            # Original rate limiting code (commented out)
            '''
            ip_address = request.remote_addr
            key = f"{key_prefix}:{ip_address}"
            
            now = time.time()
            attempts = login_attempts.get(key, [])
            
            # Remove attempts outside the time window
            attempts = [attempt for attempt in attempts if attempt > now - time_window]
            
            if len(attempts) >= max_attempts:
                flash('Too many login attempts. Please try again later.', 'error')
                return render_template('login.html'), 429
            
            attempts.append(now)
            login_attempts[key] = attempts
            
            return f(*args, **kwargs)
            '''
        return decorated_function
    return decorator

def send_email_notification(recipient_email, subject, message, transaction_type, amount, user_name=None):
    """Send email notification for transactions"""
    try:
        if not EmailConfig.EMAIL_USERNAME or not EmailConfig.EMAIL_PASSWORD:
            app.logger.warning("Email credentials not configured")
            return False

        msg = MIMEMultipart()
        msg['From'] = EmailConfig.FROM_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = f"IqubLedger - {subject}"

        # HTML email template
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: white;">
                <h2>IqubLedger Notification</h2>
            </div>
            <div style="padding: 20px;">
                <h3>{subject}</h3>
                <p>{message}</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h4>Transaction Details:</h4>
                    <p><strong>Type:</strong> {transaction_type.title()}</p>
                    <p><strong>Amount:</strong> {amount:,.2f} Birr</p>
                    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                    {f'<p><strong>User:</strong> {user_name}</p>' if user_name else ''}
                </div>
                <p>If you have any questions, please contact your Iqub administrator.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from IqubLedger. Please do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html, 'html'))

        server = smtplib.SMTP(EmailConfig.SMTP_SERVER, EmailConfig.SMTP_PORT)
        server.starttls()
        server.login(EmailConfig.EMAIL_USERNAME, EmailConfig.EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        app.logger.info(f"Email notification sent to {recipient_email}")
        return True

    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False

# ===== DATABASE INITIALIZATION =====
def init_db():
    conn = get_db_connection()
    
    # Create groups table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create users table with enhanced columns
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0,
            is_admin BOOLEAN DEFAULT 0,
            group_id INTEGER DEFAULT 1,
            reset_token TEXT,
            token_expiry REAL,
            totp_secret TEXT,
            twofa_enabled BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create transactions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER DEFAULT 1,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            date TIMESTAMP NOT NULL,
            balance_after REAL NOT NULL
        )
    ''')
    
    # Insert default groups
    conn.execute('''
        INSERT OR IGNORE INTO groups (id, name, description) 
        VALUES 
        (1, 'Iqub Group A', 'First investment group'),
        (2, 'Iqub Group B', 'Second investment group'),
        (3, 'Iqub Group C', 'Third investment group')
    ''')
    
    # Create default admin user if doesn't exist
    admin_exists = conn.execute(
        'SELECT * FROM users WHERE phone = ?', ('0911000000',)
    ).fetchone()
    
    if not admin_exists:
        hashed_password = hash_password('admin123')
        conn.execute(
            'INSERT INTO users (name, phone, password, balance, is_admin, group_id) VALUES (?, ?, ?, ?, ?, ?)',
            ('Iqub Admin', '0911000000', hashed_password, 0, 1, 1)
        )
        app.logger.info("Default admin user created")
    
    conn.commit()
    conn.close()
    app.logger.info("Database initialized successfully")

# Initialize database when app starts
try:
    init_db()
except Exception as e:
    app.logger.error(f"Database initialization failed: {str(e)}")

# ===== AUTHENTICATION ROUTES =====
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
# @rate_limit('login', max_attempts=5, time_window=900)  # TEMPORARILY DISABLED
def login():
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        
        app.logger.info(f"Login attempt for phone: {phone}")
        
        if not phone or not password:
            flash('Please enter both phone number and password', 'error')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE phone = ?', (phone,)
            ).fetchone()
            conn.close()
            
            if user:
                stored_password = user['password']
                if not stored_password:
                    stored_password = hash_password('password123')
                
                if stored_password == hash_password(password):
                    # Check if 2FA is enabled
                    if user['twofa_enabled'] and user['totp_secret']:
                        session['pending_user_id'] = user['id']
                        session['pending_2fa'] = True
                        return redirect('/verify-2fa')
                    
                    # Regular login without 2FA
                    session['user_id'] = user['id']
                    session['user_name'] = user['name']
                    session['is_admin'] = bool(user['is_admin'])
                    session['group_id'] = user['group_id']
                    
                    app.logger.info(f"Successful login for user: {user['name']}")
                    flash('Login successful!', 'success')
                    return redirect('/dashboard')
                else:
                    app.logger.warning(f"Failed login attempt for phone: {phone}")
                    flash('Invalid phone number or password', 'error')
            else:
                app.logger.warning(f"User not found: {phone}")
                flash('User not found. Please register first.', 'error')
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session or 'pending_2fa' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if not totp_code:
            flash('Please enter the verification code', 'error')
            return render_template('verify_2fa.html')
        
        try:
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', (session['pending_user_id'],)
            ).fetchone()
            conn.close()
            
            if user and user['twofa_enabled'] and user['totp_secret']:
                totp = pyotp.TOTP(user['totp_secret'])
                if totp.verify(totp_code):
                    session['user_id'] = user['id']
                    session['user_name'] = user['name']
                    session['is_admin'] = bool(user['is_admin'])
                    session['group_id'] = user['group_id']
                    session.pop('pending_user_id', None)
                    session.pop('pending_2fa', None)
                    
                    flash('Login successful!', 'success')
                    return redirect('/dashboard')
                else:
                    flash('Invalid verification code', 'error')
            else:
                flash('Two-factor authentication not properly configured', 'error')
                return redirect('/login')
                
        except Exception as e:
            app.logger.error(f"2FA verification error: {str(e)}")
            flash('Verification failed', 'error')
    
    return render_template('verify_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        group_id = request.form.get('group_id', '1')
        
        if not name or not phone or not password:
            flash('Please fill all required fields', 'error')
            return render_template('register.html', groups=get_groups())
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html', groups=get_groups())
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html', groups=get_groups())
        
        try:
            conn = get_db_connection()
            
            existing_user = conn.execute(
                'SELECT * FROM users WHERE phone = ?', (phone,)
            ).fetchone()
            
            if existing_user:
                flash('Phone number already registered. Please login instead.', 'error')
                conn.close()
                return render_template('register.html', groups=get_groups())
            
            hashed_password = hash_password(password)
            conn.execute(
                'INSERT INTO users (name, phone, email, password, balance, is_admin, group_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (name, phone, email, hashed_password, 0, 0, group_id)
            )
            conn.commit()
            conn.close()
            
            app.logger.info(f"New user registered: {name} ({phone})")
            flash('Registration successful! Please login to continue.', 'success')
            return redirect('/login')
            
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html', groups=get_groups())

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address', 'error')
            return render_template('forgot_password.html')
        
        try:
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE email = ?', (email,)
            ).fetchone()
            
            if user:
                reset_token = generate_reset_token()
                token_expiry = datetime.now().timestamp() + 3600  # 1 hour expiry
                
                conn.execute(
                    'UPDATE users SET reset_token = ?, token_expiry = ? WHERE id = ?',
                    (reset_token, token_expiry, user['id'])
                )
                conn.commit()
                
                # Send reset email
                reset_link = f"{request.host_url}reset-password/{reset_token}"
                email_sent = send_email_notification(
                    email,
                    "Password Reset Request",
                    f"Click the link below to reset your password: {reset_link}",
                    "password_reset",
                    0,
                    user['name']
                )
                
                if email_sent:
                    flash('Password reset instructions have been sent to your email', 'success')
                else:
                    flash('Failed to send email. Please contact administrator.', 'error')
            else:
                flash('No account found with that email address', 'error')
            
            conn.close()
            
        except Exception as e:
            app.logger.error(f"Password reset error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE reset_token = ? AND token_expiry > ?',
            (token, datetime.now().timestamp())
        ).fetchone()
        
        if not user:
            flash('Invalid or expired reset token', 'error')
            return redirect('/forgot-password')
        
        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not new_password or not confirm_password:
                flash('Please fill all fields', 'error')
                return render_template('reset_password.html', token=token)
            
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('reset_password.html', token=token)
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long', 'error')
                return render_template('reset_password.html', token=token)
            
            hashed_password = hash_password(new_password)
            conn.execute(
                'UPDATE users SET password = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?',
                (hashed_password, user['id'])
            )
            conn.commit()
            conn.close()
            
            # Send confirmation email
            send_email_notification(
                user['email'],
                "Password Reset Successful",
                "Your password has been successfully reset.",
                "password_reset_success",
                0,
                user['name']
            )
            
            flash('Password reset successfully! Please login with your new password.', 'success')
            return redirect('/login')
        
        conn.close()
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        app.logger.error(f"Reset password error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect('/forgot-password')

def get_groups():
    conn = get_db_connection()
    groups = conn.execute('SELECT * FROM groups').fetchall()
    conn.close()
    return groups

@app.route('/logout')
def logout():
    app.logger.info(f"User logout: {session.get('user_name')}")
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect('/login')

# ===== PROFILE MANAGEMENT ROUTES =====
@app.route('/profile')
def profile():
    if not session.get('user_id'):
        return redirect('/login')
    return redirect(f'/user/{session["user_id"]}')

@app.route('/profile/edit')
def edit_profile():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    conn.close()
    
    return render_template('edit_profile.html', user=dict(user))

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        email = request.form.get('email', '').strip()
        
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            (email, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        
    except Exception as e:
        flash(f'Failed to update profile: {str(e)}', 'error')
    
    return redirect('/profile')

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        
        user = conn.execute(
            '''SELECT u.*, g.name as group_name 
               FROM users u 
               LEFT JOIN groups g ON u.group_id = g.id 
               WHERE u.id = ? AND (u.group_id = ? OR ?)''',
            (user_id, session.get('group_id'), session.get('is_admin'))
        ).fetchone()
        
        if not user:
            flash('User not found in your group', 'error')
            return redirect('/dashboard')
        
        transactions = conn.execute(
            '''SELECT * FROM transactions 
               WHERE user_id = ? 
               ORDER BY date DESC 
               LIMIT 20''',
            (user_id,)
        ).fetchall()
        
        total_contributions_result = conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "contribution"',
            (user_id,)
        ).fetchone()
        total_contributions = total_contributions_result['total'] if total_contributions_result else 0
        
        total_withdrawals_result = conn.execute(
            'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "withdrawal"',
            (user_id,)
        ).fetchone()
        total_withdrawals = total_withdrawals_result['total'] if total_withdrawals_result else 0
        
        conn.close()
        
        return render_template('user_profile.html', 
                             user=dict(user), 
                             transactions=transactions,
                             total_contributions=total_contributions,
                             total_withdrawals=total_withdrawals)
                             
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect('/dashboard')

# ===== 2FA ROUTES =====
@app.route('/enable-2fa', methods=['GET', 'POST'])
def enable_2fa():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?', (session['user_id'],)
        ).fetchone()
        
        if request.method == 'POST':
            totp_code = request.form.get('totp_code', '').strip()
            
            if not totp_code:
                flash('Please enter the verification code', 'error')
                return redirect('/enable-2fa')
            
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                conn.execute(
                    'UPDATE users SET twofa_enabled = 1 WHERE id = ?',
                    (session['user_id'],)
                )
                conn.commit()
                conn.close()
                
                flash('Two-factor authentication enabled successfully!', 'success')
                return redirect('/profile')
            else:
                flash('Invalid verification code', 'error')
        
        # Generate new TOTP secret if not exists
        if not user['totp_secret']:
            totp_secret = pyotp.random_base32()
            conn.execute(
                'UPDATE users SET totp_secret = ? WHERE id = ?',
                (totp_secret, session['user_id'])
            )
            conn.commit()
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', (session['user_id'],)
            ).fetchone()
        
        # Generate QR code
        qr_code = None
        try:
            totp = pyotp.TOTP(user['totp_secret'])
            provisioning_uri = totp.provisioning_uri(
                name=user['email'] or user['phone'],
                issuer_name="IqubLedger"
            )
            
            qr = qrcode.make(provisioning_uri)
            buffered = BytesIO()
            qr.save(buffered, format="PNG")
            qr_code = base64.b64encode(buffered.getvalue()).decode()
        except Exception as e:
            app.logger.warning(f"QR code generation failed: {str(e)}")
            # Continue without QR code
        
        conn.close()
        
        return render_template('enable_2fa.html', 
                             qr_code=qr_code, 
                             secret=user['totp_secret'])
                             
    except Exception as e:
        app.logger.error(f"2FA setup error: {str(e)}")
        flash('Error setting up two-factor authentication', 'error')
        return redirect('/profile')

@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET twofa_enabled = 0, totp_secret = NULL WHERE id = ?',
            (session['user_id'],)
        )
        conn.commit()
        conn.close()
        
        flash('Two-factor authentication disabled successfully!', 'success')
    except Exception as e:
        app.logger.error(f"2FA disable error: {str(e)}")
        flash('Error disabling two-factor authentication', 'error')
    
    return redirect('/profile')

# ===== MAIN APPLICATION ROUTES =====
@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        
        current_user = conn.execute(
            '''SELECT u.*, g.name as group_name 
               FROM users u 
               LEFT JOIN groups g ON u.group_id = g.id 
               WHERE u.id = ?''', 
            (session['user_id'],)
        ).fetchone()
        
        group_members = []
        if current_user and current_user['group_id']:
            group_members = conn.execute(
                '''SELECT u.id, u.name, u.phone, u.balance 
                   FROM users u 
                   WHERE u.group_id = ? AND u.id != ? AND u.is_admin = 0
                   ORDER BY u.name''',
                (current_user['group_id'], session['user_id'])
            ).fetchall()
        
        recent_transactions = []
        if current_user and current_user['group_id']:
            recent_transactions = conn.execute(
                '''SELECT t.*, u.name as user_name 
                   FROM transactions t 
                   JOIN users u ON t.user_id = u.id 
                   WHERE u.group_id = ? 
                   ORDER BY t.date DESC 
                   LIMIT 10''',
                (current_user['group_id'],)
            ).fetchall()
        
        all_groups = []
        all_users = []
        if session.get('is_admin'):
            all_groups = conn.execute('SELECT * FROM groups').fetchall()
            all_users = conn.execute('SELECT * FROM users').fetchall()
        
        conn.close()
        
        today_date = datetime.now().strftime('%Y-%m-%d')
        
        app.logger.info(f"Dashboard loaded for user: {session.get('user_name')}")
        return render_template('dashboard.html', 
                             current_user=dict(current_user) if current_user else {},
                             group_members=group_members,
                             recent_transactions=recent_transactions,
                             all_groups=all_groups,
                             all_users=all_users,
                             today_date=today_date)
                             
    except Exception as e:
        app.logger.error(f"Error loading dashboard: {str(e)}")
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect('/login')

@app.route('/contribute', methods=['GET', 'POST'])
def contribute():
    if not session.get('user_id'):
        return redirect('/login')
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            description = request.form.get('description', 'Weekly Contribution')
            
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', (session['user_id'],)
            ).fetchone()
            
            new_balance = user['balance'] + amount
            conn.execute(
                'UPDATE users SET balance = ? WHERE id = ?',
                (new_balance, session['user_id'])
            )
            
            conn.execute(
                '''INSERT INTO transactions 
                   (user_id, group_id, type, amount, description, date, balance_after) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], user['group_id'], 'contribution', amount, 
                 description, datetime.now(), new_balance)
            )
            
            conn.commit()
            
            # Send email notification to user
            if user['email']:
                send_email_notification(
                    user['email'],
                    "Contribution Received",
                    f"Your contribution of {amount:,.2f} Birr has been recorded successfully.",
                    "contribution",
                    amount,
                    user['name']
                )
            
            # Send notification to admin
            admin_users = conn.execute(
                'SELECT * FROM users WHERE is_admin = 1 AND email IS NOT NULL'
            ).fetchall()
            
            for admin in admin_users:
                send_email_notification(
                    admin['email'],
                    "New Contribution",
                    f"User {user['name']} made a contribution of {amount:,.2f} Birr.",
                    "contribution",
                    amount,
                    user['name']
                )
            
            conn.close()
            
            flash(f'Contribution of {amount} Birr successful!', 'success')
            return redirect('/dashboard')
            
        except Exception as e:
            flash(f'Contribution failed: {str(e)}', 'error')
    
    return render_template('contribute.html')

@app.route('/make_contribution', methods=['POST'])
def make_contribution():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        amount = float(request.form['amount'])
        description = request.form.get('description', 'Contribution')
        
        conn = get_db_connection()
        
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?', (session['user_id'],)
        ).fetchone()
        
        new_balance = user['balance'] + amount
        conn.execute(
            'UPDATE users SET balance = ? WHERE id = ?',
            (new_balance, session['user_id'])
        )
        
        conn.execute(
            '''INSERT INTO transactions 
               (user_id, group_id, type, amount, description, date, balance_after) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (session['user_id'], user['group_id'], 'contribution', amount, 
             description, datetime.now(), new_balance)
        )
        
        conn.commit()
        
        # Send email notification
        if user['email']:
            send_email_notification(
                user['email'],
                "Contribution Received",
                f"Your contribution of {amount:,.2f} Birr has been recorded successfully.",
                "contribution",
                amount,
                user['name']
            )
        
        conn.close()
        
        app.logger.info(f"Contribution made: {amount} Birr by {session.get('user_name')}")
        flash(f'Contribution of {amount} Birr successful!', 'success')
        
    except Exception as e:
        app.logger.error(f"Contribution error: {str(e)}")
        flash(f'Contribution failed: {str(e)}', 'error')
    
    return redirect('/dashboard')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if not session.get('user_id'):
        return redirect('/login')
    
    if not session.get('is_admin'):
        flash('Only administrators can process withdrawals', 'error')
        return redirect('/dashboard')
    
    if request.method == 'POST':
        try:
            member_id = request.form['member_id']
            amount = float(request.form['amount'])
            description = request.form['description']
            
            conn = get_db_connection()
            member = conn.execute(
                'SELECT * FROM users WHERE id = ?', (member_id,)
            ).fetchone()
            
            if not member:
                flash('Member not found', 'error')
                return redirect('/withdraw')
            
            new_balance = member['balance'] - amount
            if new_balance < 0:
                flash('Insufficient balance for withdrawal', 'error')
                return redirect('/withdraw')
            
            conn.execute(
                'UPDATE users SET balance = ? WHERE id = ?',
                (new_balance, member_id)
            )
            
            conn.execute(
                '''INSERT INTO transactions 
                   (user_id, group_id, type, amount, description, date, balance_after) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (member_id, member['group_id'], 'withdrawal', amount, 
                 description, datetime.now(), new_balance)
            )
            
            conn.commit()
            
            # Send email notification to member
            if member['email']:
                send_email_notification(
                    member['email'],
                    "Withdrawal Processed",
                    f"A withdrawal of {amount:,.2f} Birr has been processed from your account.",
                    "withdrawal",
                    amount,
                    member['name']
                )
            
            conn.close()
            
            flash(f'Withdrawal of {amount} Birr to {member["name"]} successful!', 'success')
            return redirect('/dashboard')
            
        except Exception as e:
            flash(f'Withdrawal failed: {str(e)}', 'error')
    
    conn = get_db_connection()
    members = conn.execute('SELECT * FROM users WHERE is_admin = 0').fetchall()
    conn.close()
    
    return render_template('withdraw.html', members=members)

@app.route('/transactions')
def transactions():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    
    if session.get('is_admin'):
        all_transactions = conn.execute(
            '''SELECT t.*, u.name as user_name, g.name as group_name 
               FROM transactions t 
               JOIN users u ON t.user_id = u.id 
               LEFT JOIN groups g ON u.group_id = g.id 
               ORDER BY t.date DESC'''
        ).fetchall()
    else:
        all_transactions = conn.execute(
            '''SELECT t.*, u.name as user_name 
               FROM transactions t 
               JOIN users u ON t.user_id = u.id 
               WHERE u.group_id = ? 
               ORDER BY t.date DESC''',
            (session.get('group_id'),)
        ).fetchall()
    
    conn.close()
    return render_template('transactions.html', transactions=all_transactions)

# ===== EXPORT ROUTES =====
@app.route('/export/transactions/csv')
def export_transactions_csv():
    if not session.get('user_id'):
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        
        if session.get('is_admin'):
            transactions = conn.execute('''
                SELECT t.date, u.name, u.phone, t.type, t.amount, t.description, t.balance_after, g.name as group_name
                FROM transactions t 
                JOIN users u ON t.user_id = u.id 
                LEFT JOIN groups g ON u.group_id = g.id 
                ORDER BY t.date DESC
            ''').fetchall()
        else:
            transactions = conn.execute('''
                SELECT t.date, u.name, u.phone, t.type, t.amount, t.description, t.balance_after
                FROM transactions t 
                JOIN users u ON t.user_id = u.id 
                WHERE u.group_id = ? 
                ORDER BY t.date DESC
            ''', (session.get('group_id'),)).fetchall()
        
        conn.close()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        if session.get('is_admin'):
            writer.writerow(['Date', 'Member Name', 'Phone', 'Type', 'Amount (Birr)', 'Description', 'Balance After', 'Group'])
        else:
            writer.writerow(['Date', 'Member Name', 'Phone', 'Type', 'Amount (Birr)', 'Description', 'Balance After'])
        
        # Write data
        for tx in transactions:
            if session.get('is_admin'):
                writer.writerow([
                    tx['date'],
                    tx['name'],
                    tx['phone'],
                    tx['type'],
                    f"{tx['amount']:,.2f}",
                    tx['description'] or '',
                    f"{tx['balance_after']:,.2f}",
                    tx['group_name'] or ''
                ])
            else:
                writer.writerow([
                    tx['date'],
                    tx['name'],
                    tx['phone'],
                    tx['type'],
                    f"{tx['amount']:,.2f}",
                    tx['description'] or '',
                    f"{tx['balance_after']:,.2f}"
                ])
        
        filename = f"iqub_transactions_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        app.logger.error(f"Export error: {str(e)}")
        flash('Failed to export data', 'error')
        return redirect('/transactions')

@app.route('/export/report/pdf')
def export_report_pdf():
    return export_transactions_csv()  # Using CSV for now, can be enhanced to PDF later

# ===== ADMIN ROUTES =====
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    conn = get_db_connection()
    
    groups = conn.execute('SELECT * FROM groups').fetchall()
    
    users = conn.execute('''
        SELECT u.*, g.name as group_name 
        FROM users u 
        LEFT JOIN groups g ON u.group_id = g.id 
        ORDER BY u.name
    ''').fetchall()
    
    transactions = conn.execute('''
        SELECT t.*, u.name as user_name, g.name as group_name 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        LEFT JOIN groups g ON u.group_id = g.id 
        ORDER BY t.date DESC 
        LIMIT 50
    ''').fetchall()
    
    group_stats = conn.execute('''
        SELECT g.id, g.name, 
               COUNT(u.id) as member_count,
               SUM(u.balance) as total_balance
        FROM groups g 
        LEFT JOIN users u ON g.id = u.group_id 
        GROUP BY g.id, g.name
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         groups=groups,
                         users=users,
                         transactions=transactions,
                         group_stats=group_stats)

@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    if not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    try:
        name = request.form['name']
        phone = request.form['phone']
        email = request.form.get('email', '')
        group_id = request.form['group_id']
        
        conn = get_db_connection()
        
        existing_user = conn.execute(
            'SELECT * FROM users WHERE phone = ?', (phone,)
        ).fetchone()
        
        if existing_user:
            flash('Phone number already registered', 'error')
            return redirect('/admin')
        
        default_password = hash_password('password123')
        conn.execute(
            'INSERT INTO users (name, phone, email, password, balance, is_admin, group_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (name, phone, email, default_password, 0, 0, group_id)
        )
        
        conn.commit()
        conn.close()
        
        flash(f'User {name} added successfully!', 'success')
        
    except Exception as e:
        flash(f'Failed to add user: {str(e)}', 'error')
    
    return redirect('/admin')

@app.route('/admin/payout', methods=['POST'])
def admin_payout():
    if not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    try:
        member_id = request.form['member_id']
        amount = float(request.form['amount'])
        description = request.form['description']
        
        conn = get_db_connection()
        
        member = conn.execute(
            'SELECT * FROM users WHERE id = ?', (member_id,)
        ).fetchone()
        
        if not member:
            flash('Member not found', 'error')
            return redirect('/admin')
        
        new_balance = member['balance'] - amount
        if new_balance < 0:
            flash('Insufficient balance for payout', 'error')
            return redirect('/admin')
        
        conn.execute(
            'UPDATE users SET balance = ? WHERE id = ?',
            (new_balance, member_id)
        )
        
        conn.execute(
            '''INSERT INTO transactions 
               (user_id, group_id, type, amount, description, date, balance_after) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (member_id, member['group_id'], 'withdrawal', amount, 
             description, datetime.now(), new_balance)
        )
        
        conn.commit()
        conn.close()
        
        flash(f'Payout of {amount} Birr to {member["name"]} successful!', 'success')
        
    except Exception as e:
        flash(f'Payout failed: {str(e)}', 'error')
    
    return redirect('/admin')

@app.route('/admin/security-audit')
def security_audit():
    if not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    try:
        conn = get_db_connection()
        
        audit_results = {
            'weak_passwords': [],
            'inactive_users': [],
            'no_2fa_admins': [],
            'failed_logins': len([v for v in login_attempts.values() if len(v) > 3])
        }
        
        # Check for weak passwords (users with default password)
        users = conn.execute('SELECT id, name, phone FROM users').fetchall()
        default_password_hash = hash_password('password123')
        
        for user in users:
            user_data = conn.execute(
                'SELECT password FROM users WHERE id = ?', (user['id'],)
            ).fetchone()
            
            if user_data and user_data['password'] == default_password_hash:
                audit_results['weak_passwords'].append(user)
        
        # Check for inactive users (no transactions in 30 days)
        cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        inactive_users = conn.execute('''
            SELECT u.id, u.name, u.phone, MAX(t.date) as last_activity
            FROM users u 
            LEFT JOIN transactions t ON u.id = t.user_id 
            GROUP BY u.id, u.name, u.phone
            HAVING last_activity < ? OR last_activity IS NULL
        ''', (cutoff_date,)).fetchall()
        audit_results['inactive_users'] = inactive_users
        
        # Check admins without 2FA
        admins_no_2fa = conn.execute('''
            SELECT id, name, phone FROM users 
            WHERE is_admin = 1 AND twofa_enabled = 0
        ''').fetchall()
        audit_results['no_2fa_admins'] = admins_no_2fa
        
        conn.close()
        
        return render_template('security_audit.html', audit_results=audit_results)
        
    except Exception as e:
        app.logger.error(f"Security audit error: {str(e)}")
        flash('Failed to generate security audit', 'error')
        return redirect('/admin')

# ===== STATIC PAGES =====
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# ===== ADDITIONAL ROUTES FOR COMPATIBILITY =====
@app.route('/members')
def member_list():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    members = conn.execute('SELECT * FROM users WHERE is_admin = 0').fetchall()
    conn.close()
    
    return render_template('members.html', members=members)

@app.route('/member/<int:member_id>')
def member_detail(member_id):
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    member = conn.execute('SELECT * FROM users WHERE id = ?', (member_id,)).fetchone()
    
    if not member:
        flash('Member not found', 'error')
        return redirect('/members')
    
    transactions = conn.execute(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC', 
        (member_id,)
    ).fetchall()
    
    total_contributed = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "contribution"',
        (member_id,)
    ).fetchone()['total']
    
    total_received = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "withdrawal"',
        (member_id,)
    ).fetchone()['total']
    
    conn.close()
    
    summary = {
        'contributed': total_contributed,
        'received': total_received,
        'net_position': total_contributed - total_received
    }
    
    return render_template('member_detail.html', member=member, transactions=transactions, summary=summary)

@app.route('/report')
def financial_report():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    
    total_contributions_result = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = "contribution"'
    ).fetchone()
    total_contributions = total_contributions_result['total'] if total_contributions_result else 0
    
    total_payouts_result = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = "withdrawal"'
    ).fetchone()
    total_payouts = total_payouts_result['total'] if total_payouts_result else 0
    
    report_data = conn.execute('''
        SELECT u.id, u.name as full_name, u.phone as phone_number,
               COALESCE(SUM(CASE WHEN t.type = 'contribution' THEN t.amount ELSE 0 END), 0) as total_contributed,
               COALESCE(SUM(CASE WHEN t.type = 'withdrawal' THEN t.amount ELSE 0 END), 0) as total_received
        FROM users u
        LEFT JOIN transactions t ON u.id = t.user_id
        GROUP BY u.id, u.name, u.phone
    ''').fetchall()
    
    conn.close()
    
    return render_template('report.html', 
                         total_contributions=total_contributions,
                         total_payouts=total_payouts,
                         report_data=report_data)

@app.route('/balance')
def balance():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    
    total_balance_result = conn.execute(
        'SELECT COALESCE(SUM(balance), 0) as total FROM users'
    ).fetchone()
    total_balance = total_balance_result['total'] if total_balance_result else 0
    
    conn.close()
    
    return render_template('balance.html', total_balance=total_balance)

@app.route('/my_status')
def my_status():
    if not session.get('user_id'):
        return redirect('/login')
    
    conn = get_db_connection()
    
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    contributions = conn.execute(
        'SELECT * FROM transactions WHERE user_id = ? AND type = "contribution" ORDER BY date DESC',
        (session['user_id'],)
    ).fetchall()
    
    payouts = conn.execute(
        'SELECT * FROM transactions WHERE user_id = ? AND type = "withdrawal" ORDER BY date DESC',
        (session['user_id'],)
    ).fetchall()
    
    total_contributed_result = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "contribution"',
        (session['user_id'],)
    ).fetchone()
    total_contributed = total_contributed_result['total'] if total_contributed_result else 0
    
    amount_received_result = conn.execute(
        'SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE user_id = ? AND type = "withdrawal"',
        (session['user_id'],)
    ).fetchone()
    amount_received = amount_received_result['total'] if amount_received_result else 0
    
    conn.close()
    
    member_data = {
        'full_name': user['name'],
        'total_contributed': total_contributed,
        'amount_received': amount_received
    }
    
    return render_template('my_status.html', 
                         member=member_data,
                         contributions=contributions,
                         payouts=payouts)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    print("🚀 Starting IqubLedger Professional...")
    print(f"📊 Environment: {'Development' if debug_mode else 'Production'}")
    print(f"🌐 Server running on port: {port}")
    print(f"🔐 Debug mode: {debug_mode}")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
