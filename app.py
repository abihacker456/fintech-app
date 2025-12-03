"""
UNIFIED IqubLedger - Merged Application
Combines features from both applications with enhanced security
"""

import os
import sqlite3
import logging
import hashlib
import secrets
import string
import time
import csv
import io
from datetime import datetime, date, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
import pyotp
import qrcode
import base64
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# ===== CONFIGURATION =====
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
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
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database configuration
DB_PATH = 'iqub_ledger.db'

# ===== UTILITY FUNCTIONS =====
def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token():
    """Generate a secure reset token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))

def login_required(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please login to access this page', 'error')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to protect admin routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please login to access this page', 'error')
            return redirect('/login')
        if not session.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect('/dashboard')
        return f(*args, **kwargs)
    return decorated_function

def send_email_notification(recipient_email, subject, message, transaction_type=None, amount=0, user_name=None):
    """Send email notification for transactions"""
    try:
        if not EmailConfig.EMAIL_USERNAME or not EmailConfig.EMAIL_PASSWORD:
            logger.warning("Email credentials not configured")
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
                """
        
        if transaction_type:
            html += f"""
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h4>Transaction Details:</h4>
                    <p><strong>Type:</strong> {transaction_type.title()}</p>
                    <p><strong>Amount:</strong> {amount:,.2f} Birr</p>
                    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                    {f'<p><strong>User:</strong> {user_name}</p>' if user_name else ''}
                </div>
                """
        
        html += """
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

        with smtplib.SMTP(EmailConfig.SMTP_SERVER, EmailConfig.SMTP_PORT) as server:
            server.starttls()
            server.login(EmailConfig.EMAIL_USERNAME, EmailConfig.EMAIL_PASSWORD)
            server.send_message(msg)

        logger.info(f"Email sent to {recipient_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

# ===== DATABASE INITIALIZATION =====
def init_db():
    """Initialize database with unified schema"""
    conn = get_db()
    
    # Create groups table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create users table with all fields
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
            date_joined DATE,  -- From Application 2
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups(id)
        )
    ''')
    
    # Create transactions table with all fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER,
            type TEXT NOT NULL,  -- 'contribution', 'withdrawal', 'payout'
            amount REAL NOT NULL,
            description TEXT,
            reference TEXT,  -- From Application 2
            date TIMESTAMP NOT NULL,
            balance_after REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (group_id) REFERENCES groups(id)
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
    
    # Create default admin user
    admin_exists = conn.execute(
        'SELECT * FROM users WHERE phone = ?', ('0911000000',)
    ).fetchone()
    
    if not admin_exists:
        hashed_password = hash_password('admin123')
        today = date.today().isoformat()
        conn.execute(
            '''INSERT INTO users (name, phone, password, balance, is_admin, group_id, date_joined) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            ('Iqub Admin', '0911000000', hashed_password, 0, 1, 1, today)
        )
        logger.info("Default admin user created")
    
    # Create indexes
    conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_group_id ON users(group_id)')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# Initialize database
try:
    init_db()
except Exception as e:
    logger.error(f"Database initialization failed: {str(e)}")

# ===== AUTHENTICATION ROUTES =====
@app.route('/')
def index():
    """Home page - redirect to login"""
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route with 2FA support"""
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        
        if not phone or not password:
            flash('Please enter both phone number and password', 'error')
            return render_template('login.html')
        
        try:
            conn = get_db()
            user = conn.execute(
                'SELECT * FROM users WHERE phone = ?', (phone,)
            ).fetchone()
            conn.close()
            
            if user and user['password'] == hash_password(password):
                # Check 2FA
                if user['twofa_enabled'] and user['totp_secret']:
                    session['pending_user_id'] = user['id']
                    session['pending_2fa'] = True
                    return redirect('/verify-2fa')
                
                # Regular login
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['is_admin'] = bool(user['is_admin'])
                session['group_id'] = user['group_id']
                
                flash('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                flash('Invalid phone number or password', 'error')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """2FA verification"""
    if 'pending_user_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if not totp_code:
            flash('Please enter the verification code', 'error')
            return render_template('verify_2fa.html')
        
        try:
            conn = get_db()
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
                flash('Two-factor authentication not configured', 'error')
                return redirect('/login')
                
        except Exception as e:
            logger.error(f"2FA verification error: {str(e)}")
            flash('Verification failed', 'error')
    
    return render_template('verify_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        group_id = request.form.get('group_id', '1')
        date_joined = request.form.get('date_joined', date.today().isoformat())
        
        # Validation
        if not name or not phone or not password:
            flash('Please fill all required fields', 'error')
            return redirect('/register')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect('/register')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        try:
            conn = get_db()
            
            # Check if user exists
            existing = conn.execute(
                'SELECT * FROM users WHERE phone = ?', (phone,)
            ).fetchone()
            
            if existing:
                flash('Phone number already registered', 'error')
                conn.close()
                return redirect('/register')
            
            # Create user
            hashed_password = hash_password(password)
            conn.execute('''
                INSERT INTO users (name, phone, email, password, group_id, date_joined)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, phone, email, hashed_password, group_id, date_joined))
            
            conn.commit()
            conn.close()
            
            # Send welcome email
            if email and EmailConfig.EMAIL_USERNAME:
                send_email_notification(
                    email,
                    "Welcome to IqubLedger",
                    f"Hello {name}, your account has been created successfully.",
                    user_name=name
                )
            
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash(f'Registration failed: {str(e)}', 'error')
    
    # Get groups for dropdown
    conn = get_db()
    groups = conn.execute('SELECT * FROM groups ORDER BY name').fetchall()
    conn.close()
    
    return render_template('register.html', groups=groups, today_date=date.today().isoformat())

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect('/login')

# ===== MAIN APPLICATION ROUTES =====
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with merged features"""
    conn = get_db()
    
    # Get user info
    user = conn.execute('''
        SELECT u.*, g.name as group_name 
        FROM users u 
        LEFT JOIN groups g ON u.group_id = g.id 
        WHERE u.id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get group members
    members = conn.execute('''
        SELECT id, name, phone, balance 
        FROM users 
        WHERE group_id = ? AND id != ? 
        ORDER BY name
    ''', (session['group_id'], session['user_id'])).fetchall()
    
    # Get recent transactions
    recent_transactions = conn.execute('''
        SELECT t.*, u.name as user_name 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        WHERE u.group_id = ? 
        ORDER BY t.date DESC 
        LIMIT 10
    ''', (session['group_id'],)).fetchall()
    
    # Get financial summary
    summary = conn.execute('''
        SELECT 
            COALESCE(SUM(CASE WHEN type = 'contribution' THEN amount ELSE 0 END), 0) as total_contributed,
            COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'payout') THEN amount ELSE 0 END), 0) as total_received
        FROM transactions 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get all groups (for admin)
    all_groups = []
    all_users = []
    if session.get('is_admin'):
        all_groups = conn.execute('SELECT * FROM groups').fetchall()
        all_users = conn.execute('SELECT * FROM users').fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         user=dict(user),
                         members=members,
                         recent_transactions=recent_transactions,
                         total_contributed=summary['total_contributed'] if summary else 0,
                         total_received=summary['total_received'] if summary else 0,
                         all_groups=all_groups,
                         all_users=all_users)

@app.route('/contribute', methods=['GET', 'POST'])
@login_required
def contribute():
    """Make a contribution"""
    if request.method == 'POST':
        amount = request.form.get('amount', '0')
        description = request.form.get('description', 'Weekly Contribution')
        
        try:
            amount = float(amount)
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect('/contribute')
            
            conn = get_db()
            
            # Get user current balance
            user = conn.execute(
                'SELECT * FROM users WHERE id = ?', (session['user_id'],)
            ).fetchone()
            
            new_balance = user['balance'] + amount
            
            # Update user balance
            conn.execute(
                'UPDATE users SET balance = ? WHERE id = ?',
                (new_balance, session['user_id'])
            )
            
            # Record transaction
            conn.execute('''
                INSERT INTO transactions 
                (user_id, group_id, type, amount, description, date, balance_after)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (session['user_id'], user['group_id'], 'contribution', 
                  amount, description, datetime.now(), new_balance))
            
            conn.commit()
            
            # Send email notification
            if user['email'] and EmailConfig.EMAIL_USERNAME:
                send_email_notification(
                    user['email'],
                    "Contribution Recorded",
                    f"Your contribution of {amount:,.2f} Birr has been recorded.",
                    "contribution",
                    amount,
                    user['name']
                )
            
            conn.close()
            
            flash(f'Contribution of {amount:,.2f} Birr recorded successfully!', 'success')
            return redirect('/dashboard')
            
        except ValueError:
            flash('Invalid amount', 'error')
        except Exception as e:
            logger.error(f"Contribution error: {str(e)}")
            flash(f'Contribution failed: {str(e)}', 'error')
    
    return render_template('contribute.html')

@app.route('/withdraw', methods=['GET', 'POST'])
@admin_required
def withdraw():
    """Admin: Process withdrawal for member"""
    conn = get_db()
    members = conn.execute(
        'SELECT * FROM users WHERE is_admin = 0 ORDER BY name'
    ).fetchall()
    
    if request.method == 'POST':
        member_id = request.form.get('member_id')
        amount = request.form.get('amount', '0')
        description = request.form.get('description', 'Withdrawal')
        
        try:
            amount = float(amount)
            member_id = int(member_id)
            
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect('/withdraw')
            
            # Get member info
            member = conn.execute(
                'SELECT * FROM users WHERE id = ?', (member_id,)
            ).fetchone()
            
            if not member:
                flash('Member not found', 'error')
                return redirect('/withdraw')
            
            if amount > member['balance']:
                flash(f'Insufficient balance. Available: {member["balance"]:,.2f} Birr', 'error')
                return redirect('/withdraw')
            
            new_balance = member['balance'] - amount
            
            # Update member balance
            conn.execute(
                'UPDATE users SET balance = ? WHERE id = ?',
                (new_balance, member_id)
            )
            
            # Record transaction
            conn.execute('''
                INSERT INTO transactions 
                (user_id, group_id, type, amount, description, date, balance_after)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (member_id, member['group_id'], 'withdrawal', 
                  amount, description, datetime.now(), new_balance))
            
            conn.commit()
            
            # Send email notification
            if member['email'] and EmailConfig.EMAIL_USERNAME:
                send_email_notification(
                    member['email'],
                    "Withdrawal Processed",
                    f"A withdrawal of {amount:,.2f} Birr has been processed from your account.",
                    "withdrawal",
                    amount,
                    member['name']
                )
            
            flash(f'Withdrawal of {amount:,.2f} Birr for {member["name"]} processed successfully!', 'success')
            return redirect('/dashboard')
            
        except ValueError:
            flash('Invalid amount or member', 'error')
        except Exception as e:
            logger.error(f"Withdrawal error: {str(e)}")
            flash(f'Withdrawal failed: {str(e)}', 'error')
    
    conn.close()
    return render_template('withdraw.html', members=members)

@app.route('/payout', methods=['GET', 'POST'])
@admin_required
def payout():
    """Atomic payout transaction (from Application 2)"""
    conn = get_db()
    
    # Get total available balance
    total_balance = conn.execute('''
        SELECT COALESCE(SUM(balance), 0) as total 
        FROM users 
        WHERE is_admin = 0
    ''').fetchone()['total']
    
    members = conn.execute('''
        SELECT id, name, phone, balance 
        FROM users 
        WHERE is_admin = 0 
        ORDER BY name
    ''').fetchall()
    
    if request.method == 'POST':
        member_id = request.form.get('member_id')
        amount = request.form.get('amount', '0')
        payout_date = request.form.get('payout_date', date.today().isoformat())
        reference = request.form.get('reference', 'Iqub Payout')
        
        try:
            amount = float(amount)
            member_id = int(member_id)
            
            if amount <= 0:
                flash('Amount must be positive', 'error')
                return redirect('/payout')
            
            if amount > total_balance:
                flash(f'Insufficient group funds. Available: {total_balance:,.2f} Birr', 'error')
                return redirect('/payout')
            
            # Get member info
            member = conn.execute(
                'SELECT * FROM users WHERE id = ?', (member_id,)
            ).fetchone()
            
            if not member:
                flash('Member not found', 'error')
                return redirect('/payout')
            
            if amount > member['balance']:
                flash(f'Member has insufficient balance. Available: {member["balance"]:,.2f} Birr', 'error')
                return redirect('/payout')
            
            new_balance = member['balance'] - amount
            
            # ATOMIC TRANSACTION: Update balance and record
            conn.execute(
                'UPDATE users SET balance = ? WHERE id = ?',
                (new_balance, member_id)
            )
            
            conn.execute('''
                INSERT INTO transactions 
                (user_id, group_id, type, amount, description, reference, date, balance_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (member_id, member['group_id'], 'payout', amount, 
                  'Payout to member', reference, payout_date, new_balance))
            
            conn.commit()
            
            # Send email notification
            if member['email'] and EmailConfig.EMAIL_USERNAME:
                send_email_notification(
                    member['email'],
                    "Payout Processed",
                    f"A payout of {amount:,.2f} Birr has been processed.",
                    "payout",
                    amount,
                    member['name']
                )
            
            flash(f'Payout of {amount:,.2f} Birr to {member["name"]} completed successfully!', 'success')
            return redirect('/dashboard')
            
        except ValueError:
            flash('Invalid amount or member', 'error')
        except Exception as e:
            conn.rollback()
            logger.error(f"Payout error: {str(e)}")
            flash(f'Payout failed: {str(e)}', 'error')
    
    conn.close()
    return render_template('payout.html',
                         members=members,
                         total_balance=total_balance,
                         today_date=date.today().isoformat())

@app.route('/transactions')
@login_required
def transactions():
    """View all transactions"""
    conn = get_db()
    
    if session.get('is_admin'):
        # Admin sees all
        all_transactions = conn.execute('''
            SELECT t.*, u.name as user_name, g.name as group_name 
            FROM transactions t 
            JOIN users u ON t.user_id = u.id 
            LEFT JOIN groups g ON u.group_id = g.id 
            ORDER BY t.date DESC
        ''').fetchall()
    else:
        # User sees only their group
        all_transactions = conn.execute('''
            SELECT t.*, u.name as user_name 
            FROM transactions t 
            JOIN users u ON t.user_id = u.id 
            WHERE u.group_id = ? 
            ORDER BY t.date DESC
        ''', (session['group_id'],)).fetchall()
    
    conn.close()
    return render_template('transactions.html', transactions=all_transactions)

# ===== MEMBER MANAGEMENT ROUTES =====
@app.route('/members')
@login_required
def members_list():
    """List all members"""
    conn = get_db()
    
    if session.get('is_admin'):
        members = conn.execute('''
            SELECT u.*, g.name as group_name 
            FROM users u 
            LEFT JOIN groups g ON u.group_id = g.id 
            ORDER BY u.name
        ''').fetchall()
    else:
        members = conn.execute('''
            SELECT u.*, g.name as group_name 
            FROM users u 
            LEFT JOIN groups g ON u.group_id = g.id 
            WHERE u.group_id = ? 
            ORDER BY u.name
        ''', (session['group_id'],)).fetchall()
    
    conn.close()
    return render_template('members.html', members=members)

@app.route('/member/<int:member_id>')
@login_required
def member_detail(member_id):
    """View member details and ledger"""
    conn = get_db()
    
    # Check permission
    user = conn.execute(
        'SELECT is_admin, group_id FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    member = conn.execute('''
        SELECT u.*, g.name as group_name 
        FROM users u 
        LEFT JOIN groups g ON u.group_id = g.id 
        WHERE u.id = ?
    ''', (member_id,)).fetchone()
    
    if not member:
        flash('Member not found', 'error')
        return redirect('/members')
    
    # Check if user has permission to view this member
    if not user['is_admin'] and member['group_id'] != user['group_id']:
        flash('You can only view members in your group', 'error')
        return redirect('/members')
    
    # Get transactions
    transactions = conn.execute('''
        SELECT * FROM transactions 
        WHERE user_id = ? 
        ORDER BY date DESC
    ''', (member_id,)).fetchall()
    
    # Calculate summary
    summary = conn.execute('''
        SELECT 
            COALESCE(SUM(CASE WHEN type = 'contribution' THEN amount ELSE 0 END), 0) as contributed,
            COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'payout') THEN amount ELSE 0 END), 0) as received
        FROM transactions 
        WHERE user_id = ?
    ''', (member_id,)).fetchone()
    
    net_position = summary['contributed'] - summary['received']
    
    conn.close()
    
    return render_template('member_detail.html',
                         member=member,
                         transactions=transactions,
                         summary={
                             'contributed': summary['contributed'],
                             'received': summary['received'],
                             'net_position': net_position
                         })

@app.route('/my_status')
@login_required
def my_status():
    """Personal financial status"""
    conn = get_db()
    
    user = conn.execute('''
        SELECT u.*, g.name as group_name 
        FROM users u 
        LEFT JOIN groups g ON u.group_id = g.id 
        WHERE u.id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get contributions
    contributions = conn.execute('''
        SELECT date, amount, description 
        FROM transactions 
        WHERE user_id = ? AND type = 'contribution' 
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get payouts/withdrawals
    payouts = conn.execute('''
        SELECT date, amount, description 
        FROM transactions 
        WHERE user_id = ? AND type IN ('withdrawal', 'payout') 
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get financial summary
    summary = conn.execute('''
        SELECT 
            COALESCE(SUM(CASE WHEN type = 'contribution' THEN amount ELSE 0 END), 0) as total_contributed,
            COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'payout') THEN amount ELSE 0 END), 0) as amount_received
        FROM transactions 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('my_status.html',
                         member=dict(user),
                         contributions=contributions,
                         payouts=payouts,
                         total_contributed=summary['total_contributed'],
                         amount_received=summary['amount_received'])

@app.route('/financial_report')
@login_required
def financial_report():
    """Comprehensive financial report"""
    conn = get_db()
    
    # Check if user is admin
    user = conn.execute(
        'SELECT is_admin, group_id FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    if user['is_admin']:
        # Admin sees all groups
        report_data = conn.execute('''
            SELECT 
                u.id,
                u.name as full_name,
                u.phone as phone_number,
                g.name as group_name,
                COALESCE(SUM(CASE WHEN t.type = 'contribution' THEN t.amount ELSE 0 END), 0) as total_contributed,
                COALESCE(SUM(CASE WHEN t.type IN ('withdrawal', 'payout') THEN t.amount ELSE 0 END), 0) as total_received
            FROM users u
            LEFT JOIN groups g ON u.group_id = g.id
            LEFT JOIN transactions t ON u.id = t.user_id
            GROUP BY u.id, u.name, u.phone, g.name
            ORDER BY g.name, u.name
        ''').fetchall()
    else:
        # Regular user sees only their group
        report_data = conn.execute('''
            SELECT 
                u.id,
                u.name as full_name,
                u.phone as phone_number,
                g.name as group_name,
                COALESCE(SUM(CASE WHEN t.type = 'contribution' THEN t.amount ELSE 0 END), 0) as total_contributed,
                COALESCE(SUM(CASE WHEN t.type IN ('withdrawal', 'payout') THEN t.amount ELSE 0 END), 0) as total_received
            FROM users u
            LEFT JOIN groups g ON u.group_id = g.id
            LEFT JOIN transactions t ON u.id = t.user_id
            WHERE u.group_id = ?
            GROUP BY u.id, u.name, u.phone, g.name
            ORDER BY u.name
        ''', (user['group_id'],)).fetchall()
    
    # Get totals
    totals = conn.execute('''
        SELECT 
            COALESCE(SUM(CASE WHEN type = 'contribution' THEN amount ELSE 0 END), 0) as total_contributions,
            COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'payout') THEN amount ELSE 0 END), 0) as total_payouts
        FROM transactions
    ''').fetchone()
    
    conn.close()
    
    return render_template('financial_report.html',
                         report_data=report_data,
                         total_contributions=totals['total_contributions'],
                         total_payouts=totals['total_payouts'])

# ===== PROFILE & SECURITY ROUTES =====
@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    conn = get_db()
    user = conn.execute('''
        SELECT u.*, g.name as group_name 
        FROM users u 
        LEFT JOIN groups g ON u.group_id = g.id 
        WHERE u.id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get transaction summary
    summary = conn.execute('''
        SELECT 
            COALESCE(SUM(CASE WHEN type = 'contribution' THEN amount ELSE 0 END), 0) as total_contributions,
            COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'payout') THEN amount ELSE 0 END), 0) as total_withdrawals
        FROM transactions 
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get recent transactions
    transactions = conn.execute('''
        SELECT * FROM transactions 
        WHERE user_id = ? 
        ORDER BY date DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('user_profile.html',
                         user=dict(user),
                         transactions=transactions,
                         total_contributions=summary['total_contributions'],
                         total_withdrawals=summary['total_withdrawals'])

@app.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    """Enable two-factor authentication"""
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if not totp_code:
            flash('Please enter the verification code', 'error')
            return redirect('/enable-2fa')
        
        try:
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
            
            # Verify code
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                conn.execute(
                    'UPDATE users SET twofa_enabled = 1 WHERE id = ?',
                    (session['user_id'],)
                )
                conn.commit()
                
                flash('Two-factor authentication enabled successfully!', 'success')
                return redirect('/profile')
            else:
                flash('Invalid verification code', 'error')
                
        except Exception as e:
            logger.error(f"2FA setup error: {str(e)}")
            flash('Error setting up two-factor authentication', 'error')
    
    # Generate QR code
    qr_code = None
    try:
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
        logger.warning(f"QR code generation failed: {str(e)}")
    
    conn.close()
    
    return render_template('enable_2fa.html',
                         qr_code=qr_code,
                         secret=user['totp_secret'] if user else None)

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    try:
        conn = get_db()
        conn.execute(
            'UPDATE users SET twofa_enabled = 0 WHERE id = ?',
            (session['user_id'],)
        )
        conn.commit()
        conn.close()
        
        flash('Two-factor authentication disabled successfully!', 'success')
    except Exception as e:
        logger.error(f"2FA disable error: {str(e)}")
        flash('Error disabling two-factor authentication', 'error')
    
    return redirect('/profile')

# ===== ADMIN ROUTES =====
@app.route('/admin')
@admin_required
def admin():
    """Admin route - redirect to admin dashboard"""
    return redirect('/admin_dashboard')

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    conn = get_db()
    
    # Get statistics
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    total_groups = conn.execute('SELECT COUNT(*) as count FROM groups').fetchone()['count']
    total_balance = conn.execute('SELECT COALESCE(SUM(balance), 0) as total FROM users').fetchone()['total']
    recent_transactions = conn.execute('''
        SELECT t.*, u.name as user_name 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.date DESC 
        LIMIT 10
    ''').fetchall()
    
    # Get group statistics
    group_stats = conn.execute('''
        SELECT 
            g.id, 
            g.name, 
            COUNT(u.id) as member_count,
            COALESCE(SUM(u.balance), 0) as total_balance
        FROM groups g 
        LEFT JOIN users u ON g.id = u.group_id 
        GROUP BY g.id, g.name
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_groups=total_groups,
                         total_balance=total_balance,
                         recent_transactions=recent_transactions,
                         group_stats=group_stats)

@app.route('/admin/security-audit')
@admin_required
def security_audit():
    """Security audit report"""
    conn = get_db()
    
    audit_results = {
        'weak_passwords': [],
        'inactive_users': [],
        'no_2fa_admins': [],
        'failed_logins': 0  # Placeholder for actual implementation
    }
    
    # Check for weak passwords (default password)
    default_password_hash = hash_password('password123')
    weak_passwords = conn.execute('''
        SELECT id, name, phone 
        FROM users 
        WHERE password = ?
    ''', (default_password_hash,)).fetchall()
    audit_results['weak_passwords'] = weak_passwords
    
    # Check for inactive users (no transactions in 30 days)
    cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    inactive_users = conn.execute('''
        SELECT u.id, u.name, u.phone, MAX(t.date) as last_activity
        FROM users u 
        LEFT JOIN transactions t ON u.id = t.user_id 
        GROUP BY u.id, u.name, u.phone
        HAVING last_activity < ? OR last_activity IS NULL
    ''', (cutoff_date,)).fetchall()  # FIXED: was cutcutoff_date, now cutoff_date
    audit_results['inactive_users'] = inactive_users
    
    # Check admins without 2FA
    admins_no_2fa = conn.execute('''
        SELECT id, name, phone 
        FROM users 
        WHERE is_admin = 1 AND twofa_enabled = 0
    ''').fetchall()
    audit_results['no_2fa_admins'] = admins_no_2fa
    
    conn.close()
    
    return render_template('security_audit.html', audit_results=audit_results)

# ===== EXPORT ROUTES =====
@app.route('/export/transactions/csv')
@login_required
def export_transactions_csv():
    """Export transactions to CSV"""
    conn = get_db()
    
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
        ''', (session['group_id'],)).fetchall()
    
    conn.close()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    if session.get('is_admin'):
        writer.writerow(['Date', 'Member Name', 'Phone', 'Type', 'Amount (Birr)', 'Description', 'Balance After', 'Group'])
    else:
        writer.writerow(['Date', 'Member Name', 'Phone', 'Type', 'Amount (Birr)', 'Description', 'Balance After'])
    
    # Write data
    for tx in transactions:
        row = [
            tx['date'],
            tx['name'],
            tx['phone'],
            tx['type'],
            f"{tx['amount']:,.2f}",
            tx['description'] or '',
            f"{tx['balance_after']:,.2f}"
        ]
        if session.get('is_admin'):
            row.append(tx['group_name'] or '')
        writer.writerow(row)
    
    filename = f"iqub_transactions_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# ===== PASSWORD RESET ROUTES =====
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password - request reset"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter your email address', 'error')
            return render_template('forgot_password.html')
        
        try:
            conn = get_db()
            user = conn.execute(
                'SELECT * FROM users WHERE email = ?', (email,)
            ).fetchone()
            
            if user:
                reset_token = generate_reset_token()
                token_expiry = datetime.now().timestamp() + 3600  # 1 hour
                
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
                    user_name=user['name']
                )
                
                if email_sent:
                    flash('Password reset instructions sent to your email', 'success')
                else:
                    flash('Failed to send email. Please contact administrator.', 'error')
            else:
                flash('No account found with that email', 'error')
            
            conn.close()
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    try:
        conn = get_db()
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
                flash('Password must be at least 6 characters', 'error')
                return render_template('reset_password.html', token=token)
            
            hashed_password = hash_password(new_password)
            conn.execute(
                'UPDATE users SET password = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?',
                (hashed_password, user['id'])
            )
            conn.commit()
            
            # Send confirmation email
            send_email_notification(
                user['email'],
                "Password Reset Successful",
                "Your password has been successfully reset.",
                user_name=user['name']
            )
            
            flash('Password reset successfully! Please login.', 'success')
            return redirect('/login')
        
        conn.close()
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect('/forgot-password')

# ===== STATIC PAGES =====
@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

# ===== ERROR HANDLERS =====
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# ===== APPLICATION START =====
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print("=" * 50)
    print("🚀 IqubLedger Unified Application")
    print(f"📊 Database: {DB_PATH}")
    print(f"🌐 Port: {port}")
    print(f"🔧 Debug: {debug}")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
