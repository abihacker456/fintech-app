"""
Database migration script for unified schema
Run this once to migrate existing data
"""

import sqlite3
import hashlib
from datetime import datetime

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def migrate_database():
    conn = sqlite3.connect('iqub_ledger.db')
    
    print("🔧 Starting database migration...")
    
    # Check if old Application 2 tables exist
    old_tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    old_table_names = [t[0] for t in old_tables]
    
    # If we have old Application 2 tables, migrate them
    if 'members' in old_table_names and 'contributions' in old_table_names:
        print("📊 Found Application 2 data. Migrating...")
        
        # Create unified tables if they don't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
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
                date_joined DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                group_id INTEGER,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                reference TEXT,
                date TIMESTAMP NOT NULL,
                balance_after REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (group_id) REFERENCES groups(id)
            )
        ''')
        
        # Add default groups
        conn.execute('''
            INSERT OR IGNORE INTO groups (id, name, description) 
            VALUES 
            (1, 'Iqub Group A', 'First investment group'),
            (2, 'Iqub Group B', 'Second investment group'),
            (3, 'Iqub Group C', 'Third investment group')
        ''')
        
        # Migrate members to users
        old_members = conn.execute('SELECT * FROM members').fetchall()
        for member in old_members:
            try:
                # Map old fields to new fields
                conn.execute('''
                    INSERT OR IGNORE INTO users 
                    (name, phone, password, is_admin, date_joined, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    member[1],  # full_name
                    member[2],  # phone_number
                    hash_password(member[3]),  # password
                    member[5],  # is_admin
                    member[4],  # date_joined
                    datetime.now().isoformat()
                ))
            except Exception as e:
                print(f"⚠️ Error migrating member {member[1]}: {e}")
        
        print(f"✅ Migrated {len(old_members)} members")
        
        # Migrate contributions
        contributions = conn.execute('SELECT * FROM contributions').fetchall()
        for contrib in contributions:
            try:
                # Find user by member_id
                user = conn.execute('SELECT id FROM users WHERE id = ?', (contrib[1],)).fetchone()
                if user:
                    conn.execute('''
                        INSERT INTO transactions 
                        (user_id, type, amount, description, reference, date, balance_after)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        user[0],
                        'contribution',
                        contrib[2],
                        'Contribution',
                        contrib[4],  # reference
                        contrib[3],  # payment_date
                        contrib[2]  # temporary balance
                    ))
            except Exception as e:
                print(f"⚠️ Error migrating contribution: {e}")
        
        print(f"✅ Migrated {len(contributions)} contributions")
        
        # Migrate payouts
        payouts = conn.execute('SELECT * FROM payouts').fetchall()
        for payout in payouts:
            try:
                user = conn.execute('SELECT id FROM users WHERE id = ?', (payout[1],)).fetchone()
                if user:
                    conn.execute('''
                        INSERT INTO transactions 
                        (user_id, type, amount, description, reference, date, balance_after)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        user[0],
                        'payout',
                        payout[2],
                        'Payout',
                        payout[4],  # reference
                        payout[3],  # payout_date
                        -payout[2]  # temporary balance
                    ))
            except Exception as e:
                print(f"⚠️ Error migrating payout: {e}")
        
        print(f"✅ Migrated {len(payouts)} payouts")
        
        # Drop old tables
        conn.execute('DROP TABLE IF EXISTS members')
        conn.execute('DROP TABLE IF EXISTS contributions')
        conn.execute('DROP TABLE IF EXISTS payouts')
        
        print("🗑️  Removed old Application 2 tables")
    
    # Update existing Application 1 tables if needed
    else:
        print("📊 Updating Application 1 schema...")
        
        # Add missing columns to users table
        columns_to_add = [
            ('date_joined', 'DATE'),
            ('reset_token', 'TEXT'),
            ('token_expiry', 'REAL'),
            ('totp_secret', 'TEXT'),
            ('twofa_enabled', 'BOOLEAN DEFAULT 0')
        ]
        
        for column_name, column_type in columns_to_add:
            try:
                conn.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_type}')
                print(f"✅ Added column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"→ Column already exists: {column_name}")
                else:
                    print(f"⚠️ Error adding {column_name}: {e}")
        
        # Add reference column to transactions
        try:
            conn.execute('ALTER TABLE transactions ADD COLUMN reference TEXT')
            print("✅ Added reference column to transactions")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("→ Reference column already exists")
            else:
                print(f"⚠️ Error adding reference column: {e}")
    
    # Create indexes
    conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_group_id ON users(group_id)')
    
    # Create default admin if not exists
    admin_exists = conn.execute('SELECT * FROM users WHERE phone = ?', ('0911000000',)).fetchone()
    if not admin_exists:
        conn.execute('''
            INSERT INTO users (name, phone, password, is_admin, group_id, date_joined)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('Iqub Admin', '0911000000', hash_password('admin123'), 1, 1, datetime.now().date().isoformat()))
        print("✅ Created default admin user")
    
    conn.commit()
    conn.close()
    
    print("🎉 Database migration completed successfully!")

if __name__ == '__main__':
    migrate_database()
