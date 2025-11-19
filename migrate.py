import sqlite3

def migrate_database():
    conn = sqlite3.connect('iqub_ledger.db')
    cursor = conn.cursor()
    
    # List of columns to add
    new_columns = [
        'email TEXT',
        'reset_token TEXT', 
        'token_expiry REAL',
        'totp_secret TEXT',
        'twofa_enabled BOOLEAN DEFAULT 0'
    ]
    
    for column in new_columns:
        try:
            column_name = column.split(' ')[0]
            cursor.execute(f'ALTER TABLE users ADD COLUMN {column}')
            print(f"✓ Added column: {column_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"→ Column already exists: {column_name}")
            else:
                print(f"✗ Error adding {column_name}: {e}")
    
    conn.commit()
    conn.close()
    print("Database migration completed!")

if __name__ == '__main__':
    migrate_database()