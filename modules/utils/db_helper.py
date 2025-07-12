import sqlite3
import time
import os

DB_PATH = os.path.join("data", "users.db")

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        full_name TEXT,
        dob TEXT,
        phone TEXT,
        address TEXT,
        passphrase_hash TEXT,
        salt TEXT,
        totp_secret TEXT,
        fail_count INTEGER DEFAULT 0,
        lock_until INTEGER DEFAULT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_keys (
        email TEXT UNIQUE,
        created_at INTEGER,
        expire_at INTEGER,
        FOREIGN KEY (email) REFERENCES users(email)
    )
    """)
    conn.commit()
    conn.close()

def insert_user(email, full_name, dob, phone, address, passphrase_hash, salt, totp_secret):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO users (email, full_name, dob, phone, address, passphrase_hash, salt, totp_secret)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (email, full_name, dob, phone, address, passphrase_hash, salt, totp_secret))
    conn.commit()
    conn.close()

def user_exists(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_user_auth_info(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT passphrase_hash, salt, totp_secret, fail_count, lock_until
        FROM users
        WHERE email = ?
    """, (email,))
    row = cursor.fetchone()
    conn.close()
    return row

def update_fail_count(email, fail_count, lock_until=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET fail_count = ?, lock_until = ?
        WHERE email = ?
    """, (fail_count, lock_until, email))
    conn.commit()
    conn.close()

def reset_fail_count(email):
    update_fail_count(email, 0, None)

def get_user_profile(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT full_name, dob, phone, address
        FROM users
        WHERE email = ?
    """, (email,))
    result = cursor.fetchone()
    conn.close()
    return result

def update_user_profile(email, full_name, dob, phone, address):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET full_name = ?, dob = ?, phone = ?, address = ?
        WHERE email = ?
    """, (full_name, dob, phone, address, email))
    conn.commit()
    conn.close()

def update_user_passphrase(email, passphrase_hash, salt):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET passphrase_hash = ?, salt = ?
        WHERE email = ?
    """, (passphrase_hash, salt, email))
    conn.commit()
    conn.close()

def insert_user_key(email, created_at, expire_at):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_keys (email, created_at, expire_at)
        VALUES (?, ?, ?)
    """, (email, created_at, expire_at))
    conn.commit()
    conn.close()

def get_user_key_info(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT created_at, expire_at FROM user_keys
        WHERE email = ?
    """, (email,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_user_key_list():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT email FROM user_keys")
    rows = cur.fetchall()
    conn.close()
    return rows

def delete_user_key(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM user_keys WHERE email = ?
    """, (email,))
    conn.commit()
    conn.close()

def calculate_key_expiration(create_at, email):
    row = get_user_key_info(email)
    if not row:
        return "Unknown", "red"
    queried_create_at, _ = row
    if queried_create_at != create_at:
        return "Outdated", "red"
    
    current_time = time.time()
    expire_at = create_at + (90 * 24 * 60 * 60)  # 90 days
    days_left = (expire_at - current_time) / (24 * 60 * 60)
    if current_time > expire_at:
        return "Expired", "red"
    elif days_left < 10:
        return f"Expiring in ({int(days_left)} days", "orange"
    else:
        return "Active", "green"
    