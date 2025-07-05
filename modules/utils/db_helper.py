import sqlite3
import os
import time

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

def get_user_full_name(email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT full_name FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

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