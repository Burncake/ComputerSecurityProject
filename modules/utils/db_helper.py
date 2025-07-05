import sqlite3
import os

DB_PATH = os.path.join("data", "users.db")

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        passphrase_hash TEXT,
        salt TEXT,
        totp_secret TEXT
    )
    """)
    conn.commit()
    conn.close()

def insert_user(username, email, passphrase_hash, salt, totp_secret):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO users (username, email, passphrase_hash, salt, totp_secret)
    VALUES (?, ?, ?, ?, ?)
    """, (username, email, passphrase_hash, salt, totp_secret))
    conn.commit()
    conn.close()

def user_exists(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None
