from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os
import sqlite3
import time
from datetime import datetime, timedelta
from modules.utils.db_helper import DB_PATH

RSA_DB_PATH = os.path.join("data", "security_system.db")

def init_rsa_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        public_key TEXT,
        encrypted_private_key TEXT,
        key_salt TEXT,
        created_date TEXT,
        expire_date TEXT,
        is_active INTEGER DEFAULT 1
    )
    """)
    conn.commit()
    conn.close()

def derive_key_from_passphrase(passphrase, salt):
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, 32)

def generate_rsa_keypair(email, passphrase):
    key = RSA.generate(2048)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    
    salt = get_random_bytes(16)
    aes_key = derive_key_from_passphrase(passphrase, salt)
    
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded_private_key = pad(private_key_pem, AES.block_size)
    encrypted_private_key = cipher.encrypt(padded_private_key)
    
    encrypted_data = cipher.iv + encrypted_private_key
    encrypted_private_key_b64 = base64.b64encode(encrypted_data).decode()
    public_key_b64 = base64.b64encode(public_key_pem).decode()
    salt_b64 = base64.b64encode(salt).decode()
    
    created_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    expire_date = (datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE user_keys SET is_active = 0 WHERE email = ?
    """, (email,))
    
    cursor.execute("""
    INSERT INTO user_keys (email, public_key, encrypted_private_key, key_salt, created_date, expire_date)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (email, public_key_b64, encrypted_private_key_b64, salt_b64, created_date, expire_date))
    conn.commit()
    conn.close()
    
    return public_key_b64, created_date, expire_date

def get_user_key_info(email):
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT public_key, created_date, expire_date, is_active
    FROM user_keys
    WHERE email = ? AND is_active = 1
    ORDER BY created_date DESC
    LIMIT 1
    """, (email,))
    result = cursor.fetchone()
    conn.close()
    return result

def decrypt_private_key(email, passphrase):
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT encrypted_private_key, key_salt
    FROM user_keys
    WHERE email = ? AND is_active = 1
    ORDER BY created_date DESC
    LIMIT 1
    """, (email,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None
    
    encrypted_private_key_b64, salt_b64 = result
    encrypted_data = base64.b64decode(encrypted_private_key_b64)
    salt = base64.b64decode(salt_b64)
    
    aes_key = derive_key_from_passphrase(passphrase, salt)
    
    iv = encrypted_data[:16]
    encrypted_private_key = encrypted_data[16:]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_private_key = cipher.decrypt(encrypted_private_key)
    private_key_pem = unpad(padded_private_key, AES.block_size)
    
    return private_key_pem

def save_key_to_file(key_data, filename):
    os.makedirs("data/keys", exist_ok=True)
    filepath = os.path.join("data/keys", filename)
    with open(filepath, 'w') as f:
        f.write(key_data)
    return filepath

def get_all_public_keys():
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT email, public_key, created_date, expire_date, is_active
    FROM user_keys
    ORDER BY created_date DESC
    """)
    results = cursor.fetchall()
    conn.close()
    return results

def add_external_public_key(email, public_key_b64, created_date):
    conn = sqlite3.connect(RSA_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT COUNT(*) FROM user_keys WHERE email = ? AND public_key = ?
    """, (email, public_key_b64))
    
    if cursor.fetchone()[0] > 0:
        conn.close()
        return False
    
    expire_date = (datetime.strptime(created_date, '%Y-%m-%d %H:%M:%S') + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute("""
    INSERT INTO user_keys (email, public_key, encrypted_private_key, key_salt, created_date, expire_date, is_active)
    VALUES (?, ?, '', '', ?, ?, 0)
    """, (email, public_key_b64, created_date, expire_date))
    conn.commit()
    conn.close()
    return True