import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta

class DatabaseManager:
    def __init__(self, db_path="data/security_system.db"):
        self.db_path = db_path
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()

    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')

        # RSA Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rsa_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # MFA table for TOTP secrets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                totp_secret TEXT NOT NULL,
                is_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        conn.commit()
        conn.close()

    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)
        return password_hash.hex(), salt

    def create_user(self, username, email, password):
        """Create a new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Check if user already exists
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                return False, "User already exists"

            # Hash password
            password_hash, salt = self.hash_password(password)

            # Insert user
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, salt))

            user_id = cursor.lastrowid
            conn.commit()
            return True, user_id

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    def verify_user(self, username, password):
        """Verify user credentials"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, password_hash, salt FROM users 
            WHERE username = ? AND is_active = TRUE
        ''', (username,))
        
        result = cursor.fetchone()
        conn.close()

        if result:
            user_id, stored_hash, salt = result
            password_hash, _ = self.hash_password(password, salt)
            
            if password_hash == stored_hash:
                return True, user_id
        
        return False, None

    def get_user_by_id(self, user_id):
        """Get user information by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, username, email, created_at FROM users 
            WHERE id = ? AND is_active = TRUE
        ''', (user_id,))
        
        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'created_at': result[3]
            }
        return None

    def save_rsa_key(self, user_id, email, public_key, private_key_encrypted, key_size=2048):
        """Save RSA key pair for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Deactivate old keys
            cursor.execute('''
                UPDATE rsa_keys SET is_active = FALSE 
                WHERE user_id = ? AND is_active = TRUE
            ''', (user_id,))

            # Calculate expiry date (90 days from now)
            expires_at = datetime.now() + timedelta(days=90)

            # Insert new key
            cursor.execute('''
                INSERT INTO rsa_keys (user_id, email, public_key, private_key_encrypted, 
                                    key_size, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, email, public_key, private_key_encrypted, key_size, expires_at))

            key_id = cursor.lastrowid
            conn.commit()
            return True, key_id

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    def get_user_keys(self, user_id):
        """Get all keys for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, email, public_key, private_key_encrypted, key_size, 
                   created_at, expires_at, is_active
            FROM rsa_keys 
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user_id,))
        
        results = cursor.fetchall()
        conn.close()

        keys = []
        for result in results:
            keys.append({
                'id': result[0],
                'email': result[1],
                'public_key': result[2],
                'private_key_encrypted': result[3],
                'key_size': result[4],
                'created_at': result[5],
                'expires_at': result[6],
                'is_active': result[7]
            })
        
        return keys

    def get_active_key(self, user_id):
        """Get active RSA key for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, email, public_key, private_key_encrypted, key_size, 
                   created_at, expires_at
            FROM rsa_keys 
            WHERE user_id = ? AND is_active = TRUE AND expires_at > CURRENT_TIMESTAMP
            ORDER BY created_at DESC
            LIMIT 1
        ''', (user_id,))
        
        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'id': result[0],
                'email': result[1],
                'public_key': result[2],
                'private_key_encrypted': result[3],
                'key_size': result[4],
                'created_at': result[5],
                'expires_at': result[6]
            }
        return None
