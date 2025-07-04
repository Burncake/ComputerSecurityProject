import base64
import os
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import hashlib

class RSAKeyManager:
    def __init__(self):
        self.key_size = 2048
        
    def generate_key_pair(self):
        """Generate RSA key pair (2048 bit)"""
        key = RSA.generate(self.key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        return private_key, public_key
    
    def derive_aes_key(self, passphrase, salt=None):
        """Derive AES key from passphrase using PBKDF2"""
        if salt is None:
            salt = get_random_bytes(32)
        
        # Use PBKDF2 to derive a 256-bit key
        key = PBKDF2(passphrase, salt, 32, count=100000, hmac_hash_module=SHA256)
        return key, salt
    
    def encrypt_private_key(self, private_key, passphrase):
        """Encrypt private key using AES derived from passphrase"""
        try:
            # Derive AES key from passphrase
            aes_key, salt = self.derive_aes_key(passphrase)
            
            # Generate IV for AES
            iv = get_random_bytes(16)
            
            # Create AES cipher
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            
            # Pad and encrypt private key
            padded_key = pad(private_key, AES.block_size)
            encrypted_key = cipher.encrypt(padded_key)
            
            # Combine salt + iv + encrypted_key
            encrypted_data = salt + iv + encrypted_key
            
            # Return base64 encoded
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Failed to encrypt private key: {str(e)}")
    
    def decrypt_private_key(self, encrypted_private_key_b64, passphrase):
        """Decrypt private key using passphrase"""
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_private_key_b64)
            
            # Extract salt (32 bytes), IV (16 bytes), and encrypted key
            salt = encrypted_data[:32]
            iv = encrypted_data[32:48]
            encrypted_key = encrypted_data[48:]
            
            # Derive AES key from passphrase and salt
            aes_key, _ = self.derive_aes_key(passphrase, salt)
            
            # Create AES cipher
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            decrypted_padded = cipher.decrypt(encrypted_key)
            private_key = unpad(decrypted_padded, AES.block_size)
            
            return private_key
            
        except Exception as e:
            raise Exception(f"Failed to decrypt private key: {str(e)}")
    
    def save_key_to_pem(self, key_data, filename, key_type="private"):
        """Save key to PEM file"""
        try:
            # Ensure data directory exists
            data_dir = "data/keys"
            os.makedirs(data_dir, exist_ok=True)
            
            filepath = os.path.join(data_dir, filename)
            
            if key_type == "private":
                # If it's encrypted private key, save as base64
                if isinstance(key_data, str):
                    with open(filepath, 'w') as f:
                        f.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
                        # Split base64 into 64-character lines
                        for i in range(0, len(key_data), 64):
                            f.write(key_data[i:i+64] + "\n")
                        f.write("-----END ENCRYPTED PRIVATE KEY-----\n")
                else:
                    # Raw private key
                    with open(filepath, 'wb') as f:
                        f.write(key_data)
            else:
                # Public key
                with open(filepath, 'wb') as f:
                    f.write(key_data)
            
            return filepath
            
        except Exception as e:
            raise Exception(f"Failed to save key: {str(e)}")
    
    def load_key_from_pem(self, filepath):
        """Load key from PEM file"""
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load key: {str(e)}")
    
    def get_public_key_from_private(self, private_key_data):
        """Extract public key from private key"""
        try:
            key = RSA.import_key(private_key_data)
            return key.publickey().export_key()
        except Exception as e:
            raise Exception(f"Failed to extract public key: {str(e)}")
    
    def get_key_info(self, key_data):
        """Get information about RSA key"""
        try:
            key = RSA.import_key(key_data)
            return {
                'size': key.size_in_bits(),
                'has_private': key.has_private(),
                'n': key.n,
                'e': key.e
            }
        except Exception as e:
            raise Exception(f"Failed to get key info: {str(e)}")
    
    def format_key_for_display(self, key_data, max_length=50):
        """Format key for display (truncated base64)"""
        try:
            if isinstance(key_data, bytes):
                key_b64 = base64.b64encode(key_data).decode('utf-8')
            else:
                key_b64 = key_data
            
            if len(key_b64) > max_length:
                return key_b64[:max_length] + "..."
            return key_b64
            
        except Exception as e:
            return "Invalid key format"
    
    def is_key_expired(self, expires_at):
        """Check if key is expired"""
        try:
            if isinstance(expires_at, str):
                expires_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            else:
                expires_date = expires_at
            
            return datetime.now() > expires_date
        except:
            return True
    
    def get_days_until_expiry(self, expires_at):
        """Get number of days until key expires"""
        try:
            if isinstance(expires_at, str):
                expires_date = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            else:
                expires_date = expires_at
            
            delta = expires_date - datetime.now()
            return max(0, delta.days)
        except:
            return 0
    
    def create_key_pair_with_encryption(self, email, passphrase):
        """Create complete RSA key pair with encryption"""
        try:
            # Generate RSA key pair
            private_key, public_key = self.generate_key_pair()
            
            # Encrypt private key with passphrase
            encrypted_private_key = self.encrypt_private_key(private_key, passphrase)
            
            # Convert public key to base64 for storage
            public_key_b64 = base64.b64encode(public_key).decode('utf-8')
            
            return {
                'public_key': public_key_b64,
                'private_key_encrypted': encrypted_private_key,
                'public_key_raw': public_key,
                'private_key_raw': private_key,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(days=90),
                'key_size': self.key_size
            }
            
        except Exception as e:
            raise Exception(f"Failed to create key pair: {str(e)}")
