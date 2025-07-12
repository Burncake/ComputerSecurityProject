import hashlib
import os
import json
from datetime import datetime
import base64
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from modules.utils.rsa_key_helper import load_key_from_file, decrypt_private_key, derive_aes_key_from_hash
from modules.utils.db_helper import get_user_auth_info
from modules.utils import logger

class DigitalSignatureHelper:
    def __init__(self):
        self.backend = default_backend()
        self.log_file = "data/logs/signature_log.json"
        os.makedirs("data/logs", exist_ok=True)
    
    def calculate_sha256(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.digest()
    
    def sign_file(self, file_path, signer_email, private_key_pem=None):
        """
        Sign a file with digital signature
        Returns the signature file path and signature data
        """
        # Calculate SHA-256 hash
        file_hash = self.calculate_sha256(file_path)
        
        # Load private key if not provided
        if private_key_pem is None:
            raise ValueError("Private key is required for signing")
        
        # Load private key from PEM data
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        
        # Sign the hash
        signature = private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Get file info
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Create signature data
        signature_data = {
            "file_path": os.path.abspath(file_path),
            "file_name": file_name,
            "file_size": file_size,
            "sha256_hash": base64.b64encode(file_hash).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "signer_email": signer_email,
            "timestamp": datetime.now().isoformat(),
            "unix_timestamp": int(time.time()),
            "algorithm": "RSA-PSS with SHA-256",
            "key_size": private_key.key_size
        }
        
        # Create signature file
        sig_file_path = file_path + ".sig"
        with open(sig_file_path, 'w', encoding='utf-8') as f:
            json.dump(signature_data, f, indent=2, ensure_ascii=False)
        
        # Log signing activity
        self._log_signing_activity(file_path, signer_email, sig_file_path, "SIGN_SUCCESS")
        
        return sig_file_path, signature_data
    
    def verify_signature(self, file_path, sig_file_path, public_key_pem=None):
        """Verify digital signature"""
        try:
            # Load signature data
            with open(sig_file_path, 'r', encoding='utf-8') as f:
                signature_data = json.load(f)
            
            # Calculate current file hash
            current_hash = self.calculate_sha256(file_path)
            
            # Compare with stored hash
            stored_hash = base64.b64decode(signature_data["sha256_hash"])
            if current_hash != stored_hash:
                self._log_verification_activity(file_path, sig_file_path, "VERIFY_FAIL_MODIFIED")
                return False, "File has been modified since signing"
            
            # Load public key
            if public_key_pem is None:
                signer_email = signature_data.get("signer_email")
                if not signer_email:
                    return False, "No signer email in signature file"
                
                # Try to load public key from system
                pub_key_path = f"data/keys/{signer_email}/{signer_email}_pub.pem"
                if not os.path.exists(pub_key_path):
                    return False, f"Public key not found for signer: {signer_email}"
                
                public_key_pem = load_key_from_file(pub_key_path, binary=True)
            
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            # Verify signature
            signature = base64.b64decode(signature_data["signature"])
            public_key.verify(
                signature,
                current_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self._log_verification_activity(file_path, sig_file_path, "VERIFY_SUCCESS")
            return True, "Signature is valid"
            
        except Exception as e:
            self._log_verification_activity(file_path, sig_file_path, f"VERIFY_FAIL_ERROR: {str(e)}")
            return False, f"Verification failed: {str(e)}"
    
    def get_user_private_key(self, email, passphrase=None):
        """Get user's private key from encrypted storage"""
        try:
            # Get user auth info
            row = get_user_auth_info(email)
            if not row:
                raise ValueError("User not found")
            
            stored_hash_b64, stored_salt_b64, *_ = row
            
            # If passphrase provided, verify it
            if passphrase:
                from modules.utils.crypto_helper import hash_passphrase
                input_hash_b64, _ = hash_passphrase(passphrase, base64.b64decode(stored_salt_b64))
                if input_hash_b64 != stored_hash_b64:
                    raise ValueError("Incorrect passphrase")
            
            # Load and decrypt private key
            priv_enc_path = f"data/keys/{email}/{email}_priv.enc"
            with open(priv_enc_path, "r") as f:
                enc_data = json.load(f)
            
            salt = base64.b64decode(enc_data["salt"])
            aes_key, _ = derive_aes_key_from_hash(stored_hash_b64, salt)
            private_key_pem = decrypt_private_key(enc_data, aes_key)
            
            if not private_key_pem:
                raise ValueError("Failed to decrypt private key")
            
            return private_key_pem
            
        except Exception as e:
            raise ValueError(f"Failed to get private key: {str(e)}")
    
    def _log_signing_activity(self, file_path, signer_email, sig_file_path, status):
        """Log signing activity"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "unix_timestamp": int(time.time()),
            "action": "SIGN",
            "status": status,
            "file_path": os.path.abspath(file_path),
            "file_name": os.path.basename(file_path),
            "signer_email": signer_email,
            "signature_file": sig_file_path
        }
        
        self._write_log_entry(log_entry)
        logger.log_info(f"Digital signature: {status} - File: {os.path.basename(file_path)} - Signer: {signer_email}")
    
    def _log_verification_activity(self, file_path, sig_file_path, status):
        """Log verification activity"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "unix_timestamp": int(time.time()),
            "action": "VERIFY",
            "status": status,
            "file_path": os.path.abspath(file_path),
            "file_name": os.path.basename(file_path),
            "signature_file": sig_file_path
        }
        
        self._write_log_entry(log_entry)
        logger.log_info(f"Signature verification: {status} - File: {os.path.basename(file_path)}")
    
    def _write_log_entry(self, log_entry):
        """Write log entry to file"""
        # Read existing log or create new one
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                logs = []
        else:
            logs = []
        
        # Add new log entry
        logs.append(log_entry)
        
        # Keep only last 1000 entries
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        # Write back to log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    
    def get_signature_info(self, sig_file_path):
        """Get information from signature file"""
        try:
            with open(sig_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Cannot read signature file: {str(e)}")
    
    def get_signature_logs(self, limit=50):
        """Get recent signature logs"""
        try:
            if not os.path.exists(self.log_file):
                return []
            
            with open(self.log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            
            # Return last 'limit' entries, most recent first
            return logs[-limit:][::-1]
        except Exception:
            return []
    
    def verify_file_integrity(self, file_path, expected_hash):
        """Verify file integrity against expected hash"""
        current_hash = self.calculate_sha256(file_path)
        expected_hash_bytes = base64.b64decode(expected_hash)
        return current_hash == expected_hash_bytes

# Convenience functions for GUI integration
def sign_file_with_user(file_path, signer_email, passphrase=None):
    """Sign a file using user's stored private key"""
    helper = DigitalSignatureHelper()
    
    try:
        # Get user's private key
        private_key_pem = helper.get_user_private_key(signer_email, passphrase)
        
        # Sign the file
        sig_file_path, signature_data = helper.sign_file(file_path, signer_email, private_key_pem)
        
        return True, sig_file_path, signature_data
        
    except Exception as e:
        return False, None, str(e)

def verify_file_signature(file_path, sig_file_path, public_key_pem=None):
    """Verify a file's digital signature"""
    helper = DigitalSignatureHelper()
    
    try:
        is_valid, message = helper.verify_signature(file_path, sig_file_path, public_key_pem)
        return is_valid, message
        
    except Exception as e:
        return False, f"Verification error: {str(e)}"

def get_signature_details(sig_file_path):
    """Get detailed information about a signature file"""
    helper = DigitalSignatureHelper()
    
    try:
        return helper.get_signature_info(sig_file_path)
    except Exception as e:
        return None

def get_recent_signature_activity(limit=50):
    """Get recent signature activity logs"""
    helper = DigitalSignatureHelper()
    return helper.get_signature_logs(limit)