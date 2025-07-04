import hashlib
import os
import base64

def hash_passphrase(passphrase, salt=None):
    if salt is None:
        salt = os.urandom(16)   # 16 bytes
    salted_passphrase = passphrase.encode() + salt
    hash_value = hashlib.sha256(salted_passphrase).digest()
    hash_b64 = base64.b64encode(hash_value).decode()
    salt_b64 = base64.b64encode(salt).decode()
    return hash_b64, salt_b64
