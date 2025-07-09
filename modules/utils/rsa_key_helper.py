from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib

def derive_aes_key_from_hash(passphrase_hash_b64, salt=None):
    """
    Derive AES key from user's passphrase hash (stored in DB)
    """
    hash_bytes = base64.b64decode(passphrase_hash_b64)
    # optional salt - can be constant
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(hash_bytes, salt, dkLen=32, count=100_000)
    return key, salt

def generate_rsa_key_pair(bits=2048):
    """
    Generate RSA key pair
    """
    key = RSA.generate(bits)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    return private_key_pem, public_key_pem

def encrypt_private_key(private_key_pem, aes_key, salt):
    """
    Encrypt the private key using AES with a key derived from the passphrase.
    """
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem)

    data = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return data

def decrypt_private_key(encrypted_data, aes_key):
    """
    Decrypt the private key using AES and passphrase
    """
    nonce = base64.b64decode(encrypted_data["nonce"])
    tag = base64.b64decode(encrypted_data["tag"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        return None  # wrong passphrase or corrupted data

def save_key_to_file(path, data, binary=False):
    mode = "wb" if binary else "w"
    with open(path, mode) as f:
        f.write(data if binary else data.decode() if isinstance(data, bytes) else data)

def load_key_from_file(path, binary=False):
    mode = "rb" if binary else "r"
    with open(path, mode) as f:
        return f.read()

def get_public_key_fingerprint(public_key_pem):
    sha256 = hashlib.sha256(public_key_pem).hexdigest()
    # group every 2 hex for readability
    return ":".join([sha256[i:i+2] for i in range(0, len(sha256), 2)])