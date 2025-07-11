import os
import json
import base64
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def encrypt_file_for_user(
    sender_email: str,
    receiver_pub_pem: bytes,
    input_filepath: str,
    output_path: str,
    mode: str = "combined"
):
    """
    Encrypt a file for a given receiver.
    - sender_email: email of the sender
    - receiver_pub_pem: bytes of receiver's RSA public key (PEM)
    - input_filepath: path to plaintext file
    - output_path: if mode=='combined', .enc file path; if mode=='separate', directory path
    - mode: 'combined' or 'separate'
    Returns path(s) of created file(s).
    """
    # 1. Read plaintext
    with open(input_filepath, "rb") as f:
        plaintext = f.read()

    # 2. Generate AES-GCM session key
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # 3. Encrypt AES key with RSA
    pub_key = RSA.import_key(receiver_pub_pem)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_session_key = cipher_rsa.encrypt(aes_key)

    # 4. Metadata
    metadata = {
        "sender": sender_email,
        "receiver": pub_key.export_key().decode(),  # or just receiver email if preferred
        "filename": os.path.basename(input_filepath),
        "timestamp": int(time.time())
    }

    if mode == "combined":
        out = {
            "encrypted_session_key": base64.b64encode(enc_session_key).decode(),
            "nonce": base64.b64encode(cipher_aes.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "metadata": metadata
        }
        # save single JSON file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(out, f, indent=2)
        return output_path

    elif mode == "separate":
        # path is directory
        os.makedirs(output_path, exist_ok=True)
        # write ciphertext JSON
        enc_path = os.path.join(output_path, metadata["filename"] + ".enc")
        with open(enc_path, "w") as f:
            json.dump({
                "nonce": base64.b64encode(cipher_aes.nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "metadata": metadata
            }, f, indent=2)

        # write session key file
        key_path = os.path.join(output_path, metadata["filename"] + ".key")
        with open(key_path, "w") as f:
            json.dump({
                "encrypted_session_key": base64.b64encode(enc_session_key).decode()
            }, f, indent=2)

        return enc_path, key_path

    else:
        raise ValueError("mode must be 'combined' or 'separate'")

def decrypt_file_for_user(
    receiver_priv_pem: bytes,
    passphrase: str,
    encrypted_path: str,
    key_path: str = None,
    output_filepath: str = None
):
    """
    Decrypt a file encrypted by encrypt_file_for_user.
    - receiver_priv_pem: bytes of the *decrypted* private key PEM
    - passphrase: passphrase to decrypt .enc if needed
    - encrypted_path: path to combined .enc (if key_path None) or ciphertext file
    - key_path: path to .key file if separate mode (else None)
    - output_filepath: where to write the plaintext (defaults to input filename)
    Returns output_filepath.
    """
    # Load encrypted JSON
    with open(encrypted_path, "r") as f:
        enc_json = json.load(f)

    # Extract session key
    if key_path:
        # separate mode
        with open(key_path, "r") as f:
            key_json = json.load(f)
        enc_session_key = base64.b64decode(key_json["encrypted_session_key"])
    else:
        enc_session_key = base64.b64decode(enc_json["encrypted_session_key"])

    # Decrypt session key with RSA private key
    priv_key = RSA.import_key(receiver_priv_pem, passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    aes_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt ciphertext
    nonce = base64.b64decode(enc_json["nonce"])
    tag = base64.b64decode(enc_json["tag"])
    ciphertext = base64.b64decode(enc_json["ciphertext"])

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Determine output path
    if not output_filepath:
        # derive from encrypted filename
        base = os.path.basename(encrypted_path)
        if base.endswith(".enc"):
            out_name = base[:-4]
        else:
            out_name = base + ".dec"
        output_filepath = os.path.join(os.path.dirname(encrypted_path), out_name)

    # Write plaintext
    with open(output_filepath, "wb") as f:
        f.write(plaintext)

    return output_filepath
