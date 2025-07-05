import pyotp
import qrcode
import io
import sqlite3
from PIL import Image
from modules.utils.db_helper import DB_PATH

def generate_totp_secret():
    return pyotp.random_base32()

def get_qr_image_uri(secret, username, issuer="Computer Security Project"):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    return uri

def generate_qr_image(uri):
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)
    return Image.open(buffer)
