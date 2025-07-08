import qrcode
import json
import base64
import zlib
from PIL import Image
import io
import os

def create_public_key_qr(email, created_date, public_key_b64):
    compressed_key = base64.b64encode(zlib.compress(public_key_b64.encode())).decode()
    
    qr_data = {
        "type": "rsa_public_key",
        "email": email,
        "created_date": created_date,
        "public_key": compressed_key
    }
    
    qr_content = json.dumps(qr_data)
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_content)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    return qr_image

def save_qr_image(qr_image, email):
    os.makedirs("data/qr_codes", exist_ok=True)
    filename = f"{email}_public_key_qr.png"
    filepath = os.path.join("data/qr_codes", filename)
    qr_image.save(filepath)
    return filepath

def get_qr_image_as_tk(qr_image):
    buffer = io.BytesIO()
    qr_image.save(buffer, format='PNG')
    buffer.seek(0)
    return Image.open(buffer)

def manual_qr_input_dialog(parent):
    import tkinter as tk
    from tkinter import messagebox
    
    dialog = tk.Toplevel(parent)
    dialog.title("Manual QR Code Input")
    dialog.geometry("500x400")
    dialog.resizable(False, False)
    
    tk.Label(dialog, text="Manual QR Code Data Entry", font=("Helvetica", 14, "bold")).pack(pady=10)
    tk.Label(dialog, text="Since QR scanning is not available, you can manually paste the QR code data here:").pack(pady=5)
    
    tk.Label(dialog, text="QR Code Data (JSON format):").pack(pady=(20, 5))
    text_area = tk.Text(dialog, height=15, width=60)
    text_area.pack(pady=5, padx=10, fill='both', expand=True)
    
    result = {'data': None, 'cancelled': False}
    
    def process_input():
        try:
            qr_data = text_area.get('1.0', tk.END).strip()
            if not qr_data:
                messagebox.showerror("Error", "Please enter QR code data")
                return
                
            data = json.loads(qr_data)
            
            if data.get("type") != "rsa_public_key":
                messagebox.showerror("Error", "Invalid QR code type")
                return
            
            compressed_key = data.get("public_key")
            public_key_b64 = zlib.decompress(base64.b64decode(compressed_key)).decode()
            
            result['data'] = {
                "email": data.get("email"),
                "created_date": data.get("created_date"),
                "public_key": public_key_b64
            }
            dialog.destroy()
            
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON format")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing data: {str(e)}")
    
    def cancel():
        result['cancelled'] = True
        dialog.destroy()
    
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=10)
    
    tk.Button(button_frame, text="Process", command=process_input, width=15).pack(side='left', padx=5)
    tk.Button(button_frame, text="Cancel", command=cancel, width=15).pack(side='right', padx=5)
    
    example_frame = tk.Frame(dialog)
    example_frame.pack(pady=10)
    
    tk.Label(example_frame, text="Example format:", font=("Helvetica", 10, "bold")).pack()
    example_text = '{"type": "rsa_public_key", "email": "user@example.com", "created_date": "2024-01-01 12:00:00", "public_key": "..."}'
    tk.Label(example_frame, text=example_text, font=("Courier", 8), fg="gray").pack()
    
    dialog.transient(parent)
    dialog.grab_set()
    parent.wait_window(dialog)
    
    if result['cancelled']:
        return None, "Cancelled"
    elif result['data']:
        return result['data'], "Success"
    else:
        return None, "No data processed"

def get_qr_data_as_text(email, created_date, public_key_b64):
    compressed_key = base64.b64encode(zlib.compress(public_key_b64.encode())).decode()
    
    qr_data = {
        "type": "rsa_public_key",
        "email": email,
        "created_date": created_date,
        "public_key": compressed_key
    }
    
    return json.dumps(qr_data, indent=2)