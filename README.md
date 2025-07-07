# Computer Security Project 1

## Project Description

This project simulates a secure system including:

* User registration and login with password hashing and salting (PBKDF2 + SHA256)
* RSA key management (2048-bit) with automatic expiration (90 days)
* Private key encryption using AES-256-CBC derived from passphrase
* Public key storage with email association and creation timestamps
* Key status monitoring and expiration warnings
* PEM file export functionality for keys
* Multi-factor authentication (MFA) with TOTP (planned)
* Encryption and decryption of files (AES + RSA hybrid encryption) (planned)
* Digital signature and verification (planned)
* Account management and recovery (planned)
* Admin functionalities and logging (planned)

## Technology Stack

* Python 3.12.10
* Tkinter for GUI
* SQLite3 for database
* pycryptodome for RSA and AES cryptography
* PBKDF2 for key derivation
* Base64 encoding for key storage
* pyotp for TOTP (planned)
* qrcode for QR code generation (planned)
* pillow for image processing (planned)

## Project Structure

```
/COMPUTER_SECURITY_PROJECT
├── main.py                     # Main application entry point
├── requirements.txt            # Python dependencies
├── test_rsa.py                # RSA functionality tests
├── gui/
│   ├── main_window.py         # Main application window
│   ├── login_window.py        # User login interface
│   ├── register_window.py     # User registration interface
│   └── key_management_window.py # RSA key management interface
├── modules/
│   ├── auth/
│   │   ├── __init__.py
│   │   └── database.py        # User and key database management
│   ├── key_mgmt/
│   │   ├── __init__.py
│   │   └── rsa_manager.py     # RSA key generation and encryption
│   └── crypto/                # Future cryptographic modules
├── data/                      # Database and key storage
│   ├── security_system.db     # SQLite database (auto-created)
│   └── keys/                  # Exported key files (auto-created)
└── README.md
```

## Features Implemented

### User Authentication System
- **User Registration**: Secure user registration with password validation
- **Password Security**: PBKDF2-SHA256 hashing with random salt (100,000 iterations)
- **User Login**: Credential verification and session management
- **Database Storage**: SQLite database for user and key management

### RSA Key Management System
- **2048-bit RSA Key Generation**: Secure RSA key pair generation
- **Private Key Encryption**: AES-256-CBC encryption of private keys using user passphrase
- **Key Derivation**: PBKDF2-SHA256 for deriving AES keys from passphrases
- **Automatic Expiration**: 90-day validity period for all generated keys
- **Key Status Monitoring**: Real-time key status and expiration tracking
- **PEM Export**: Export keys to standard PEM format files
- **Email Association**: Keys are linked to user email addresses
- **Multiple Key Support**: Users can have multiple keys with different expiration dates

### Planned Features
- Multi-factor authentication (MFA) with TOTP
- File encryption/decryption using hybrid AES+RSA
- Digital signatures and verification
- QR code generation for key sharing
- Admin dashboard and logging
- Key recovery mechanisms

## How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/Burncake/ComputerSecurityProject.git
   cd ComputerSecurityProject
   ```

2. Install system dependencies (Ubuntu/Debian):

   ```bash
   sudo apt update
   sudo apt install python3-tk python3-pip
   ```

3. Create a virtual environment and install Python dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. Run the main program:

   ```bash
   python3 main.py
   ```

5. (Optional) Run tests to verify functionality:

   ```bash
   python3 test_rsa.py
   ```

## Usage Guide

### Registration
1. Click "Register" in the main window
2. Enter username, email, and a secure passphrase
3. Optionally enable auto-generation of RSA key pair
4. Complete registration

### Login and Key Management
1. Click "Login" in the main window
2. Enter your credentials
3. Access the Key Management window to:
   - Generate new RSA key pairs
   - View key status and expiration dates
   - Export keys to PEM files
   - Monitor key validity

### Key Security Features
- **Private keys** are encrypted with AES-256-CBC using your passphrase
- **Public keys** are stored in Base64 format
- **Keys expire** automatically after 90 days
- **Export functionality** saves keys in standard PEM format

## Contribution Guidelines

* Create a feature branch before working:

  ```bash
  git checkout -b feature/your-feature-name
  ```
* Follow Python PEP 8 coding standards
* Add tests for new functionality
* Commit changes with meaningful messages
* Push and create a Pull Request

## Testing

The project includes comprehensive tests:

```bash
# Run all RSA functionality tests
python3 test_rsa.py

# Test specific components
python3 -c "from modules.key_mgmt.rsa_manager import RSAKeyManager; print('RSA Manager OK')"
python3 -c "from modules.auth.database import DatabaseManager; print('Database Manager OK')"
```

## Security Notes

- **Never share your private keys** or passphrases
- **Keys expire after 90 days** for security - generate new ones regularly
- **Passphrases must be strong**: minimum 8 characters with uppercase, lowercase, digits, and special characters
- **Database is local**: stored in `data/security_system.db`
- **Exported keys**: stored in `data/keys/` directory

## Authors

* 22127021 - Phan Thế Anh
* 22127127 - Nguyễn Khánh Hoàng
* 22127422 - Lê Thanh Minh Trí
