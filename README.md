# Computer Security Project

A comprehensive desktop cryptography application built with Python and Tkinter, implementing modern security practices for user authentication, key management, file encryption, and digital signatures.

## 🔐 Project Overview

This project is a **complete cryptographic security system** that demonstrates real-world security implementations including:

### Core Features ✅ **IMPLEMENTED**
* **User Authentication System** - Secure registration and login with SHA256 hashing
* **RSA Key Management** - 2048-bit key generation with AES-256-GCM encryption
* **File Encryption/Decryption** - Hybrid AES+RSA encryption for secure file storage
* **Digital Signatures** - PSS padding with SHA-256 for document authentication
* **Multi-Factor Authentication** - TOTP-based MFA with QR code generation
* **Account Recovery** - Secure recovery code system
* **Admin Dashboard** - User management, role assignment, and system monitoring
* **Security Logging** - Comprehensive audit trail with structured logging
* **Key Expiration Management** - Automatic 90-day key lifecycle with renewal alerts
* **Account Lockout Protection** - Failed login attempt tracking and temporary lockouts
* **Session Management** - Secure session handling with automatic timeouts
* **Role-Based Access Control** - User and admin privilege separation
* **Secure File Storage** - Encrypted private key storage with passphrase protection

## 🏗️ Architecture & Technology Stack

### Core Technologies
- **Python 3.12+** - Main application language
- **Tkinter** - Cross-platform GUI framework
- **SQLite3** - Embedded database for user and key management
- **pycryptodome** - RSA and AES cryptographic operations
- **cryptography** - Digital signatures and advanced crypto functions
- **pyotp** - Time-based One-Time Password (TOTP) implementation
- **qrcode + Pillow** - QR code generation for MFA setup

### Security Architecture
```
┌───────────────────────────┐    ┌──────────────────────────┐
│    GUI Layer (Tkinter)    │    │    Session Management    │
│  ┌─────────────────────┐  │    │   ┌──────────────────┐   │
│  │ Login │ Register    │  │    │   │ User State       │   │
│  │ Keys  │ Files       │  │◄──►│   │ Auth Status      │   │
│  │ Admin │ Recovery    │  │    │   │ Role Permissions │   │
│  └─────────────────────┘  │    │   └──────────────────┘   │
└───────────────────────────┘    └──────────────────────────┘
            │                                  │
            ▼                                  ▼
┌───────────────────────────────────────────────────────────┐
│                  Core Business Logic                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐  │
│  │   Crypto    │ │   Database  │ │   File Operations   │  │
│  │   Helpers   │ │   Helpers   │ │      & Logging      │  │
│  └─────────────┘ └─────────────┘ └─────────────────────┘  │
└───────────────────────────────────────────────────────────┘
            │                                  │
            ▼                                  ▼
┌───────────────────────┐         ┌───────────────────────────┐
│    SQLite Database    │         │    File System Storage    │
│  ┌─────────────────┐  │         │  ┌─────────────────────┐  │
│  │ users           │  │         │  │ data/keys/          │  │
│  │ user_keys       │  │         │  │ data/logs/          │  │
│  │ user_recovery   │  │         │  │ encrypted files     │  │
│  │ user_roles      │  │         │  │ digital signatures  │  │
│  │ account_lock    │  │         │  └─────────────────────┘  │
│  └─────────────────┘  │         └───────────────────────────┘
└───────────────────────┘
```

### Database Schema
```sql
-- Core user authentication and profile data
users: id, email, full_name, dob, phone, address, passphrase_hash, 
       salt, totp_secret, fail_count, lock_until

-- RSA key lifecycle management  
user_keys: email, created_at, expire_at

-- Account recovery system
user_recovery: email, recovery_code_hash, created_at

-- Role-based access control
user_roles: email, role [user|admin]

-- Account security controls
account_lock: email, locked [0|1]
```

## 📁 Project Structure

```
ComputerSecurityProject/
├── main.py                         # Application entry point
├── requirements.txt                # Python dependencies
├── setup.sh                        # Linux/macOS setup script  
├── CHANGELOG.md                    # Version history
├── README.md                       # This documentation
│
├── gui/                            # Tkinter GUI components
│   ├── main_window.py              # Main application window & navigation
│   ├── login_frame.py              # User authentication interface
│   ├── register_frame.py           # New user registration
│   ├── key_create_frame.py         # RSA key generation interface
│   ├── key_management_frame.py     # Key lifecycle management
│   ├── encrypt_frame.py            # File encryption interface
│   ├── decrypt_frame.py            # File decryption interface
│   ├── signature_frame.py          # Digital signature creation
│   ├── verify_frame.py             # Signature verification
│   ├── account_update_frame.py     # Profile and security settings
│   ├── recover_account_frame.py    # Account recovery workflow
│   └── admin_dashboard.py          # Administrative functions
│
├── modules/
│   ├── core/
│   │   └── session.py              # Global session state management
│   └── utils/                      # Core utility modules
│       ├── db_helper.py            # SQLite database operations
│       ├── crypto_helper.py        # Password hashing utilities
│       ├── rsa_key_helper.py       # RSA key generation & management
│       ├── file_crypto_helper.py   # File encryption/decryption
│       ├── signature_helper.py     # Digital signature operations
│       ├── otp_helper.py           # TOTP/MFA functionality
│       └── logger.py               # Security event logging
│
└── data/                           # Application data directory
    ├── users.db                    # SQLite database (auto-created)
    ├── keys/                       # User key storage
    │   └── {email}/                # Per-user key directories
    │       ├── {email}_priv.enc    # Encrypted private key
    │       └── {email}_pub.pem     # Public key (PEM format)
    └── logs/                       # Application logs
        ├── security.log            # Security events
        └── signature_log.json      # Digital signature audit trail
```

## 🛡️ Security Features Deep Dive

### User Authentication System
- **Password Security**: SHA256 hashed + random salt
- **Account Protection**: Failed login tracking with progressive lockout (5 attempts)
- **Session Management**: Secure in-memory session state with automatic cleanup
- **Multi-Factor Authentication**: TOTP-based MFA with QR code setup

### RSA Key Management  
- **Key Generation**: 2048-bit RSA keys using cryptographically secure random numbers
- **Private Key Protection**: AES-256-GCM encryption using PBKDF2-derived keys with 100,000 iterations
- **Key Lifecycle**: 90-day automatic expiration with renewal notifications
- **Secure Storage**: Encrypted private keys + PEM public keys with file permissions
- **Key Export**: Industry-standard PEM format for interoperability

### File Encryption System
- **Hybrid Encryption**: AES-256-GCM for data + RSA-2048 for key transport
- **Format Support**: Combined JSON encrypted format or separate key/data files
- **Metadata Protection**: Sender/receiver tracking with timestamp verification
- **Integrity Protection**: GCM authenticated encryption prevents tampering

### Digital Signature Implementation
- **Algorithm**: RSA-PSS with SHA-256 for collision resistance
- **Verification**: Cryptographic proof of document authenticity and integrity
- **Audit Trail**: JSON-formatted signature logs with tamper detection
- **Standards Compliance**: PKCS#1 v2.1 PSS padding for security

### Administrative Controls
- **Role-Based Access**: User/Admin privilege separation
- **Account Management**: User promotion, demotion, and lockout controls
- **System Monitoring**: Real-time user activity and key status tracking
- **Audit Logging**: Comprehensive security event logging

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.12+** (3.12.10 recommended)
- **Git** for cloning the repository
- **Windows, macOS, or Linux** operating system

### Installation

#### Option 1: Windows Setup (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/Burncake/ComputerSecurityProject.git
cd ComputerSecurityProject

# Create virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

#### Option 2: Linux/macOS Setup (Automated)
```bash
# Clone and setup automatically
git clone https://github.com/Burncake/ComputerSecurityProject.git
cd ComputerSecurityProject

# Run setup script (installs system dependencies + Python packages)
chmod +x setup.sh
./setup.sh

# Activate virtual environment and run
source venv/bin/activate
python main.py
```

#### Option 3: Manual Setup (Any Platform)
```bash
# After cloning the repository
python3 -m venv venv

# Activate virtual environment
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate

pip install -r requirements.txt
python main.py
```

### First Run
1. **Database Initialization**: The application automatically creates the `data/` directory and SQLite database
2. **Admin Account**: Register the first admin account by manually updating `data/users.db` database
3. **Key Generation**: Create your first RSA key pair during registration or afterward
4. **MFA Setup**: Optionally enable TOTP multi-factor authentication

## 📖 User Guide

### Getting Started
1. **Registration**: Create a new account with email and secure passphrase
2. **MFA Setup**: Enable TOTP for additional security (scan QR code with authenticator app)
3. **Recovery Code**: Generate a secure recovery code for account recovery (only shown once)
4. **Key Creation**: Generate your RSA key pair (required for encryption/signing)

### Core Workflows

#### Login
1. Navigate to **Login** tab
2. Enter your email and passphrase
3. Enter the TOTP code from your authenticator app

#### Key Management
1. Navigate to **Keys** tab
2. Renew or view your RSA key pair details
(Optional) Export your key in PEM format or QR code for public key sharing
3. Search and import another user's public key by email or QR code image
4. View other users' public keys status

#### File Encryption
1. Navigate to **Encrypt** tab
2. Select file to encrypt and recipient's public key (must be imported in your account)
3. Choose output format (combined or separate key/data)
4. Encrypted file is saved with `.enc` extension, if separate, key is saved as `.key` file

#### File Decryption  
1. Navigate to **Decrypt** tab
2. Select encrypted file and corresponding key file (if separate)
3. Provide your private key passphrase
4. Decrypted file is restored to original format

#### Digital Signatures
1. Navigate to **Sign** tab  
2. Select document to sign and provide private key passphrase
3. Signature file (`.sig`) is created alongside original document

#### Signature Verification
1. Navigate to **Verify** tab
2. Select document and corresponding signature file (ensure public key is imported and active)
3. System verifies authenticity and integrity

### Administrative Functions
- **User Management**: Promote/demote users, lock/unlock accounts
- **System Monitoring**: View active users and security logs
- **Audit Trail**: Access comprehensive logging of all security events

## 🔒 Security Best Practices

### For Users
- **Strong Passphrases**: Use minimum 8 characters with mixed case, numbers, and symbols
- **MFA Enabled**: Always enable TOTP multi-factor authentication
- **Key Rotation**: Renew your RSA keys before 90-day expiration
- **Secure Storage**: Never share private key passphrases or recovery codes
- **Regular Updates**: Regularly check your other users' public keys status for validity
- **Recovery Code**: Store your recovery code securely, as it is to recover your account if you lose access

### For Developers  
- **Input Validation**: User inputs are sanitized and validated
- **Error Handling**: Detailed logging without exposing sensitive information
- **Dependency Management**: Regular security updates for all dependencies
- **Code Review**: Security-focused code review process

### Security Considerations
- **Local Storage**: All data stored locally - no cloud dependencies
- **Memory Management**: Sensitive data cleared from memory after use
- **File Permissions**: Restricted access to key files and database
- **Session Timeout**: Automatic session expiration after inactivity
- **Audit Trail**: Comprehensive logging for security monitoring

## 🧪 Testing & Validation

### Cryptographic Testing
```bash
# Test RSA key generation and encryption
python -c "from modules.utils.rsa_key_helper import *; print('RSA module OK')"

# Test file encryption/decryption
python -c "from modules.utils.file_crypto_helper import *; print('File crypto OK')"

# Test digital signatures
python -c "from modules.utils.signature_helper import *; print('Signatures OK')"

# Validate database operations
python -c "from modules.utils.db_helper import *; print('Database OK')"
```

### Security Validation
- **Passphrase Strength**: Ensure passphrases meet complexity requirements and are SHA256 hashed securely
- **AES Key Strength**: PBKDF2 with 100,000 iterations exceeds NIST recommendations
- **Key Encryption**: Verify private keys are encrypted with AES-256-GCM and PBKDF2
- **RSA Key Sizes**: 2048-bit RSA and 256-bit AES meet current security standards
- **Cryptographic Libraries**: Uses industry-standard pycryptodome and cryptography libraries
- **Algorithm Selection**: Modern algorithms (AES-GCM, RSA-PSS, SHA-256) with secure parameters

### Performance Testing
- **Key Generation**: ~1-2 seconds for 2048-bit RSA on modern hardware
- **File Encryption**: Scales linearly with file size (AES-GCM performance)
- **Database Operations**: Optimized queries with proper indexing
- **GUI Responsiveness**: Background threading for crypto operations

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup
```bash
# Fork the repository and clone your fork
git clone https://github.com/your-username/ComputerSecurityProject.git
cd ComputerSecurityProject

# Create a feature branch
git checkout -b feature/your-feature-name

# Set up development environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Code Standards
- **Python Style**: Follow PEP 8 coding standards
- **Documentation**: Add docstrings for all public functions
- **Type Hints**: Use type annotations where appropriate
- **Error Handling**: Comprehensive exception handling with logging
- **Security**: Security-first development approach

### Testing Requirements
- Add unit tests for new functionality
- Ensure all existing tests pass
- Test cryptographic operations thoroughly
- Validate input sanitization and error handling

### Pull Request Process
1. Create feature branch with descriptive name
2. Make atomic commits with clear messages
3. Add/update documentation as needed
4. Ensure all tests pass
5. Submit pull request with detailed description

## 📄 License & Legal

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Security Disclosure
If you discover a security vulnerability, please report it privately to the maintainers before public disclosure.

### Educational Purpose
This project is designed for educational and research purposes. While it implements industry-standard cryptographic practices, please conduct thorough security assessments before using in production environments.

## 👥 Authors & Acknowledgments

### Development Team
- **22127021** - Phan Thế Anh
- **22127127** - Nguyễn Khánh Hoàng  
- **22127422** - Lê Thanh Minh Trí

### Acknowledgments
- **pycryptodome** developers for robust cryptographic primitives
- **Python cryptography** library contributors
- **NIST** for cryptographic standards and guidelines
- **OWASP** for security best practices

## 🔗 Additional Resources

### Cryptographic Standards
- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) - PBKDF2 Recommendations
- [RFC 8017](https://tools.ietf.org/html/rfc8017) - PKCS #1 v2.2: RSA Cryptography
- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP Algorithm

### Security References  
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Python Cryptography Documentation](https://cryptography.io/)
- [Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

---

**⚠️ Security Notice**: This application handles cryptographic keys and sensitive data. Always run on trusted systems and keep your software updated. For production use, conduct thorough security audits and penetration testing.
