# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- RSA Key Management System
- User Authentication with Database Storage
- Key Expiration and Monitoring
- PEM Export Functionality

## [0.2.0] - 2025-07-04

### Added
- **RSA Key Management System**
  - 2048-bit RSA key pair generation
  - AES-256-CBC encryption of private keys using user passphrase
  - PBKDF2-SHA256 key derivation from passphrases (100,000 iterations)
  - Automatic 90-day key expiration
  - Key status monitoring and expiration warnings
  - PEM file export for both public and private keys
  - Multiple key support per user

- **Enhanced User Authentication**
  - SQLite database integration for user storage
  - PBKDF2-SHA256 password hashing with random salt
  - Secure user registration with password validation
  - User login and session management

- **GUI Improvements**
  - Key Management Window with comprehensive key listing
  - Real-time key status display (Active/Expired/Inactive)
  - Key details view with creation and expiration dates
  - Export functionality with file dialog
  - Progress indicators for key generation

- **Database Schema**
  - Users table with secure password storage
  - RSA keys table with metadata (email, creation, expiration)
  - Foreign key relationships and data integrity

- **Testing Framework**
  - Comprehensive RSA functionality tests
  - Database integration tests
  - Key encryption/decryption verification
  - Key expiry logic testing

### Technical Details
- **Encryption**: AES-256-CBC with random IV and salt
- **Key Derivation**: PBKDF2-SHA256 with 100,000 iterations
- **Key Storage**: Base64 encoding for database storage
- **File Format**: Standard PEM format for exports
- **Key Size**: 2048-bit RSA keys (industry standard)

### Files Added
- `modules/auth/database.py` - Database management
- `modules/key_mgmt/rsa_manager.py` - RSA operations
- `gui/login_window.py` - User login interface
- `gui/key_management_window.py` - Key management interface
- `test_rsa.py` - Comprehensive test suite
- `requirements-minimal.txt` - Minimal dependencies

### Files Modified
- `gui/register_window.py` - Enhanced with database integration and auto-key generation
- `gui/main_window.py` - Added login integration
- `main.py` - Updated application entry point
- `README.md` - Comprehensive documentation update
- `requirements.txt` - Updated with detailed descriptions

## [0.1.0] - Initial Release

### Added
- Basic project structure
- Initial GUI framework with Tkinter
- Basic registration window
- Main application window structure
- Initial requirements setup

### Technical Stack
- Python 3.12.10
- Tkinter for GUI
- Basic project organization
