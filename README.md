# Computer Security Project 1

## Project Description

This project simulates a secure system including:

* User registration and login with password hashing and salting
* Multi-factor authentication (MFA) with TOTP
* RSA key management and QR codes
* Encryption and decryption of files (AES + RSA hybrid encryption)
* Digital signature and verification
* Account management and recovery
* Admin functionalities and logging

## Technology Stack

* Python 3.12.10
* Tkinter for GUI
* pycryptodome
* pyotp
* qrcode
* pillow
* sqlite3

## Project Structure

```
/COMPUTER_SECURITY_PROJECT
├── main.py
├── requirements.txt
├── gui/
│    ├── main_window.py
│    ├── login_window.py
│    ├── register_window.py
│    ├── ...
├── modules/
│    ├── auth/
│    ├── crypto/
│    ├── key_mgmt/
│    ├── ...
├── data/
├── report/
└── README.md
```

## How to Run

1. Clone the repository:

   ```
   git clone https://github.com/Burncake/ComputerSecurityProject.git
   cd ComputerSecurityProject
   ```

2. Create a virtual environment and install dependencies:

   ```
   python -m venv venv
   .\venv\Scripts\activate # Linux: source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Run the main program:

   ```
   python main.py
   ```

## Contribution Guidelines

* Create a feature branch before working:

  ```
  git checkout -b feature/your-feature-name
  ```
* Commit changes with meaningful messages
* Push and create a Pull Request

## Authors

* 22127021 - Phan Thế Anh
* 22127127 - Nguyễn Khánh Hoàng
* 22127422 - Lê Thanh Minh Trí
