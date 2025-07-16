# 🔐 Secure CLI Password Manager (Python)

A simple yet secure password manager built using Python and the `cryptography` library. It allows you to **store** and **retrieve** credentials for different services using a master password (encrypted with PBKDF2 & AES).

---

## 🚀 Features

- 🔑 Master password protected
- 🔐 PBKDF2 with SHA256-based key derivation
- 🧊 AES-256 encryption using Fernet
- 📁 All data stored in encrypted files (`master.dat`, `passwords.dat`)
- 🧠 No third-party storage — local-only, secure, minimal

---

## 🛠️ Tech Stack

- **Python 3.10+**
- `cryptography` – for encryption
- `pickle` – for binary data storage
- `hashlib`, `base64`, `os` – for key generation and handling

---

## 🧪 How It Works

- When you **run the script for the first time**, it will ask you to create a **master password**.
- This password is hashed and stored securely.
- For each service (like "gmail", "twitter"), you can:
  - **Store** → Save a username & password
  - **Retrieve** → Get the stored credentials
- Everything is encrypted using Fernet (AES-128/256).

---

## 📦 Installation

```bash
# Clone this repository
git clone https://github.com/daksheshsharma2409/python-password-manager.git
cd python-password-manager

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
