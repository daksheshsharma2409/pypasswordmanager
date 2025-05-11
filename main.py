import os
import pickle
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

MASTER_PASSWORD_FILE = "master.dat"
PASSWORD_DATA_FILE = "passwords.dat"

def store_master_password_hash_secure(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    try:
        with open(MASTER_PASSWORD_FILE, "wb") as f:
            pickle.dump((salt, key), f)
        print("Master password set and stored securely using PBKDF2.")
        return True, salt
    except Exception as e:
        print(f"Error storing master password: {e}")
        return False, None

def verify_master_password_secure():
    if os.path.exists(MASTER_PASSWORD_FILE):
        entered_master = input("Enter your master password: ")
        try:
            with open(MASTER_PASSWORD_FILE, "rb") as f:
                stored_salt, stored_key = pickle.load(f)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=stored_salt,
                iterations=100000,
                backend=default_backend()
            )
            entered_key = kdf.derive(entered_master.encode())
            if entered_key == stored_key:
                print("Master password verified.")
                return True, stored_salt
            else:
                print("Incorrect master password.")
                return False, None
        except Exception as e:
            print(f"Error reading master password file: {e}")
            return False, None
    else:
        print("No master password set yet.")
        return False, None

def get_master_password():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        new_master = input("Set your master password: ")
        success, salt = store_master_password_hash_secure(new_master)
        return success, salt
    else:
        return verify_master_password_secure()

def store_password(keyword, username, password, fernet_key):
    combined_data = f"{username}:{password}".encode()
    encrypted_data = fernet_key.encrypt(combined_data).decode()
    try:
        with open(PASSWORD_DATA_FILE, "a") as f:
            f.write(f"{keyword}:{encrypted_data}\n")
        print(f"Password for '{keyword}' stored (encrypted).")
    except Exception as e:
        print(f"Error storing password: {e}")

def retrieve_password(keyword, fernet_key):
    try:
        with open(PASSWORD_DATA_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == keyword:
                    encrypted_data = parts[1].encode()
                    try:
                        decrypted_data = fernet_key.decrypt(encrypted_data).decode()
                        username, password = decrypted_data.split(":")
                        print(f"Username for '{keyword}': {username}")
                        print(f"Password for '{keyword}': {password}")
                        return
                    except Exception as decrypt_error:
                        print(f"Error during decryption for keyword '{keyword}': {decrypt_error}")
                        return
            print(f"No entry found for keyword '{keyword}'.")
    except FileNotFoundError:
        print("Password data file not found.")
    except Exception as e:
        print(f"General error during retrieval: {e}")

if __name__ == "__main__":
    success, stored_salt = get_master_password()
    if success and stored_salt:
        master = input("Enter your master password again for this session: ")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=stored_salt,
            iterations=100000,
            backend=default_backend()
        )
        raw_key = kdf.derive(master.encode())
        fernet_key = Fernet(base64.urlsafe_b64encode(raw_key))

        print("\nPassword Manager Actions:")
        print("1: Store")
        print("2: Retrieve")
        print("3: Exit")

        while True:
            action = input("Enter action (1, 2, or 3): ")
            if action == "1":
                keyword = input("Enter keyword: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                store_password(keyword, username, password, fernet_key)
            elif action == "2":
                keyword = input("Enter keyword to retrieve: ")
                retrieve_password(keyword, fernet_key)
            elif action == "3":
                break
            else:
                print("Invalid action. Please enter 1, 2, or 3.")

    print("Exiting Password Manager.")