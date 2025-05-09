import streamlit as st
import hashlib
import base64
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ---------- Constants ----------
DATA_FILE = "data.json"
USER_FILE = "users.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # seconds

# ---------- Session State ----------
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'page' not in st.session_state:
    st.session_state.page = "login"
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = {}

# ---------- Utility Functions ----------
def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

def hash_passkey(passkey, salt):
    return pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()

def generate_key(passkey, salt):
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_text(text, passkey, salt):
    fernet = Fernet(generate_key(passkey, salt))
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(ciphertext, passkey, salt):
    try:
        fernet = Fernet(generate_key(passkey, salt))
        return fernet.decrypt(ciphertext.encode()).decode()
    except:
        return None

def navigation_bar():
    st.sidebar.title("🔐 Secure Vault")
    st.sidebar.button("🏠 Home", on_click=lambda: st.session_state.update({"page": "home"}))
    st.sidebar.button("➕ Insert Data", on_click=lambda: st.session_state.update({"page": "insert"}))
    st.sidebar.button("🔍 Retrieve Data", on_click=lambda: st.session_state.update({"page": "retrieve"}))
    st.sidebar.button("🚪 Logout", on_click=logout)

def logout():
    st.session_state.current_user = None
    st.session_state.page = "login"

# ---------- Pages ----------
def login_page():
    st.title("🔐 Login / Register")
    users = load_json(USER_FILE)

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    action = st.radio("Action", ["Login", "Register"])

    if st.button(action):
        if not username or not password:
            st.error("Please fill all fields.")
            return

        if action == "Register":
            if username in users:
                st.error("User already exists.")
            else:
                salt = os.urandom(16).hex()
                hashed = hash_passkey(password, salt)
                users[username] = {"passkey": hashed, "salt": salt}
                save_json(USER_FILE, users)
                st.success("User registered successfully.")
        else:
            if username not in users:
                st.error("User does not exist.")
                return

            # Lockout check
            if username in st.session_state.lockout_time:
                delta = time.time() - st.session_state.lockout_time[username]
                if delta < LOCKOUT_TIME:
                    st.error(f"Locked out. Try again in {int(LOCKOUT_TIME - delta)}s")
                    return
                else:
                    del st.session_state.lockout_time[username]
                    st.session_state.failed_attempts[username] = 0

            user_data = users[username]
            if hash_passkey(password, user_data["salt"]) == user_data["passkey"]:
                st.session_state.current_user = username
                st.session_state.page = "home"
                st.session_state.failed_attempts[username] = 0
            else:
                st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
                st.error(f"Incorrect password. Attempt {st.session_state.failed_attempts[username]}/{MAX_ATTEMPTS}")
                if st.session_state.failed_attempts[username] >= MAX_ATTEMPTS:
                    st.session_state.lockout_time[username] = time.time()
                    st.error("Too many attempts. Locked for 60 seconds.")

def home():
    navigation_bar()
    st.title("🔐 Secure Data Encryption System")
    st.markdown(f"👋 Welcome, {st.session_state.current_user}")
    st.write("Use the sidebar to encrypt or retrieve your data.")

def insert_data():
    navigation_bar()
    st.title("➕ Insert Encrypted Data")

    text = st.text_area("Enter your secret text")
    passkey = st.text_input("Encryption Passkey", type="password")

    if st.button("Save"):
        if not text or not passkey:
            st.warning("All fields are required.")
            return

        users = load_json(USER_FILE)
        salt = users[st.session_state.current_user]["salt"]
        encrypted = encrypt_text(text, passkey, salt)

        data = load_json(DATA_FILE)
        data[st.session_state.current_user] = {"encrypted_text": encrypted}
        save_json(DATA_FILE, data)
        st.success("Data encrypted and saved!")

def retrieve_data():
    navigation_bar()
    st.title("🔍 Retrieve Your Data")

    data = load_json(DATA_FILE)
    if st.session_state.current_user not in data:
        st.info("No data found.")
        return

    passkey = st.text_input("Enter your encryption passkey", type="password")

    if st.button("Decrypt"):
        users = load_json(USER_FILE)
        salt = users[st.session_state.current_user]["salt"]
        encrypted = data[st.session_state.current_user]["encrypted_text"]
        decrypted = decrypt_text(encrypted, passkey, salt)

        if decrypted:
            st.success(f"Decrypted Text: {decrypted}")
        else:
            st.error("Incorrect passkey.")

# ---------- Main ----------
def main():
    if not st.session_state.current_user:
        login_page()
    elif st.session_state.page == "home":
        home()
    elif st.session_state.page == "insert":
        insert_data()
    elif st.session_state.page == "retrieve":
        retrieve_data()

main()
