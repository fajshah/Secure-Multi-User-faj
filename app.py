import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta

# -----------------------------
# 📁 JSON File Handling
# -----------------------------
DATA_FILE = "data.json"
LOCK_FILE = "lock.json"
USERS_FILE = "users.json"

# File operation functions...
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_locks():
    if os.path.exists(LOCK_FILE):
        with open(LOCK_FILE, "r") as f:
            return json.load(f)
    return {}

def save_locks(locks):
    with open(LOCK_FILE, "w") as f:
        json.dump(locks, f, indent=4)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# -----------------------------
# 🔐 Key and Cipher Setup
# -----------------------------
def generate_cipher(passkey):
    salt = b'streamlit-salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(passkey.encode()))
    return Fernet(key)

# -----------------------------
# 📆 Load Data into Session State
# -----------------------------
stored_data = load_data()
locks = load_locks()
users_data = load_users()

if "stored_data" not in st.session_state:
    st.session_state.stored_data = stored_data
if "locks" not in st.session_state:
    st.session_state.locks = locks
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "page" not in st.session_state:
    st.session_state.page = "Login"
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "retrieve_attempts" not in st.session_state:
    st.session_state.retrieve_attempts = {}

# -----------------------------
# 🔑 Utility Functions
# -----------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    cipher = generate_cipher(passkey)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    try:
        cipher = generate_cipher(passkey)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# -----------------------------
# 🔐 Auth System First
# -----------------------------
st.set_page_config(page_title="Secure Data Vault", page_icon="🛡️", initial_sidebar_state="collapsed")
st.title("🛡️Secure Data Encryption System")
st.caption("Developed by Syeda Farzana Shah")

if not st.session_state.is_logged_in:
    auth_tab = st.radio("Login or Register", ["Login", "Register"], horizontal=True)

    if auth_tab == "Login":
        st.subheader("🔐 Login to Your Vault")
        user_login = st.text_input("👤 Username")
        pass_login = st.text_input("🔑 Password", type="password")

        if st.button("🔓 Login"):
            user_lock_info = locks.get(user_login, {"attempts": 0, "lock_time": None})
            if user_lock_info["lock_time"]:
                locked_until = datetime.strptime(user_lock_info["lock_time"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() < locked_until:
                    remaining = (locked_until - datetime.now()).seconds
                    st.error(f"⏳ Account locked! Try again in {remaining} seconds.")
                    st.stop()
                else:
                    user_lock_info = {"attempts": 0, "lock_time": None}

            hashed_input = hash_passkey(pass_login)
            if users_data.get(user_login) == hashed_input:
                st.session_state.is_logged_in = True
                st.session_state.current_user = user_login
                st.success(f"✅ Welcome, {user_login}!")
                st.balloons()
                time.sleep(2)
                st.session_state.page = "home"
                locks[user_login] = {"attempts": 0, "lock_time": None}
                save_locks(locks)
                st.rerun()
            else:
                user_lock_info["attempts"] += 1
                if user_lock_info["attempts"] >= 3:
                    lock_time = datetime.now() + timedelta(seconds=60)
                    user_lock_info["lock_time"] = lock_time.strftime("%Y-%m-%d %H:%M:%S")
                    st.error("🛑 Too many failed attempts. Account locked for 60 seconds.")
                else:
                    st.error("❌ Incorrect username or password.")
                locks[user_login] = user_lock_info
                save_locks(locks)

    elif auth_tab == "Register":
        st.subheader("💊 Create New Account")
        new_user = st.text_input("👤 Username")
        new_pass = st.text_input("🔑 Password", type="password")

        if st.button("📝 Register"):
            if new_user in users_data:
                st.error("❌ Username already exists.")
            elif new_user and new_pass:
                users_data[new_user] = hash_passkey(new_pass)
                save_users(users_data)
                st.success("✅ Registered successfully! You can now login.")
                st.balloons()
                st.session_state.page = "home"
                st.rerun()
            else:
                st.warning("⚠️ Please enter both username and password.")
    st.stop()

# -----------------------------
# 🧱 Main Navigation
# -----------------------------
menu = ["Home", "Store Data", "Retrieve Data", "Download data", "Change Password", "Delete Profile", "Logout"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to Your Secure Vault")
    st.markdown("Use the sidebar to store or retrieve your encrypted data.")

elif choice == "Store Data":
    st.subheader("📂 Store Encrypted Data")
    username = st.session_state.current_user
    title = st.text_input("🗂️ Title for Your Secret")
    user_data = st.text_area("📝 Enter Secret Data:")
    passkey = st.text_input("🔑 Create Passkey:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey and title:
            encrypted = encrypt_data(user_data, passkey)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if username not in st.session_state.stored_data:
                st.session_state.stored_data[username] = {}
            st.session_state.stored_data[username][title] = {
                "encrypted": encrypted,
                "passkey": hash_passkey(passkey),
                "timestamp": timestamp
            }
            save_data(st.session_state.stored_data)
            st.success("✅ Data encrypted and saved!")
            st.balloons()
            with st.expander("📆 Encrypted Text (click to view)"):
                st.code(encrypted, language="text")
            st.text(f"Timestamp: {timestamp}")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    username = st.session_state.current_user
    user_entries = st.session_state.stored_data.get(username, {})

    if user_entries:
        selected_title = st.selectbox("📁 Select a Title to Decrypt", list(user_entries.keys()))
        passkey_input = st.text_input("🔑 Enter Passkey:", type="password")

        if username not in st.session_state.retrieve_attempts:
            st.session_state.retrieve_attempts[username] = {"count": 0, "lock_until": None}

        lock_info = st.session_state.retrieve_attempts[username]
        now = datetime.now()
        if lock_info["lock_until"] and now < lock_info["lock_until"]:
            remaining = int((lock_info["lock_until"] - now).total_seconds())
            st.warning(f"⏳ Locked out due to failed attempts. Try again in {remaining} seconds.")
        elif st.button("🤩 Decrypt"):
            entry = user_entries.get(selected_title)
            if entry and entry["passkey"] == hash_passkey(passkey_input):
                decrypted = decrypt_data(entry["encrypted"], passkey_input)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                    st.balloons()
                    st.session_state.retrieve_attempts[username] = {"count": 0, "lock_until": None}
                else:
                    st.error("❌ Failed to decrypt. Try again.")
            else:
                lock_info["count"] += 1
                if lock_info["count"] >= 3:
                    lock_info["lock_until"] = now + timedelta(seconds=60)
                    st.error("🛑 Too many failed attempts. Locked for 60 seconds.")
                else:
                    st.error("❌ Incorrect passkey.")
                st.session_state.retrieve_attempts[username] = lock_info
    else:
        st.info("ℹ️ You have no saved data yet.")

elif choice == "Download data":
    st.subheader("📥 Download Your Encrypted Data")
    user = st.session_state.current_user
    user_data = stored_data.get(user, {})

    if user_data:
        data_text = json.dumps(user_data, indent=4)
        st.download_button(
            label="⬇️ Download as JSON",
            data=data_text,
            file_name=f"{user}_encrypted_data.json",
            mime="application/json"
        )
    else:
        st.info("📬 No data available to download.")

elif choice == "Change Password":
    st.subheader("🔑 Change Password")
    old_pass = st.text_input("🔐 Old Password", type="password")
    new_pass = st.text_input("🆕 New Password", type="password")

    if st.button("🔁 Update Password"):
        user = st.session_state.current_user
        if users_data.get(user) == hash_passkey(old_pass):
            users_data[user] = hash_passkey(new_pass)
            save_users(users_data)
            st.success("✅ Password changed successfully.")
        else:
            st.error("❌ Old password is incorrect.")

elif choice == "Delete Profile":
    st.subheader("🗑️ Delete Account")
    confirm = st.checkbox("I understand that this action is irreversible.")
    delete_pass = st.text_input("🔑 Confirm Password", type="password")

    if st.button("🗑️ Delete My Profile") and confirm:
        user = st.session_state.current_user
        if users_data.get(user) == hash_passkey(delete_pass):
            del users_data[user]
            st.session_state.stored_data.pop(user, None)
            locks.pop(user, None)  # 🔐 Remove lock info
            save_users(users_data)
            save_data(st.session_state.stored_data)
            save_locks(locks)  # 📂 Save updated lock info
            st.session_state.is_logged_in = False
            st.session_state.current_user = None
            st.success("✅ Your profile has been deleted.")
            st.rerun()
        else:
            st.error("❌ Incorrect password. Account not deleted.")

elif choice == "Logout":
    st.session_state.is_logged_in = False
    st.session_state.current_user = None
    st.success("👋 You have been logged out successfully.")
    st.rerun()
