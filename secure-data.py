import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Setup
st.set_page_config(page_title="Secure Encryption System", layout="centered")

# In-Memory Store
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {encrypted_text, passkey_hash}}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True  # Used to redirect after lockout

# Key Generation
@st.cache_resource
def get_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = get_cipher()

# Helpers
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    entry = st.session_state.stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Login redirect logic
if st.session_state.failed_attempts >= 3 and choice != "Login":
    st.warning("🔒 Too many failed attempts. Please login again.")
    st.session_state.authorized = False
    st.experimental_rerun()

# Pages
if choice == "Home":
    st.header("🏠 Welcome")
    st.markdown("Store and retrieve your data securely using passkeys. All data is encrypted and held only in memory.")
    
elif choice == "Store Data":
    st.header("📂 Store Data Securely")
    data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey:", type="password")
    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted = encrypt_data(data, passkey)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Please login to continue.")
        st.experimental_rerun()

    st.header("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Enter the encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")
    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Data Decrypted:")
                st.code(result, language="text")
            else:
                remaining = max(0, 3 - st.session_state.failed_attempts)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Redirecting to login due to too many failed attempts.")
                    st.session_state.authorized = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ All fields must be filled!")

elif choice == "Login":
    st.header("🔑 Reauthorize")
    master_key = st.text_input("Enter master password to unlock:", type="password")
    if st.button("Login"):
        if master_key == "admin123":  # Replace with secure system in real-world
            st.success("✅ Logged in successfully!")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.experimental_rerun()
        else:
            st.error("❌ Invalid password.")
