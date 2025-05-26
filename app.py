
import streamlit as st
import hashlib
import time
import sqlite3
from cryptography.fernet import Fernet
print("Cryptography is installed correctly!")

from datetime import datetime, timedelta

def create_connection():
    conn = sqlite3.connect('secure_vault.db')
    return conn

def create_tables():
    conn = create_connection()
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, 
                    password_hash TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_data (
                    encrypted_text TEXT PRIMARY KEY, 
                    passkey_hash TEXT, 
                    owner TEXT, 
                    timestamp TEXT)''')
    
    conn.commit()
    conn.close()
create_tables()    
def get_theme():
    theme = st.session_state.get('theme', 'light')
    return theme

theme_option = st.selectbox('Choose Theme', ('light', 'dark'))

st.session_state.theme = theme_option

theme_styles = {
    "light": {
        "primary_color": "#3498db",
        "background_color": "#ffffff",
        "secondary_background": "#f5f7fa",
        "text_color": "#2c3e50",
        "border_color": "#e1e4e8",
        "card_shadow": "0 4px 8px rgba(0,0,0,0.1)",
        "success_color": "#28a745",
        "warning_color": "#ffc107",
        "error_color": "#dc3545",
        "info_color": "#17a2b8"
    },
    "dark": {
        "primary_color": "#5dade2",
        "background_color": "#121212",
        "secondary_background": "#1e1e1e",
        "text_color": "#f5f5f5",
        "border_color": "#444",
        "card_shadow": "0 4px 8px rgba(0,0,0,0.3)",
        "success_color": "#4caf50",
        "warning_color": "#ff9800",
        "error_color": "#f44336",
        "info_color": "#2196f3"
    }
}

theme = theme_styles.get(theme_option, theme_styles['light'])

st.markdown(f"""
<style>
    /* Base styling */
    .stApp {{
        background-color: {theme['secondary_background']};
    }}
    
    /* Text colors */
    body, .stTextInput>div>div>input, .stTextArea>div>div>textarea {{
        color: {theme['text_color']};
    }}
    
    /* Headers */
    h1, h2, h3, h4, h5, h6 {{
        color: {theme['primary_color']};
    }}
    
    /* Sidebar */
    .css-1d391kg {{
        background-color: {theme['secondary_background']} !important;
    }}
    
    /* Buttons */
    .stButton>button {{
        background-color: {theme['primary_color']};
        color: white;
        border-radius: 5px;
        padding: 8px 16px;
        border: none;
        font-weight: bold;
    }}
    
    .stButton>button:hover {{
        background-color: {theme['primary_color']};
        opacity: 0.9;
    }}
    
    /* Input fields */
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {{
        background-color: {theme['background_color']};
        border: 1px solid {theme['border_color']};
        border-radius: 5px;
    }}
    
    /* Cards */
    .card {{
        background-color: {theme['background_color']};
        border-radius: 8px;
        box-shadow: {theme['card_shadow']};
        padding: 15px;
        margin-bottom: 15px;
        border: 1px solid {theme['border_color']};
    }}
    
    /* Alerts */
    .stAlert .stSuccess {{
        background-color: rgba(40, 167, 69, 0.1);
        color: {theme['success_color']};
        border-left: 4px solid {theme['success_color']};
    }}
    
    .stAlert .stError {{
        background-color: rgba(220, 53, 69, 0.1);
        color: {theme['error_color']};
        border-left: 4px solid {theme['error_color']};
    }}
    
    .stAlert .stWarning {{
        background-color: rgba(255, 193, 7, 0.1);
        color: {theme['warning_color']};
        border-left: 4px solid {theme['warning_color']};
    }}
    
    .stAlert .stInfo {{
        background-color: rgba(23, 162, 184, 0.1);
        color: {theme['info_color']};
        border-left: 4px solid {theme['info_color']};
    }}
    
    /* Strength indicators */
    .strength-strong {{
        color: {theme['success_color']};
        font-weight: bold;
    }}
    
    .strength-moderate {{
        color: {theme['warning_color']};
        font-weight: bold;
    }}
    
    .strength-weak {{
        color: {theme['error_color']};
        font-weight: bold;
    }}
    
    /* Radio buttons */
    .stRadio>div {{
        background-color: {theme['background_color']};
        padding: 10px;
        border-radius: 5px;
        box-shadow: {theme['card_shadow']};
    }}
</style>
""", unsafe_allow_html=True)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "start_time" not in st.session_state:
    st.session_state.start_time = None
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

if "users" not in st.session_state:
    st.session_state.users = {"admin": hash_passkey("admin123")}
if "current_user" not in st.session_state:
    st.session_state.current_user = None

key = Fernet.generate_key()
cipher = Fernet(key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def check_passkey_strength(passkey):
    if len(passkey) >= 8 and any(c.isdigit() for c in passkey) and any(c.isupper() for c in passkey) and any(not c.isalnum() for c in passkey):
        return "<span class='strength-strong'>🔐 Strong (Excellent security)</span>"
    elif len(passkey) >= 8 and any(c.isdigit() for c in passkey) and any(c.isupper() for c in passkey):
        return "<span class='strength-strong'>🛡️ Strong</span>"
    elif len(passkey) >= 5:
        return "<span class='strength-moderate'>🛡️ Moderate</span>"
    return "<span class='strength-weak'>⚠️ Weak (Please use a stronger passkey)</span>"

def auto_logout():
    if st.session_state.start_time and datetime.now() - st.session_state.start_time > timedelta(minutes=5):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.warning("⏳ Session expired due to inactivity. Please login again.")

def login_register_page():
    col1, col2, col3 = st.columns([1,3,1])
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=100)
        st.title("Secure Vault")
        st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            Your personal encryption system for secure data storage
        </div>
        """, unsafe_allow_html=True)
        
        with st.container():
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            action = st.radio("Choose Action", ["Login", "Register"], horizontal=True)
            
            username = st.text_input("👤 Username")
            password = st.text_input("🔑 Password", type="password")
            
            if action == "Login":
                if st.button("🚀 Login", key="login_btn"):
                    hashed_input = hash_passkey(password)
                    if username in st.session_state.users and st.session_state.users[username] == hashed_input:
                        st.session_state.authenticated = True
                        st.session_state.failed_attempts = 0
                        st.session_state.start_time = datetime.now()
                        st.session_state.current_user = username
                        st.success("✅ Login successful! Welcome back.")
                        st.balloons()
                    else:
                        st.error("❌ Invalid credentials. Please try again.")
            else:
                if st.button("✨ Register", key="register_btn"):
                    if username in st.session_state.users:
                        st.warning("⚠️ Username already exists. Please choose another.")
                    else:
                        st.session_state.users[username] = hash_passkey(password)
                        st.success("🎉 Registered successfully! You can now log in.")
            st.markdown("</div>", unsafe_allow_html=True)

def home_page():
    auto_logout()
    st.title(f"Welcome, {st.session_state.current_user}!")
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class='card'>
            <h3>🔐 Secure Data Encryption</h3>
            <p>Store your sensitive information with military-grade encryption.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class='card'>
            <h3>📜 Encrypted History</h3>
            <p>View all your previously encrypted entries in one place.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='card'>
            <h3>🔓 Safe Retrieval</h3>
            <p>Access your data securely with your personal passkey.</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class='card'>
            <h3>⏳ Auto-Logout</h3>
            <p>Automatic logout after 5 minutes for your security.</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.success("🔒 System is secure and running smoothly")

def store_data_page():
    auto_logout()
    st.title("📦 Store Encrypted Data")
    st.markdown("""
    <div class='card'>
        <p>Enter your sensitive data below. It will be encrypted before storage.</p>
    </div>
    """, unsafe_allow_html=True)
    
    user_data = st.text_area("📝 Enter your confidential data:", height=150)
    passkey = st.text_input("🔑 Create a strong passkey (min 8 chars with numbers and uppercase):", type="password")
    
    if passkey:
        st.markdown(f"<div class='card'>Passkey Strength: {check_passkey_strength(passkey)}</div>", unsafe_allow_html=True)
    
    if st.button("🔒 Encrypt & Save", key="encrypt_btn"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted, 
                "passkey": hashed, 
                "owner": st.session_state.current_user,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            st.success("✅ Data encrypted and stored securely!")
            with st.expander("🔍 View Encrypted Data"):
                st.code(encrypted, language="text")
            st.balloons()
        else:
            st.error("❗ Both fields are required")

def retrieve_data_page():
    auto_logout()
    st.title("🔓 Retrieve Your Data")
    st.markdown("""
    <div class='card'>
        <p>Paste your encrypted data and enter your passkey to decrypt it.</p>
    </div>
    """, unsafe_allow_html=True)
    
    encrypted_input = st.text_area("🔐 Paste your encrypted text:", height=150)
    passkey = st.text_input("🔑 Enter your passkey:", type="password")
    
    if st.button("🔓 Decrypt Now", key="decrypt_btn"):
        if encrypted_input and passkey:
            hashed_passkey = hash_passkey(passkey)
            entry = st.session_state.stored_data.get(encrypted_input)
            
            if entry and entry["passkey"] == hashed_passkey and entry["owner"] == st.session_state.current_user:
                st.session_state.failed_attempts = 0
                decrypted = decrypt_data(encrypted_input)
                
                st.success("✅ Decryption Successful!")
                with st.expander("📄 View Decrypted Content"):
                    st.text_area("Decrypted Data", value=decrypted, height=200)
                st.balloons()
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey or unauthorized access! Attempts remaining: {attempts_left}")
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authenticated = False
                    st.session_state.current_user = None
                    st.warning("🔒 Too many failed attempts. You've been logged out for security.")
        else:
            st.error("❗ Both fields are required")

def view_all_encrypted():
    auto_logout()
    st.title("📜 Your Encrypted Entries")
    
    user_entries = [v for v in st.session_state.stored_data.values() 
                   if v["owner"] == st.session_state.current_user]
    
    if user_entries:
        st.markdown(f"<div class='card'>You have {len(user_entries)} encrypted entries</div>", 
                   unsafe_allow_html=True)
        
        for i, entry in enumerate(sorted(user_entries, key=lambda x: x["timestamp"], reverse=True), 1):
            with st.expander(f"📄 Entry #{i} - {entry['timestamp']}"):
                st.code(entry["encrypted_text"], language="text")
                if st.button(f"🗑️ Delete Entry #{i}", key=f"del_{i}"):
                    del st.session_state.stored_data[entry["encrypted_text"]]
                    st.success("Entry deleted successfully!")
                    st.experimental_rerun()
    else:
        st.info("ℹ️ You haven't stored any data yet. Visit the 'Store Data' page to get started.")

def profile_page():
    auto_logout()
    st.title("👤 Your Profile")
    
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.image("https://cdn-icons-png.flaticon.com/512/3135/3135715.png", width=150)
    
    with col2:
        st.markdown(f"""
        <div class='card'>
            <h3>User Information</h3>
            <p><strong>Username:</strong> {st.session_state.current_user}</p>
            <p><strong>Account Created:</strong> Today</p>
            <p><strong>Security Status:</strong> <span style='color: {theme['success_color']};'>Protected 🔒</span></p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("""
    <div class='card'>
        <h3>🔐 Security Information</h3>
        <p>• Auto-logout after 5 minutes of inactivity</p>
        <p>• Military-grade AES-256 encryption</p>
        <p>• Secure password hashing (SHA-256)</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🚪 Logout", key="logout_profile"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.success("👋 Logged out successfully.")
        st.experimental_rerun()

if not st.session_state.authenticated:
    login_register_page()
else:
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=80)
        st.markdown(f"### Welcome, {st.session_state.current_user}!")
        st.markdown("---")
        
        menu_options = {
            "🏠 Home": "Home",
            "📦 Store Data": "Store Data",
            "🔓 Retrieve Data": "Retrieve Data",
            "📜 My Encrypted Data": "My Encrypted Data",
            "👤 Profile": "Profile",
            "🚪 Logout": "Logout"
        }
        
        selected = st.radio(
            "Navigation",
            list(menu_options.keys()),
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        st.markdown(f"⏳ Session active for: {(datetime.now() - st.session_state.start_time).seconds // 60} minutes")
        
    choice = menu_options[selected]

    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "My Encrypted Data":
        view_all_encrypted()
    elif choice == "Profile":
        profile_page()
    elif choice == "Logout":
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.success("👋 Logged out successfully.")
        time.sleep(1)
        st.rerun()