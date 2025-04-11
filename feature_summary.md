# 🔐 Secure Multi-User Data Vault – Feature Summary

## ✅ Data Persistence
- All encrypted user data is saved to a file `secure_data.json`.
- The app loads this file at startup using `load_data()` function.

## ✅ Advanced Security Features
- 3 failed login attempts trigger a 60-second lockout.
- Passwords are hashed using PBKDF2 (`pbkdf2_hmac`) with 100,000 iterations.
- Salt is used to enhance password security.
- Encrypted data is handled securely using Fernet (AES encryption).

## ✅ Multi-User Support
- Users can register with unique usernames and passwords.
- Each user can store and retrieve only their own encrypted data.
- Users must be authenticated to store or access data.

---

💡 This summary describes the core features implemented in the `Secure Multi-User Data Vault` app built with Streamlit.
