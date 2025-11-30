# 🏥🔐 Medical File Encryption System

Secure Multi-User File Sharing with Hybrid Encryption (RSA + AES/Fernet)

A class project demonstrating secure communication, authentication, and encrypted file transfer between user accounts.

## 📌 Overview

Medical File Encryption is a Python application built with:

 - Tkinter (GUI)
 - RSA public-key cryptography (per-user keypairs)
 - Hybrid encryption: AES/Fernet + RSA
 - JSON-based lightweight storage
 - Password-based private key encryption (PBKDF2)

Users can:
 - Create accounts
 - Automatically generate cryptographic keypairs
 - Encrypt files for selected recipients
 - Receive and decrypt files
 - Log out and log back in
 - Maintain complete end-to-end encryption

## 🧠 How It Works
**🔑 1. Account Creation**
When a user registers:
 - A RSA 2048-bit keypair is generated
 - The public key is stored
 - The private key is encrypted using:
   - PBKDF2 → AES/Fernet
 - Only the correct user password can decrypt the private key

**🗝️ 2. Login**
During login:
 - The password is checked via SHA-256 hash
 - The private RSA key is decrypted using the password
 - This decrypted private key is held in memory for decryption operations
 - No plaintext private keys are written to disk.

**📨 3. Sending an Encrypted File**
When User A sends a file to User B:
 - A random symmetric key is generated
 - The file is encrypted using AES/Fernet
 - The symmetric key is encrypted with:
   - B’s public RSA key
   - A’s RSA key (so the sender can access the file later)
 - File metadata + encrypted keys are stored in:
   - data/files.json
   - encrypted_files/<file_id>.bin

**📥 4. Receiving / Decrypting a File**
When User B decrypts a file:
 - Their RSA private key decrypts their symmetric key
 - The symmetric key decrypts the file
 - B chooses where to save the decrypted version
 - End-to-end encryption: only the intended recipient(s) can decrypt the file.

## 🗂️ Project Structure
medical_file_encryption/
│
├── main.py
├── login_app.py
├── dashboard.py
│
├── users_repo.py
├── files_repo.py
├── passwords.py
├── file_crypto.py
│
├── data/
│   ├── users.json
│   └── files.json
│
└── encrypted_files/
    └── *.bin (encrypted files)
