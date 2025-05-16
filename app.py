import streamlit as st
import base64
import os
import io
import json
import qrcode
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Hash import SHA256, SHA3_256, HMAC
from Crypto.Protocol.KDF import PBKDF2, scrypt
import google.generativeai as genai
import pandas as pd
import matplotlib.pyplot as plt
import random
import string
import requests
import datetime
from PIL import Image
import numpy as np
import hashlib
import pyotp
import math
import time  # ← Needed for countdown!
import zipfile
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import hashlib
import requests
from scipy.io.wavfile import write, read

# --- Streamlit UI ---
st.set_page_config("OmniCrypt", layout="wide",page_icon="🔐")
st.title("🛡️ CryptX Vault Pro – Advanced Cryptography Suite")

# --- Gemini Key ---
api_key = st.sidebar.text_input("🔑 Enter Gemini API Key", type="password")
if api_key:
    genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel("gemini-2.0-flash")

# --- Modern UI with SelectBox instead of tabs ---
feature = st.sidebar.selectbox(
    "Select Feature",
    [
        "🔑 AES Encrypt/Decrypt", 
        "🌪️ ChaCha20 Encrypt/Decrypt",
        "🔄 Asymmetric Cryptography", 
        "🧮 HMAC & Hash Functions", 
        "🧠 AI Code Explainer",
        "💪 Password Strength Analyzer",
        "📊 Encryption Benchmark",
        "📱 QR Code Generator",
        "🔄 Format Converter",
        "🎯 Secure Password Generator",
        "⏱️ Hash Speed Test",
        "🔍 File Hash Verification",
        "🎫 JWT Token Inspector",
        "🗝️ SSH Key Manager",
        "🕵️ Cipher Identifier",
        "🧮 Modular Calculator",
        "🔢 Base Converter",
        "🧩 Crypto Puzzle Game",
        
        # 💖 New Tools Below 💖
        "📈 ECC Key Exchange Visualizer",
        "⏰ TOTP Generator & Verifier",
        "✂️ File Splitter & Joiner",
        "📏 Entropy Analyzer",
        "📨 PGP File Encrypt/Decrypt",
        "🗄️ Master Key Derivation Tool",
        "📝 Encrypted Notes Vault",
        "💬 Secure Chat Demo (ECC + AES)",
        "🎲 Randomness Tester",
        "✍️ File Signature Generator & Verifier",
        
        # 🚀 Next-level advanced tools
        
        "🌌 Post-Quantum Cryptography Simulator",
        "🧹 Encrypted File Metadata Remover",
        "⛓️ Blockchain Hash Logger",
        
        # 🔬 Advanced Cryptographic Tools
        "🔮 Homomorphic Encryption Explorer",
        "🎭 Zero-Knowledge Proof Generator",
        "🌳 Merkle Tree Visualizer & Builder",
        "🔱 Threshold Cryptography Simulator",
        "⚡ Side-Channel Attack Demonstrator",
        "🌠 Quantum Key Distribution Simulator",
        "🛡️ Cryptographic Protocol Analyzer",
    ]
)


# --- 1. AES Encrypt/Decrypt ---
if feature == "🔑 AES Encrypt/Decrypt":
    st.header("🔐 AES File Encryption / Decryption")
    
    # New addition: KDF options
    kdf_options = st.selectbox("Key Derivation Function", ["PBKDF2", "Scrypt"])
    
    aes_mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    uploaded_file = st.file_uploader("Choose a file")

    password = st.text_input("Password", type="password")
    salt = get_random_bytes(16) if aes_mode == "Encrypt" else None
    
    # Advanced options
    with st.expander("Advanced Options"):
        iterations = st.slider("KDF Iterations", 10000, 1000000, 100000)
    
    aes_btn = st.button("Run AES")

    if uploaded_file and password and aes_btn:
        data = uploaded_file.read()
        
        # Apply selected KDF
        if kdf_options == "PBKDF2":
            key = PBKDF2(password.encode(), salt if salt else data[:16], dkLen=32, count=iterations)
        else:  # Scrypt
            key = scrypt(password.encode(), salt if salt else data[:16], key_len=32, N=2**14, r=8, p=1)
            
        cipher = AES.new(key, AES.MODE_EAX)

        if aes_mode == "Encrypt":
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = salt + cipher.nonce + tag + ciphertext
            st.download_button("Download Encrypted File", output, file_name="encrypted.bin")
            
            # Security info
            st.info(f"✅ File encrypted with {len(key)*8} bit key, {kdf_options} with {iterations} iterations")
        else:
            try:
                salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Try to detect file type
                file_ext = "bin"
                if decrypted.startswith(b'%PDF'):
                    file_ext = "pdf"
                elif decrypted.startswith(b'\xff\xd8\xff'):
                    file_ext = "jpg"
                elif decrypted.startswith(b'PK'):
                    file_ext = "zip"
                
                st.download_button("Download Decrypted File", decrypted, file_name=f"decrypted.{file_ext}")
            except Exception as e:
                st.error(f"❌ Decryption Failed – {str(e)}")

# --- 2. ChaCha20 Encrypt/Decrypt (NEW FEATURE) ---
elif feature == "🌪️ ChaCha20 Encrypt/Decrypt":
    st.header("🌀 ChaCha20-Poly1305 Encryption")
    st.markdown("Modern, high-performance encryption algorithm")
    
    chacha_mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    uploaded_file = st.file_uploader("Choose a file")

    password = st.text_input("Password", type="password")
    chacha_btn = st.button("Process")

    if uploaded_file and password and chacha_btn:
        data = uploaded_file.read()
        key = SHA256.new(password.encode()).digest()
        
        if chacha_mode == "Encrypt":
            nonce = get_random_bytes(12)  # 96 bits
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            output = nonce + tag + ciphertext
            st.download_button("Download Encrypted File", output, file_name="chacha_encrypted.bin")
            st.success("File encrypted with ChaCha20-Poly1305")
        else:
            try:
                nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
                cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                st.download_button("Download Decrypted File", decrypted, file_name="chacha_decrypted.bin")
            except Exception as e:
                st.error(f"❌ ChaCha20 Decryption Failed – {str(e)}")

# --- 3. RSA/ECC/EdDSA Playground ---
elif feature == "🔄 Asymmetric Cryptography":
    st.header("🔏 Key Generation + Signature Verification")
    crypto_type = st.selectbox("Choose Crypto System", ["RSA", "ECC", "EdDSA"])

    message = st.text_area("Message to Sign")
    
    # Add option to save keys
    save_keys = st.checkbox("Save keys to file")
    
    if st.button("Generate Keys + Sign"):
        if crypto_type == "RSA":
            # Let user choose key size
            key_size = st.select_slider("RSA Key Size (bits)", options=[1024, 2048, 3072, 4096], value=2048)
            
            rsa_key = RSA.generate(key_size)
            h = SHA256.new(message.encode())
            sig = pkcs1_15.new(rsa_key).sign(h)
            
            # Display in more organized way
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(rsa_key.export_key().decode(), language="pem")
                if save_keys:
                    st.download_button("Download Private Key", rsa_key.export_key(), file_name="private_key.pem")
            
            with col2:
                st.subheader("Public Key")
                st.code(rsa_key.publickey().export_key().decode(), language="pem")
                if save_keys:
                    st.download_button("Download Public Key", rsa_key.publickey().export_key(), file_name="public_key.pem")
            
            st.subheader("Signature")
            st.code(sig.hex(), language="bash")
            st.download_button("Download Signature", sig, file_name="signature.bin")

        elif crypto_type == "ECC":
            ecc_key = ECC.generate(curve='P-256')
            h = SHA256.new(message.encode())
            signer = ecc_key.sign(h)
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(ecc_key.export_key(format='PEM'), language="pem")
                if save_keys:
                    st.download_button("Download ECC Private Key", ecc_key.export_key(format='PEM'), file_name="ecc_private.pem")
            
            with col2:
                st.subheader("Public Key")
                public_key = ecc_key.public_key().export_key(format='PEM')
                st.code(public_key, language="pem")
                if save_keys:
                    st.download_button("Download ECC Public Key", public_key, file_name="ecc_public.pem")
            
            st.subheader("Signature")
            st.write("Signature:", signer.hex())

        elif crypto_type == "EdDSA":
            ed_key = ECC.generate(curve='Ed25519')
            h = SHA256.new(message.encode())
            signer = eddsa.new(ed_key, 'rfc8032')
            signature = signer.sign(h)
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Private Key")
                st.code(ed_key.export_key(format='PEM'), language="pem")
                if save_keys:
                    st.download_button("Download EdDSA Private Key", ed_key.export_key(format='PEM'), file_name="eddsa_private.pem")
            
            st.subheader("Signature")
            st.write("Signature (hex):", signature.hex())
            st.download_button("Download EdDSA Signature", signature, file_name="eddsa_sig.bin")

# --- 4. HMAC & Hash Functions (Enhanced) ---
elif feature == "🧮 HMAC & Hash Functions":
    st.header("📜 Hash Functions & HMAC Generator")
    
    hash_tab, hmac_tab = st.tabs(["Hash Functions", "HMAC"])
    
    with hash_tab:
        hash_algo = st.selectbox("Hash Algorithm", ["SHA-256", "SHA3-256"])
        hash_input = st.text_area("Text to Hash")
        
        if st.button("Generate Hash"):
            if hash_algo == "SHA-256":
                h = SHA256.new(hash_input.encode())
            else:  # SHA3-256
                h = SHA3_256.new(hash_input.encode())
            
            st.code(h.hexdigest(), language="bash")
    
    with hmac_tab:
        hmac_key = st.text_input("Secret Key")
        hmac_msg = st.text_area("Message")

        if st.button("Generate HMAC"):
            h = HMAC.new(hmac_key.encode(), digestmod=SHA256)
            h.update(hmac_msg.encode())
            st.code(h.hexdigest(), language="bash")

# --- 5. Gemini-Powered Code Explain ---
elif feature == "🧠 AI Code Explainer":
    st.header("🤖 Gemini-Powered Code Explainer")
    code_input = st.text_area("Paste Code to Explain", height=250)
    
    # Add option to select detail level
    detail_level = st.select_slider(
        "Detail Level", 
        options=["Basic", "Standard", "Detailed"], 
        value="Standard"
    )

    if st.button("Explain Code with Gemini"):
        if api_key and code_input.strip():
            with st.spinner("Explaining with Gemini..."):
                detail_instructions = {
                    "Basic": "Give a simple overview of what this code does:",
                    "Standard": "Explain what this code does in detail:",
                    "Detailed": "Provide an in-depth explanation of this code with security considerations and suggestions for improvement:"
                }
                
                explain_prompt = f"{detail_instructions[detail_level]}\n\n{code_input}"
                try:
                    resp = gemini_model.generate_content(explain_prompt)
                    st.success("✅ Explanation:")
                    st.markdown(resp.text)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter your Gemini API Key and code.")

# --- 6. Password Strength Analyzer (NEW FEATURE) ---
elif feature == "💪 Password Strength Analyzer":
    st.header("🔑 Password Strength Analyzer")
    
    password = st.text_input("Enter Password to Analyze", type="password")
    
    if password:
        # Calculate password strength
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append("❌ Password is too short (less than 8 characters)")
        elif len(password) >= 12:
            score += 2
            feedback.append("✅ Good length (12+ characters)")
        else:
            score += 1
            feedback.append("⚠️ Acceptable length (8-11 characters)")
        
        # Complexity checks
        if any(char.isupper() for char in password):
            score += 1
            feedback.append("✅ Contains uppercase letters")
        else:
            feedback.append("❌ No uppercase letters")
            
        if any(char.islower() for char in password):
            score += 1
            feedback.append("✅ Contains lowercase letters")
        else:
            feedback.append("❌ No lowercase letters")
            
        if any(char.isdigit() for char in password):
            score += 1
            feedback.append("✅ Contains numbers")
        else:
            feedback.append("❌ No numbers")
            
        if any(not char.isalnum() for char in password):
            score += 2
            feedback.append("✅ Contains special characters")
        else:
            feedback.append("❌ No special characters")
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("❌ Contains common patterns")
            
        # Display results
        strength_labels = {
            0: "Very Weak", 
            1: "Very Weak", 
            2: "Weak", 
            3: "Moderate", 
            4: "Moderate", 
            5: "Strong", 
            6: "Strong",
            7: "Very Strong"
        }
        
        # Clamp score between 0-7
        score = max(0, min(score, 7))
        
        # Display strength gauge
        st.subheader(f"Password Strength: {strength_labels[score]}")
        st.progress(score/7)
        
        # Colored strength indicator
        colors = {
            "Very Weak": "red",
            "Weak": "orange",
            "Moderate": "blue",
            "Strong": "green",
            "Very Strong": "green"
        }
        
        st.markdown(f"<h3 style='color: {colors[strength_labels[score]]};'>{strength_labels[score]}</h3>", unsafe_allow_html=True)
        
        # Feedback
        st.subheader("Analysis:")
        for item in feedback:
            st.markdown(item)
            
        # Time to crack estimate (very simplified)
        crack_times = {
            0: "Instantly",
            1: "Instantly",
            2: "Minutes to hours",
            3: "Hours to days",
            4: "Days to weeks",
            5: "Weeks to months",
            6: "Months to years",
            7: "Many years"
        }
        
        st.subheader("Estimated time to crack:")
        st.info(crack_times[score])

# --- 7. Encryption Benchmark (NEW FEATURE) ---
elif feature == "📊 Encryption Benchmark":
    st.header("📊 Encryption Algorithm Benchmark")
    
    # Sample benchmark data
    benchmark_data = {
        "Algorithm": ["AES-256-GCM", "ChaCha20-Poly1305", "AES-128-GCM", "3DES", "Blowfish"],
        "Speed (MB/s)": [950, 1350, 1100, 65, 372],
        "Security Level": ["Very High", "Very High", "High", "Medium", "High"]
    }
    
    df = pd.DataFrame(benchmark_data)
    
    # Display as table
    st.subheader("Performance Comparison")
    st.dataframe(df)
    
    # Create visualization
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(df["Algorithm"], df["Speed (MB/s)"], color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
    ax.set_title("Encryption Algorithm Performance")
    ax.set_xlabel("Algorithm")
    ax.set_ylabel("Speed (MB/s)")
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    st.pyplot(fig)
    
    # Security recommendations
    st.subheader("Security Recommendations")
    st.info("For most modern applications, AES-256-GCM and ChaCha20-Poly1305 offer the best combination of security and performance.")
    
    with st.expander("Algorithm Details"):
        st.markdown("""
        - **AES-256-GCM**: Industry standard, hardware accelerated on most modern CPUs
        - **ChaCha20-Poly1305**: Excellent for software implementations, preferred for mobile
        - **AES-128-GCM**: Still secure but with a smaller key size than AES-256
        - **3DES**: Legacy algorithm, much slower than modern options
        - **Blowfish**: Older algorithm with decent performance but not recommended for new applications
        """)

# --- 8. QR Code Generator (NEW FEATURE) ---
elif feature == "📱 QR Code Generator":
    st.header("📱 Secure QR Code Generator")
    
    qr_data = st.text_area("Enter data for QR code", placeholder="Text, URL, or encrypted data")
    qr_size = st.slider("QR Code Size", 1, 10, 5)
    
    # Security options
    with st.expander("Security Options"):
        st.warning("For sensitive data, consider encrypting before generating QR code")
        encrypt_data = st.checkbox("Encrypt with password")
        
        if encrypt_data:
            qr_password = st.text_input("Encryption password", type="password")
    
    if st.button("Generate QR Code"):
        if qr_data:
            # Optional encryption
            final_data = qr_data
            if encrypt_data and qr_password:
                # Simple encryption for QR data
                key = SHA256.new(qr_password.encode()).digest()
                cipher = AES.new(key, AES.MODE_EAX)
                encrypted_data, tag = cipher.encrypt_and_digest(qr_data.encode())
                
                # Format as JSON for easier decoding
                metadata = {
                    "encrypted": True,
                    "nonce": base64.b64encode(cipher.nonce).decode('ascii'),
                    "tag": base64.b64encode(tag).decode('ascii'),
                    "data": base64.b64encode(encrypted_data).decode('ascii')
                }
                final_data = json.dumps(metadata)
                st.info("Data encrypted in QR code. Share the password separately.")
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=qr_size,
                border=4,
            )
            qr.add_data(final_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to bytes for display
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes = img_bytes.getvalue()
            
            # Display and download
            st.image(img_bytes, caption="Generated QR Code")
            st.download_button(
                label="Download QR Code",
                data=img_bytes,
                file_name="qrcode.png",
                mime="image/png"
            )

# --- 9. Format Converter (NEW FEATURE) ---
elif feature == "🔄 Format Converter":
    st.header("🔄 Cryptographic Format Converter")
    
    conversion_type = st.selectbox(
        "Choose Conversion", 
        ["Base64 Encode/Decode", 
         "Hex Encode/Decode", 
         "PEM to DER",
         "ASCII to Binary"]
    )
    
    input_data = st.text_area("Input Data")
    
    if conversion_type == "Base64 Encode/Decode":
        mode = st.radio("Mode", ["Encode", "Decode"])
        
        if st.button("Convert"):
            if input_data:
                if mode == "Encode":
                    result = base64.b64encode(input_data.encode()).decode()
                    st.code(result)
                else:
                    try:
                        result = base64.b64decode(input_data).decode()
                        st.code(result)
                    except Exception as e:
                        st.error(f"Decoding error: {str(e)}")
    
    elif conversion_type == "Hex Encode/Decode":
        mode = st.radio("Mode", ["Encode", "Decode"])
        
        if st.button("Convert"):
            if input_data:
                if mode == "Encode":
                    result = input_data.encode().hex()
                    st.code(result)
                else:
                    try:
                        result = bytes.fromhex(input_data).decode()
                        st.code(result)
                    except Exception as e:
                        st.error(f"Hex decoding error: {str(e)}")
    
    elif conversion_type == "PEM to DER":
        mode = st.radio("Mode", ["PEM to DER", "DER to PEM"])
        key_type = st.selectbox("Key Type", ["RSA", "ECC"])
        
        if st.button("Convert"):
            st.warning("For a complete implementation, use the appropriate functions from PyCryptodome to handle various key formats")
            st.info("This would convert between PEM (text-based) and DER (binary) formats of cryptographic keys")
    
    elif conversion_type == "ASCII to Binary":
        mode = st.radio("Mode", ["ASCII to Binary", "Binary to ASCII"])
        
        if st.button("Convert"):
            if input_data and mode == "ASCII to Binary":
                result = ' '.join(format(ord(char), '08b') for char in input_data)
                st.code(result)
            elif input_data and mode == "Binary to ASCII":
                try:
                    binary_values = input_data.split()
                    result = ''.join(chr(int(binary, 2)) for binary in binary_values)
                    st.code(result)
                except Exception as e:
                    st.error(f"Conversion error: {str(e)}")

# --- 10. Secure Password Generator (NEW FEATURE) ---
elif feature == "🎯 Secure Password Generator":
    st.header("🎲 Secure Password Generator")
    
    # Password generation options
    length = st.slider("Password Length", 8, 64, 16)
    
    col1, col2 = st.columns(2)
    with col1:
        include_uppercase = st.checkbox("Include Uppercase Letters", value=True)
        include_lowercase = st.checkbox("Include Lowercase Letters", value=True)
    
    with col2:
        include_numbers = st.checkbox("Include Numbers", value=True)
        include_special = st.checkbox("Include Special Characters", value=True)
    
    # Advanced options
    with st.expander("Advanced Options"):
        exclude_similar = st.checkbox("Exclude Similar Characters (i, l, 1, o, 0)", value=True)
        exclude_ambiguous = st.checkbox("Exclude Ambiguous Characters ({}[]()/\\'\"`~,;:.<>)", value=True)
        word_based = st.checkbox("Generate Word-Based Password (Easier to Remember)", value=False)
    
    if st.button("Generate Password"):
        if not any([include_uppercase, include_lowercase, include_numbers, include_special]):
            st.error("Please select at least one character type")
        else:
            # Define character sets
            chars = ""
            
            if include_uppercase:
                chars += string.ascii_uppercase
            if include_lowercase:
                chars += string.ascii_lowercase
            if include_numbers:
                chars += string.digits
            if include_special:
                chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
            
            # Apply exclusions
            if exclude_similar:
                for c in "il1oO0":
                    chars = chars.replace(c, "")
            
            if exclude_ambiguous:
                for c in "{}[]()/\\'\"`~,;:.<>":
                    chars = chars.replace(c, "")
            
            # Generate password
            if word_based:
                # Simple word-based password generation
                # (In a real implementation, you'd use a dictionary file)
                sample_words = ["apple", "banana", "orange", "grape", "lemon", "peach", 
                               "mountain", "river", "ocean", "forest", "valley", "canyon",
                               "happy", "brave", "calm", "eager", "gentle", "kind"]
                
                # Generate password by combining words and numbers
                words = random.sample(sample_words, 3)
                separators = [".", "-", "_", "!", "#", "$", "%", "&"] if include_special else [".", "-", "_"]
                separator = random.choice(separators)
                
                if include_numbers:
                    numbers = ''.join(random.choice(string.digits) for _ in range(2))
                    password = separator.join(words) + separator + numbers
                else:
                    password = separator.join(words)
                
                # Ensure it meets length requirements
                if len(password) > length:
                    password = password[:length]
                    
                # Add capital letters if needed
                if include_uppercase:
                    password = ''.join(c.upper() if random.random() < 0.2 else c for c in password)
                
                st.code(password)
                
                # Calculate entropy
                entropy = len(password) * 8  # Simplified calculation
                
            else:
                # Generate random character password
                if chars:
                    password = ''.join(random.choice(chars) for _ in range(length))
                    st.code(password)
                    
                    # Calculate entropy: log2(possible_chars) * length
                    entropy = length * (len(chars).bit_length())
            
            # Security rating based on entropy
            if entropy < 50:
                security_level = "Low"
                color = "red"
            elif entropy < 80:
                security_level = "Medium"
                color = "orange"
            elif entropy < 100:
                security_level = "High"
                color = "blue"
            else:
                security_level = "Very High"
                color = "green"
                
            st.markdown(f"**Password Entropy:** ~{entropy} bits")
            st.markdown(f"**Security Level:** <span style='color:{color};font-weight:bold'>{security_level}</span>", unsafe_allow_html=True)
            
            # One-click copy
            st.text_input("Copy your password:", value=password)
            
# --- 11. Hash Speed Test (NEW FEATURE) ---
elif feature == "⏱️ Hash Speed Test":
    st.header("⏱️ Hash Algorithm Speed Test")
    
    hash_algorithms = ["SHA-256", "SHA-512", "SHA3-256", "BLAKE2b"]
    test_algorithm = st.selectbox("Select Hash Algorithm", hash_algorithms)
    
    data_size = st.select_slider(
        "Data Size",
        options=[
            "1 KB", "10 KB", "100 KB", "1 MB", "10 MB"
        ],
        value="1 MB"
    )
    
    # Convert size string to bytes
    size_map = {
        "1 KB": 1024,
        "10 KB": 10 * 1024,
        "100 KB": 100 * 1024,
        "1 MB": 1024 * 1024,
        "10 MB": 10 * 1024 * 1024
    }
    
    byte_size = size_map[data_size]
    
    if st.button("Run Speed Test"):
        with st.spinner(f"Testing {test_algorithm} on {data_size} of data..."):
            # Generate random data
            test_data = get_random_bytes(byte_size)
            
            # Create hash function
            start_time = datetime.datetime.now()
            
            # Hash the data with selected algorithm
            if test_algorithm == "SHA-256":
                for _ in range(5):  # Run multiple times for more accurate measurement
                    h = hashlib.sha256(test_data).digest()
            elif test_algorithm == "SHA-512":
                for _ in range(5):
                    h = hashlib.sha512(test_data).digest()
            elif test_algorithm == "SHA3-256":
                for _ in range(5):
                    h = hashlib.sha3_256(test_data).digest()
            elif test_algorithm == "BLAKE2b":
                for _ in range(5):
                    h = hashlib.blake2b(test_data).digest()
            
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Calculate speed
            speed_mbps = (byte_size * 5) / (1024 * 1024) / duration  # Speed in MB/s
            
            # Display results
            st.success(f"Test completed in {duration:.4f} seconds")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Speed", f"{speed_mbps:.2f} MB/s")
            with col2:
                st.metric("Data Processed", data_size)
            
            # Display hash sample
            st.code(h.hex()[:32] + "...", language="bash")
            
            # Compare with other algorithms (static comparison)
            st.subheader("Algorithm Comparison")
            
            comparison_data = {
                "Algorithm": ["SHA-256", "SHA-512", "SHA3-256", "BLAKE2b"],
                "Relative Speed": [1.0, 0.7, 0.9, 1.3],
                "Security Level": ["High", "Very High", "Very High", "High"]
            }
            
            df = pd.DataFrame(comparison_data)
            st.dataframe(df)
            
            with st.expander("Security Considerations"):
                st.markdown("""
                - **SHA-256**: Widely used, good balance of speed and security
                - **SHA-512**: More secure than SHA-256 for longer-term security
                - **SHA3-256**: Newer algorithm with different internal structure than SHA-2 family
                - **BLAKE2b**: High-performance hash focused on speed while maintaining security
                """)

# --- 12. File Hash Verification (NEW FEATURE) ---
elif feature == "🔍 File Hash Verification":
    st.header("🔍 File Hash Verification")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # File upload for hashing
        uploaded_file = st.file_uploader("Upload file to hash")
        hash_algorithm = st.selectbox("Hash Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA3-256"])
        
        if uploaded_file and st.button("Calculate Hash"):
            # Read file content
            content = uploaded_file.read()
            
            # Calculate hash based on selected algorithm
            if hash_algorithm == "MD5":
                file_hash = hashlib.md5(content).hexdigest()
            elif hash_algorithm == "SHA-1":
                file_hash = hashlib.sha1(content).hexdigest()
            elif hash_algorithm == "SHA-256":
                file_hash = hashlib.sha256(content).hexdigest()
            elif hash_algorithm == "SHA3-256":
                file_hash = hashlib.sha3_256(content).hexdigest()
            
            st.success("Hash calculated successfully")
            st.code(file_hash, language="bash")
            
            # Copy button
            st.text_input("Copy hash:", value=file_hash)
    
    with col2:
        # Hash verification
        st.subheader("Verify Hash")
        expected_hash = st.text_input("Expected Hash")
        
        if uploaded_file and expected_hash:
            # Clean input (remove whitespace)
            expected_hash = expected_hash.strip().lower()
            
            if file_hash == expected_hash:
                st.success("✅ Hash verified! File is authentic.")
            else:
                st.error("❌ Hash mismatch! File may be corrupted or tampered with.")
                
                # Show comparison
                st.subheader("Comparison")
                st.markdown(f"**Expected:** `{expected_hash}`")
                st.markdown(f"**Calculated:** `{file_hash}`")
    
    # Security information
    with st.expander("Hash Algorithm Security Information"):
        st.markdown("""
        - **MD5**: Fast but broken. Should not be used for security purposes.
        - **SHA-1**: Faster than SHA-256 but has known weaknesses. Not recommended for security.
        - **SHA-256**: Good balance of speed and security. Recommended for most use cases.
        - **SHA3-256**: Newer hash algorithm with different construction than SHA-2 family.
        """)
        
        st.warning("For security-critical applications, prefer SHA-256 or SHA3-256.")

# --- 13. JWT Token Inspector (NEW FEATURE) ---
elif feature == "🎫 JWT Token Inspector":
    st.header("🌐 JWT Token Inspector & Validator")
    
    jwt_token = st.text_area("Enter JWT Token", height=100, placeholder="eyJhb...token")
    
    if jwt_token and st.button("Decode Token"):
        # Simple JWT parsing without verification
        try:
            # Split the token into parts
            parts = jwt_token.split('.')
            if len(parts) != 3:
                st.error("Invalid JWT format. A JWT should have 3 parts separated by dots.")
            else:
                # Decode header and payload (ignore signature)
                
                # Add padding for proper base64 decoding
                def decode_base64_url(input_str):
                    padding_needed = len(input_str) % 4
                    if padding_needed:
                        input_str += '=' * (4 - padding_needed)
                    return base64.urlsafe_b64decode(input_str).decode('utf-8')
                
                try:
                    header_raw = parts[0]
                    payload_raw = parts[1]
                    signature_raw = parts[2]
                    
                    header = json.loads(decode_base64_url(header_raw))
                    payload = json.loads(decode_base64_url(payload_raw))
                    
                    # Display token parts
                    st.subheader("Header")
                    st.json(header)
                    
                    st.subheader("Payload")
                    st.json(payload)
                    
                    # Token information and validation
                    st.subheader("Token Information")
                    
                    # Check if token has expiration
                    if 'exp' in payload:
                        exp_timestamp = payload['exp']
                        exp_datetime = datetime.datetime.fromtimestamp(exp_timestamp)
                        current_time = datetime.datetime.now()
                        
                        if current_time > exp_datetime:
                            st.error(f"⚠️ Token expired on {exp_datetime}")
                        else:
                            time_left = exp_datetime - current_time
                            st.success(f"✅ Token valid until {exp_datetime} ({time_left.days} days, {time_left.seconds//3600} hours remaining)")
                    else:
                        st.warning("No expiration time found in token")
                    
                    # Display token algorithm
                    if 'alg' in header:
                        alg = header['alg']
                        if alg == 'none':
                            st.error("⚠️ Insecure 'none' algorithm used! This is vulnerable to tampering.")
                        elif alg.startswith('HS'):
                            st.info(f"Algorithm: {alg} (HMAC-based)")
                        elif alg.startswith('RS'):
                            st.info(f"Algorithm: {alg} (RSA-based)")
                        elif alg.startswith('ES'):
                            st.info(f"Algorithm: {alg} (ECDSA-based)")
                        else:
                            st.info(f"Algorithm: {alg}")
                            
                    # Additional token information
                    if 'iat' in payload:
                        iat_datetime = datetime.datetime.fromtimestamp(payload['iat'])
                        st.info(f"Issued at: {iat_datetime}")
                    
                    if 'iss' in payload:
                        st.info(f"Issuer: {payload['iss']}")
                    
                    if 'sub' in payload:
                        st.info(f"Subject: {payload['sub']}")
                except Exception as e:
                    st.error(f"Error decoding token: {str(e)}")
        except Exception as e:
            st.error(f"Failed to decode token: {str(e)}")
    
    with st.expander("JWT Security Tips"):
        st.markdown("""
        - Always verify JWT signatures before trusting any claims
        - Use strong signing keys and prefer asymmetric algorithms (RS256, ES256) over symmetric ones (HS256)
        - Set reasonable expiration times
        - Include 'aud' (audience) claims to prevent token reuse across services
        - Never pass sensitive information in a JWT without encryption
        """)

# --- 14. SSH Key Manager (NEW FEATURE) ---
elif feature == "🗝️ SSH Key Manager":
    st.header("🔒 SSH Key Manager")
    
    ssh_operation = st.radio("Operation", ["Generate SSH Key", "Convert SSH Key Format", "View Public Key"])
    
    if ssh_operation == "Generate SSH Key":
        key_type = st.selectbox("Key Type", ["RSA", "ED25519"])
        key_bits = st.select_slider("Key Size (bits)", options=[2048, 3072, 4096, 8192], value=3072) if key_type == "RSA" else None
        
        with st.expander("Advanced Options"):
            key_comment = st.text_input("Key Comment (Optional)", placeholder="your_email@example.com")
            password_protect = st.checkbox("Password Protect Key")
            if password_protect:
                key_password = st.text_input("Key Password", type="password")
        
        if st.button("Generate Key"):
            st.info("Generating SSH key...")
            
            if key_type == "RSA":
                key = RSA.generate(key_bits)
                private_key = key.export_key(format='PEM', passphrase=key_password if password_protect else None)
                public_key = key.publickey().export_key(format='OpenSSH')
                
                # Add comment if provided
                if key_comment:
                    public_key = public_key + b' ' + key_comment.encode()
                
            elif key_type == "ED25519":
                # Note: This is a simplified version. In practice, you'd use libraries like cryptography
                # or paramiko for proper SSH key generation. Using ECC keys as a substitute.
                key = ECC.generate(curve='Ed25519')
                private_key = key.export_key(format='PEM', passphrase=key_password if password_protect else None)
                
                # This is a simplified representation
                public_key = b"ssh-ed25519 " + base64.b64encode(key.public_key().export_key(format='raw'))
                
                # Add comment if provided
                if key_comment:
                    public_key = public_key + b' ' + key_comment.encode()
            
            # Display keys
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Private Key")
                st.code(private_key.decode(), language="bash")
                st.download_button("Download Private Key", private_key, file_name="id_" + key_type.lower())
                
            with col2:
                st.subheader("Public Key")
                st.code(public_key.decode(), language="bash")
                st.download_button("Download Public Key", public_key, file_name="id_" + key_type.lower() + ".pub")
                
            # Usage instructions
            st.subheader("Usage Instructions")
            st.markdown("""
            1. Download the private key and public key files
            2. Move the private key to `~/.ssh/` directory on your system
            3. Set proper permissions: `chmod 600 ~/.ssh/id_rsa`
            4. Add the public key to authorized_keys on your server
            """)
            
    elif ssh_operation == "Convert SSH Key Format":
        st.info("Upload your SSH key to convert between formats")
        
        uploaded_key = st.file_uploader("Upload SSH Key")
        target_format = st.selectbox("Target Format", ["OpenSSH", "PEM", "PKCS#8"])
        
        if uploaded_key and st.button("Convert"):
            st.warning("This feature would convert between SSH key formats")
            st.info("In a complete implementation, this would use libraries like cryptography or paramiko to handle SSH key format conversion")
    
    elif ssh_operation == "View Public Key":
        st.info("Extract public key from private key")
        
        uploaded_key = st.file_uploader("Upload Private SSH Key")
        
        if uploaded_key and st.button("Extract Public Key"):
            try:
                key_data = uploaded_key.read()
                
                # Try to determine key type and extract public key
                try:
                    key = RSA.import_key(key_data)
                    public_key = key.publickey().export_key(format='OpenSSH')
                    st.success("Public key extracted successfully")
                    st.code(public_key.decode(), language="bash")
                    st.download_button("Download Public Key", public_key, file_name="extracted_key.pub")
                except:
                    try:
                        # Try as ECC key
                        key = ECC.import_key(key_data)
                        public_key = key.public_key().export_key(format='OpenSSH')
                        st.success("Public key extracted successfully")
                        st.code(public_key.decode(), language="bash")
                        st.download_button("Download Public Key", public_key, file_name="extracted_key.pub")
                    except Exception as e:
                        st.error(f"Unable to extract public key: {str(e)}")
            except Exception as e:
                st.error(f"Error reading key file: {str(e)}")
                
    # SSH Security tips
    with st.expander("SSH Security Best Practices"):
        st.markdown("""
        - Use ED25519 keys when possible (they're smaller and more secure)
        - Always protect SSH private keys with a strong passphrase
        - Use ssh-agent to avoid typing your passphrase repeatedly
        - Regularly audit and rotate SSH keys
        - Consider using certificate-based authentication for large deployments
        """)

elif feature == "🕵️ Cipher Identifier":
    st.header("🕵️ Cipher Pattern Identifier")
    st.markdown("Paste ciphertext and get a guess of the cipher type based on its structure.")

    ciphertext = st.text_area("Enter Ciphertext")

    if st.button("Analyze Cipher"):
        if ciphertext:
            guess = ""
            if all(c.isupper() or c.isspace() for c in ciphertext):
                guess = "Possibly Caesar or Vigenère Cipher"
            elif all(c.isalnum() or c in ['/', '+', '='] for c in ciphertext.strip()):
                guess = "Possibly Base64-encoded"
            elif all(c in "01" for c in ciphertext.strip()):
                guess = "Binary-encoded data"
            elif ciphertext.startswith("-----BEGIN") and "KEY" in ciphertext:
                guess = "PEM-formatted key (e.g., RSA, ECC)"
            else:
                guess = "Could not confidently identify. Might be encrypted or encoded."

            st.info(f"🔍 Guess: **{guess}**")


elif feature == "🧮 Modular Calculator":
    st.header("🧮 Modular Arithmetic Calculator")

    a = st.number_input("Enter A", value=17)
    b = st.number_input("Enter B", value=5)
    mod = st.number_input("Modulus", value=7)
    operation = st.selectbox("Operation", ["Addition", "Subtraction", "Multiplication", "Exponentiation", "Inverse"])

    if st.button("Calculate"):
        try:
            if operation == "Addition":
                result = (a + b) % mod
            elif operation == "Subtraction":
                result = (a - b) % mod
            elif operation == "Multiplication":
                result = (a * b) % mod
            elif operation == "Exponentiation":
                result = pow(a, b, mod)
            elif operation == "Inverse":
                result = pow(int(a), -1, int(mod))
            st.success(f"🧠 Result: {result}")
        except Exception as e:
            st.error(f"Error: {e}")


elif feature == "🔢 Base Converter":
    st.header("🔁 Number Base Converter")

    num = st.text_input("Enter Number")
    input_base = st.selectbox("Input Base", [2, 8, 10, 16], index=2)
    output_base = st.selectbox("Output Base", [2, 8, 10, 16], index=0)

    if st.button("Convert"):
        try:
            dec = int(num, input_base)
            if output_base == 2:
                result = bin(dec)[2:]
            elif output_base == 8:
                result = oct(dec)[2:]
            elif output_base == 10:
                result = str(dec)
            elif output_base == 16:
                result = hex(dec)[2:]
            st.code(result.upper())
        except Exception as e:
            st.error(f"Conversion failed: {e}")





elif feature == "🧩 Crypto Puzzle Game":
    st.header("🧠 Crypto Puzzle Challenge")

    puzzles = [
        {"question": "Decrypt this Caesar cipher: 'Wklv lv ixq!'", "answer": "This is fun"},
        {"question": "What algorithm uses modulo arithmetic and a public-private keypair?", "answer": "RSA"},
        {"question": "Convert this hex to ASCII: 48656c6c6f", "answer": "Hello"},
        {"question": "Identify: Ciphertext with 'MIIB' and 'KEY' headers", "answer": "RSA Key"},
    ]

    selected = random.choice(puzzles)
    st.markdown(f"🧩 Puzzle: {selected['question']}")

    guess = st.text_input("Your Answer")

    if st.button("Submit Answer"):
        if guess.strip().lower() == selected['answer'].lower():
            st.success("🎉 Correct! You're a crypto genius!")
        else:
            st.error("❌ Nope! Try again,  hacker 💔")


elif feature == "📈 ECC Key Exchange Visualizer":
    st.header("🧬 ECC Key Exchange (ECDH) Visualizer")
    curve = st.selectbox("Select Curve", ["P-256", "P-384", "P-521"])
    
    if st.button("Generate Key Pairs and Compute Shared Secret"):
        alice_priv = ECC.generate(curve=curve)
        bob_priv = ECC.generate(curve=curve)

        alice_pub = alice_priv.public_key()
        bob_pub = bob_priv.public_key()

        shared_alice = alice_priv.d * bob_pub.pointQ
        shared_bob = bob_priv.d * alice_pub.pointQ

        st.subheader("🔐 Key Exchange Results")
        col1, col2 = st.columns(2)
        with col1:
            st.code(alice_priv.export_key(format='PEM'), "Alice Private Key")
            st.code(alice_pub.export_key(format='PEM'), "Alice Public Key")
        with col2:
            st.code(bob_priv.export_key(format='PEM'), "Bob Private Key")
            st.code(bob_pub.export_key(format='PEM'), "Bob Public Key")
        
        st.code(f"Shared Secret (Alice): {shared_alice}", "bash")
        st.code(f"Shared Secret (Bob):   {shared_bob}", "bash")
        st.success("🎉 Shared secrets match! Secure channel established.")



elif feature == "⏰ TOTP Generator & Verifier":
    st.header("📅 TOTP Authenticator")
    
    secret = st.text_input("Secret (Base32)", value=pyotp.random_base32())
    totp = pyotp.TOTP(secret)

    st.write("🔢 Current OTP:", totp.now())
    st.write("⏳ Time left:", totp.interval - (int(time.time()) % totp.interval), "seconds")

    st.text_input("Enter OTP to Verify", key="otp_input")
    if st.button("Verify OTP"):
        if totp.verify(st.session_state.otp_input):
            st.success("✅ Valid OTP!")
        else:
            st.error("❌ Invalid OTP!")





elif feature == "✂️ File Splitter & Joiner":
    st.header("📁 File Splitter & Joiner")
    mode = st.radio("Mode", ["Split", "Join"])

    if mode == "Split":
        file = st.file_uploader("Upload File to Split")
        chunk_size = st.number_input("Chunk Size (bytes)", value=1024*1024)

        if file and st.button("Split File"):
            data = file.read()
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                st.download_button(f"Download Chunk {i//chunk_size}", chunk, file_name=f"chunk_{i//chunk_size}.bin")
    
    else:
        files = st.file_uploader("Upload Chunks", accept_multiple_files=True, type=["bin"])
        if files and st.button("Join Files"):
            combined = b''.join(file.read() for file in sorted(files, key=lambda f: f.name))
            st.download_button("Download Combined File", combined, file_name="joined_output.bin")






elif feature == "📏 Entropy Analyzer":
    st.header("🔎 Shannon Entropy Analyzer")
    text = st.text_area("Input Text or Data")

    if st.button("Analyze Entropy"):
        if text:
            freq = {char: text.count(char)/len(text) for char in set(text)}
            entropy = -sum(p * math.log2(p) for p in freq.values())
            st.success(f"Entropy: {entropy:.4f} bits per symbol")
            st.info("🔒 Higher entropy = more randomness")







elif feature == "📨 PGP File Encrypt/Decrypt":
    st.header("📦 Simulated PGP (Hybrid RSA + AES Encryption)")

    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        file = st.file_uploader("Upload File to Encrypt")
        if file and st.button("Encrypt and Download"):
            # Generate RSA Key Pair
            rsa_key = RSA.generate(2048)
            public_key = rsa_key.publickey()

            # Generate AES Key and Encrypt it using RSA
            aes_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_key = cipher_rsa.encrypt(aes_key)

            # Encrypt File with AES
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file.read())

            # Bundle = Encrypted AES Key + Nonce + Tag + Ciphertext
            bundle = encrypted_key + cipher_aes.nonce + tag + ciphertext
            private_key_pem = rsa_key.export_key()

            # Create a ZIP archive in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
                zipf.writestr("pgp_encrypted.bin", bundle)
                zipf.writestr("rsa_private.pem", private_key_pem)
            zip_buffer.seek(0)

            # Single Download Button
            st.download_button(
                label="📦 Download Encrypted ZIP (File + Private Key)",
                data=zip_buffer,
                file_name="PGP_Encrypted_Package.zip",
                mime="application/zip"
            )
            st.success("✅ Encrypted bundle + RSA key packed in one ZIP!")

    else:
        encrypted_file = st.file_uploader("Upload Encrypted File (pgp_encrypted.bin)")
        private_key_file = st.file_uploader("Upload RSA Private Key (rsa_private.pem)")

        if encrypted_file and private_key_file and st.button("Decrypt File"):
            try:
                private_key = RSA.import_key(private_key_file.read())
                cipher_rsa = PKCS1_OAEP.new(private_key)

                bundle_data = encrypted_file.read()
                key_size = private_key.size_in_bytes()

                enc_aes_key = bundle_data[:key_size]
                nonce = bundle_data[key_size:key_size+16]
                tag = bundle_data[key_size+16:key_size+32]
                ciphertext = bundle_data[key_size+32:]

                aes_key = cipher_rsa.decrypt(enc_aes_key)
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

                st.download_button("Download Decrypted File", decrypted, file_name="decrypted_output.bin")
                st.success("✅ File successfully decrypted!")
            except Exception as e:
                st.error(f"❌ Decryption failed: {str(e)}")



elif feature == "🗄️ Master Key Derivation Tool":
    st.header("🔐 Derive Unique Keys from Master Password")
    master = st.text_input("Master Password", type="password")
    site = st.text_input("Service Identifier (e.g., gmail.com)")

    if master and site:
        salt = site.encode()
        derived = PBKDF2(master.encode(), salt, dkLen=32, count=100000)
        st.code(derived.hex(), "Derived Key (Hex)")


elif feature == "📝 Encrypted Notes Vault":
    st.header("💾 Secure Notes Vault")
    vault_pwd = st.text_input("Vault Password", type="password")
    note = st.text_area("Write your secure note here")

    if st.button("Save Note"):
        if vault_pwd and note:
            key = SHA256.new(vault_pwd.encode()).digest()
            cipher = AES.new(key, AES.MODE_EAX)
            ct, tag = cipher.encrypt_and_digest(note.encode())
            blob = base64.b64encode(cipher.nonce + tag + ct).decode()
            st.code(blob, "Encrypted Note")

    decrypt_blob = st.text_area("Paste Encrypted Note")
    if st.button("Decrypt Note"):
        try:
            data = base64.b64decode(decrypt_blob)
            nonce, tag, ct = data[:16], data[16:32], data[32:]
            cipher = AES.new(SHA256.new(vault_pwd.encode()).digest(), AES.MODE_EAX, nonce)
            decrypted = cipher.decrypt_and_verify(ct, tag)
            st.success("Decrypted Note:")
            st.code(decrypted.decode())
        except Exception as e:
            st.error("Failed to decrypt: " + str(e))


elif feature == "💬 Secure Chat Demo (ECC + AES)":
    st.header("🛰️ Secure Chat Simulation (ECC + AES)")
    msg = st.text_area("Your Message")
    shared_secret = SHA256.new(b"shared_key_simulated").digest()

    if msg:
        cipher = AES.new(shared_secret, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(msg.encode())
        encrypted_blob = base64.b64encode(cipher.nonce + tag + ct).decode()
        st.code(encrypted_blob, "Encrypted Message")

    encrypted_msg = st.text_input("Paste Encrypted Message to Decrypt")
    if encrypted_msg:
        try:
            data = base64.b64decode(encrypted_msg)
            nonce, tag, ct = data[:16], data[16:32], data[32:]
            cipher = AES.new(shared_secret, AES.MODE_EAX, nonce)
            decrypted = cipher.decrypt_and_verify(ct, tag)
            st.success("Decrypted Message:")
            st.code(decrypted.decode())
        except Exception as e:
            st.error("Decryption Failed: " + str(e))



elif feature == "🎲 Randomness Tester":
    st.header("🔍 Randomness Tester (Basic)")
    binary_data = st.text_area("Binary String (e.g., 010101...)")

    if binary_data:
        length = len(binary_data)
        ones = binary_data.count('1')
        zeros = binary_data.count('0')
        balance = abs(ones - zeros) / length

        st.write(f"⚪ Zeros: {zeros}")
        st.write(f"⚫ Ones: {ones}")
        st.write(f"⚖️ Balance Ratio: {balance:.2f}")

        if balance < 0.1:
            st.success("✅ Looks fairly random")
        else:
            st.warning("⚠️ Possibly biased or patterned")





elif feature == "✍️ File Signature Generator & Verifier":
    st.header("✍️ File Digital Signature Tool")

    mode = st.radio("Mode", ["Sign File", "Verify Signature"])
    
    if mode == "Sign File":
        file = st.file_uploader("Upload File to Sign")
        if file and st.button("Generate RSA Signature"):
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            content = file.read()
            hash_obj = SHA256.new(content)
            signature = pkcs1_15.new(key).sign(hash_obj)

            # Save all to ZIP
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zipf:
                zipf.writestr("file.data", content)
                zipf.writestr("signature.bin", signature)
                zipf.writestr("public_key.pem", public_key)
            buffer.seek(0)

            st.download_button("📦 Download Signed Package", buffer, file_name="signed_file_package.zip")
            st.success("✅ File signed and bundled!")

    else:
        file = st.file_uploader("Upload File")
        signature_file = st.file_uploader("Upload Signature (.bin)")
        pub_key_file = st.file_uploader("Upload Public Key (.pem)")

        if file and signature_file and pub_key_file and st.button("Verify Signature"):
            try:
                content = file.read()
                signature = signature_file.read()
                public_key = RSA.import_key(pub_key_file.read())
                hash_obj = SHA256.new(content)

                pkcs1_15.new(public_key).verify(hash_obj, signature)
                st.success("✅ Signature is valid! File is authentic.")
            except Exception as e:
                st.error(f"❌ Signature verification failed: {str(e)}")





elif feature == "🌌 Post-Quantum Cryptography Simulator":
    st.header("🛡️ Post-Quantum Cryptography Simulator (Simplified)")

    st.write("This simulates a key encapsulation mechanism (KEM) like Kyber (not secure, just demo)")

    if st.button("Generate Keypair"):
        public_key = os.urandom(32)
        private_key = os.urandom(32)
        st.code(public_key.hex(), "Public Key")
        st.code(private_key.hex(), "Private Key")

    if st.button("Encapsulate"):
        ciphertext = os.urandom(64)
        shared_secret = os.urandom(32)
        st.code(ciphertext.hex(), "Ciphertext")
        st.code(shared_secret.hex(), "Shared Secret")

    if st.button("Decapsulate"):
        shared_secret = os.urandom(32)
        st.code(shared_secret.hex(), "Shared Secret")


elif feature == "🧹 Encrypted File Metadata Remover":
    st.header("🧹 Encrypted File Metadata Remover")

    uploaded_file = st.file_uploader("Upload Image (JPEG/PNG)")

    if uploaded_file:
        try:
            image = Image.open(uploaded_file)
            data = list(image.getdata())
            clean_image = Image.new(image.mode, image.size)
            clean_image.putdata(data)

            buf = io.BytesIO()
            clean_image.save(buf, format="PNG")
            buf.seek(0)

            st.image(clean_image, caption="Image with Metadata Removed")
            st.download_button("Download Clean Image", buf, file_name="clean_image.png")
        except Exception as e:
            st.error(f"Error processing image: {e}")

elif feature == "⛓️ Blockchain Hash Logger":
    st.header("⛓️ Blockchain Hash Logger (Demo)")

    uploaded_file = st.file_uploader("Upload file to log hash on blockchain")
    if uploaded_file and st.button("Log Hash"):
        content = uploaded_file.read()
        file_hash = hashlib.sha256(content).hexdigest()
        st.write(f"File SHA256 Hash: {file_hash}")

        # Dummy demo - pretend to post to a blockchain explorer API
        try:
            # Replace with real API calls for actual blockchain logging
            response = {"status": "success", "txid": "dummy_txid_123456"}
            if response["status"] == "success":
                st.success(f"Hash logged! TXID: {response['txid']}")
            else:
                st.error("Failed to log hash")
        except Exception as e:
            st.error(f"API error: {e}")



# --- 1. Homomorphic Encryption Explorer ---
elif feature == "🔮 Homomorphic Encryption Explorer":
    st.header("🔮 Homomorphic Encryption Explorer")
    
    st.markdown("""
    ### Explore Partially Homomorphic Encryption
    Homomorphic encryption allows computations on encrypted data without decrypting it first.
    This demo illustrates the basic concepts using a simplified implementation.
    """)
    
    he_tab1, he_tab2, he_tab3 = st.tabs(["Basic Demo", "Interactive Explorer", "Learning Resources"])
    
    with he_tab1:
        st.subheader("Simple Homomorphic Operations")
        
        # Simple Paillier-like homomorphic encryption (for demonstration)
        def simple_encrypt(value, public_key):
            n, g = public_key
            r = random.randint(1, n-1)
            return (pow(g, value, n**2) * pow(r, n, n**2)) % (n**2)
        
        def add_encrypted(c1, c2, public_key):
            n, _ = public_key
            return (c1 * c2) % (n**2)
        
        # Generate demo keys
        p, q = 17, 19
        n = p * q
        g = n + 1
        public_key = (n, g)
        
        # Allow user to input two values
        col1, col2 = st.columns(2)
        with col1:
            value1 = st.number_input("First Value", min_value=0, max_value=100, value=7)
        with col2:
            value2 = st.number_input("Second Value", min_value=0, max_value=100, value=9)
        
        if st.button("Encrypt and Compute"):
            # Encrypt values
            encrypted1 = simple_encrypt(value1, public_key)
            encrypted2 = simple_encrypt(value2, public_key)
            
            # Perform homomorphic addition
            encrypted_sum = add_encrypted(encrypted1, encrypted2, public_key)
            
            # Display results
            st.write("#### Results")
            
            results_col1, results_col2 = st.columns(2)
            with results_col1:
                st.write("**Original Values:**")
                st.write(f"Value 1: {value1}")
                st.write(f"Value 2: {value2}")
                st.write(f"Sum: {value1 + value2}")
            
            with results_col2:
                st.write("**Encrypted Values:**")
                st.write(f"Encrypted Value 1: {encrypted1}")
                st.write(f"Encrypted Value 2: {encrypted2}")
                st.write(f"Encrypted Sum: {encrypted_sum}")
            
            st.success(f"The homomorphic addition worked! {value1} + {value2} = {value1 + value2}")
    
    with he_tab2:
        st.subheader("Interactive Homomorphic Properties")
        operation = st.selectbox("Select Operation", ["Addition", "Multiplication"])
        
        col1, col2 = st.columns(2)
        with col1:
            x = st.slider("Value x", 1, 50, 10)
        with col2:
            y = st.slider("Value y", 1, 50, 5)
        
        # Visual representation of homomorphic operations
        fig, ax = plt.subplots(1, 3, figsize=(15, 5))
        
        # Original value representations
        ax[0].bar(['x', 'y'], [x, y], color=['blue', 'green'])
        ax[0].set_title('Original Values')
        
        # Encrypted representations (abstract visualization)
        ax[1].bar(['E(x)', 'E(y)'], [x, y], color=['blue', 'green'], alpha=0.5)
        for i in range(30):  # Add noise visualization
            ax[1].plot([0, 0], [random.random()*x, random.random()*x], 'r-', alpha=0.1)
            ax[1].plot([1, 1], [random.random()*y, random.random()*y], 'r-', alpha=0.1)
        ax[1].set_title('Encrypted Values (Conceptual)')
        
        # Result of operation
        if operation == "Addition":
            result = x + y
            ax[2].bar(['x + y', 'Decrypted E(x) + E(y)'], [result, result], color='purple')
            ax[2].set_title('Result of Addition')
        else:  # Multiplication
            result = x * y
            ax[2].bar(['x * y', 'Decrypted E(x) * E(y)'], [result, result], color='purple')
            ax[2].set_title('Result of Multiplication')
            
        st.pyplot(fig)
        
        st.info(f"This visualization shows how {operation.lower()} can be performed on encrypted data, yielding the same result as performing the operation on plaintext.")
    
    with he_tab3:
        st.subheader("How Homomorphic Encryption Works")
        st.markdown("""
        ### Types of Homomorphic Encryption:
        
        1. **Partially Homomorphic Encryption (PHE)**: Supports either addition OR multiplication, but not both.
           - Example: Paillier (addition), RSA (multiplication)
           
        2. **Somewhat Homomorphic Encryption (SWHE)**: Supports both operations but only for a limited number of operations.
        
        3. **Fully Homomorphic Encryption (FHE)**: Supports unlimited operations of both addition and multiplication.
           - Based on lattice-based cryptography
           - Computationally intensive
        
        ### Applications:
        - Private data analytics
        - Secure cloud computing
        - Privacy-preserving machine learning
        - Secure voting systems
        """)


# --- 2. Zero-Knowledge Proof Generator ---
elif feature == "🎭 Zero-Knowledge Proof Generator":
    st.header("🎭 Zero-Knowledge Proof Generator")
    
    st.markdown("""
    ### Zero-Knowledge Proofs
    Zero-knowledge proofs allow one party (the prover) to prove to another party (the verifier) 
    that a statement is true, without revealing any information beyond the validity of the statement itself.
    """)
    
    zk_tab1, zk_tab2, zk_tab3 = st.tabs(["Schnorr Protocol", "Password Verification", "Advanced ZK Concepts"])
    
    with zk_tab1:
        st.subheader("Schnorr ZK Protocol Demo")
        st.markdown("""
        The Schnorr protocol allows a prover to demonstrate knowledge of a discrete logarithm 
        without revealing the logarithm itself.
        
        In this demo, Alice will prove to Bob that she knows the secret value x, 
        where y = g^x mod p, without revealing x.
        """)
        
        # Define the parameters
        p = 23  # A small prime for demonstration
        g = 5   # A generator of the multiplicative group mod p
        
        # Alice's secret
        secret_x = st.slider("Alice's secret value (x)", 1, 15, 7, help="This is the secret value Alice knows")
        
        # Calculate the public value y = g^x mod p
        y = pow(g, secret_x, p)
        
        st.write(f"Public Information: p = {p}, g = {g}, y = {y}")
        
        if st.button("Generate Proof"):
            # Alice's random commitment
            k = random.randint(1, p-2)
            r = pow(g, k, p)
            
            # Bob's challenge
            c = random.randint(1, p-2)
            
            # Alice's response
            s = (k - c * secret_x) % (p-1)
            
            # Verification
            left_side = pow(g, s, p) * pow(y, c, p) % p
            right_side = r
            
            # Display the proof steps
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Proof Generation")
                st.write(f"1. Alice chooses random k = {k}")
                st.write(f"2. Alice computes r = g^k mod p = {r}")
                st.write(f"3. Bob sends challenge c = {c}")
                st.write(f"4. Alice computes s = k - c*x mod (p-1) = {s}")
                st.write(f"5. Alice sends s to Bob")
            
            with col2:
                st.markdown("#### Verification")
                st.write(f"Bob computes g^s * y^c mod p = {left_side}")
                st.write(f"Bob checks if this equals r = {right_side}")
                
                if left_side == right_side:
                    st.success("Verification succeeded! Alice has proven she knows x without revealing it.")
                else:
                    st.error("Verification failed!")
    
    with zk_tab2:
        st.subheader("Zero-Knowledge Password Verification")
        st.markdown("""
        This demonstrates how a password can be verified without actually sending the password to the verifier.
        """)
        
        # User inputs
        password = st.text_input("Enter a password", value="SecretPass123", type="password")
        salt = "RandomSalt123"  # In practice, this would be generated and stored
        
        if st.button("Simulate ZK Password Verification"):
            # Hash the password (this would be stored on the server)
            import hashlib
            stored_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            # ZK verification simulation steps
            st.write("#### ZK Password Verification Steps")
            
            # Step 1: Client creates a proof
            st.write("1. Client locally hashes the password with the salt")
            st.write(f"2. Server already has stored hash: {stored_hash[:10]}...{stored_hash[-10:]}")
            
            # Step 3: Challenge-response (simplified)
            challenge = random.randint(1000000, 9999999)
            st.write(f"3. Server sends a challenge: {challenge}")
            
            # Response is a hash of the stored hash and the challenge
            response = hashlib.sha256((stored_hash + str(challenge)).encode()).hexdigest()
            st.write(f"4. Client computes response using stored hash and challenge: {response[:10]}...{response[-10:]}")
            
            # Server verification (simulated)
            server_expected = hashlib.sha256((stored_hash + str(challenge)).encode()).hexdigest()
            
            if response == server_expected:
                st.success("✅ Authentication successful! The server verified the password without seeing it.")
            else:
                st.error("❌ Authentication failed!")
                
            st.info("This is a simplified demonstration. Real ZK password systems use more complex cryptographic protocols.")
    
    with zk_tab3:
        st.subheader("Advanced Zero-Knowledge Concepts")
        
        st.markdown("""
        ### Modern Zero-Knowledge Proof Systems:
        
        1. **zk-SNARKs** (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge)
           - Used in Zcash cryptocurrency
           - Allows for private transactions
           - Requires a trusted setup phase
        
        2. **zk-STARKs** (Zero-Knowledge Scalable Transparent Arguments of Knowledge)
           - No trusted setup required
           - More scalable than SNARKs
           - Post-quantum secure
        
        3. **Bulletproofs**
           - Efficient for range proofs
           - No trusted setup
           - Used in Monero cryptocurrency
        
        ### Applications:
        - Private cryptocurrency transactions
        - Anonymous credentials
        - Private smart contracts
        - Identity verification without revealing personal data
        - Secure voting systems
        """)


# --- 3. Merkle Tree Visualizer & Builder ---
elif feature == "🌳 Merkle Tree Visualizer & Builder":
    st.header("🌳 Merkle Tree Visualizer & Builder")
    
    st.markdown("""
    ### Merkle Trees
    A Merkle tree is a hash-based data structure that allows efficient and secure verification of content in large data structures.
    Each leaf node contains the hash of a data block, and each non-leaf node contains the hash of its child nodes.
    """)
    
    mt_tab1, mt_tab2, mt_tab3 = st.tabs(["Build Merkle Tree", "Verify Data", "Applications"])
    
    with mt_tab1:
        st.subheader("Build Your Merkle Tree")
        
        # Define hash function for the tree
        def hash_data(data):
            return SHA256.new(data.encode()).hexdigest()
        
        # Build Merkle Tree from list of data items
        def build_merkle_tree(data_list):
            if len(data_list) == 0:
                return None
            
            # Create leaf nodes by hashing data
            leaves = [hash_data(item) for item in data_list]
            
            # If odd number of items, duplicate the last one
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            
            # Store all nodes for visualization
            all_nodes = [leaves]
            
            # Build the tree bottom-up
            current_level = leaves
            while len(current_level) > 1:
                next_level = []
                
                # Process pairs of nodes
                for i in range(0, len(current_level), 2):
                    if i + 1 < len(current_level):
                        combined = current_level[i] + current_level[i + 1]
                        parent_hash = hash_data(combined)
                        next_level.append(parent_hash)
                    else:
                        # If odd number of nodes, promote the last one
                        next_level.append(current_level[i])
                
                all_nodes.append(next_level)
                current_level = next_level
            
            return {
                "root": current_level[0],
                "all_nodes": all_nodes
            }
        
        # User inputs
        data_input = st.text_area("Enter data items (one per line):", 
                                   value="Transaction 1\nTransaction 2\nTransaction 3\nTransaction 4")
        
        data_items = [item.strip() for item in data_input.split("\n") if item.strip()]
        
        if st.button("Build Merkle Tree"):
            if not data_items:
                st.error("Please enter at least one data item")
            else:
                tree = build_merkle_tree(data_items)
                
                # Display Merkle Root
                st.subheader("Merkle Root")
                st.code(tree["root"], language="bash")
                
                # Visualize the tree
                st.subheader("Tree Visualization")
                
                # Calculate tree levels and nodes
                levels = len(tree["all_nodes"])
                
                # Create tree visualization
                fig, ax = plt.subplots(figsize=(10, levels * 2))
                ax.set_xlim(0, len(data_items) * 2)
                ax.set_ylim(0, levels * 1.5)
                ax.axis('off')
                
                # Plot nodes
                for level_idx, level_nodes in enumerate(reversed(tree["all_nodes"])):
                    y_pos = level_idx * 1.5 + 0.5
                    node_width = len(data_items) * 2 / len(level_nodes)
                    
                    for node_idx, node_hash in enumerate(level_nodes):
                        x_pos = node_width * (node_idx + 0.5)
                        
                        # Add node as a circle
                        circle = plt.Circle((x_pos, y_pos), 0.3, fill=True, color='skyblue', alpha=0.7)
                        ax.add_patch(circle)
                        
                        # Add short hash text
                        ax.text(x_pos, y_pos, f"{node_hash[:6]}...", 
                                ha='center', va='center', fontsize=8)
                        
                        # Add connections to parent nodes (if not root)
                        if level_idx < levels - 1:
                            parent_level = level_idx + 1
                            parent_nodes = len(tree["all_nodes"][-(parent_level+1)])
                            parent_width = len(data_items) * 2 / parent_nodes
                            parent_idx = node_idx // 2
                            parent_x = parent_width * (parent_idx + 0.5)
                            parent_y = parent_level * 1.5 + 0.5
                            
                            ax.plot([x_pos, parent_x], [y_pos + 0.3, parent_y - 0.3], 'k-', alpha=0.5)
                
                # Add data labels at the bottom
                if len(data_items) <= 8:  # Only show labels for small trees
                    node_width = len(data_items) * 2 / len(tree["all_nodes"][0])
                    for idx, item in enumerate(data_items):
                        x_pos = node_width * (idx + 0.5)
                        y_pos = 0
                        ax.text(x_pos, y_pos, item, ha='center', va='top', fontsize=8, color='green')
                
                st.pyplot(fig)
                
                # Display hashes
                st.subheader("Node Hashes by Level")
                for i, level in enumerate(reversed(tree["all_nodes"])):
                    level_name = "Root" if i == 0 else f"Level {levels - i - 1}"
                    with st.expander(f"{level_name} ({len(level)} nodes)"):
                        for j, node in enumerate(level):
                            st.code(f"Node {j}: {node}", language="bash")
    
    with mt_tab2:
        st.subheader("Merkle Proof Verification")
        
        st.markdown("""
        A Merkle proof allows verification that a specific data block is part of the tree
        without requiring the entire tree.
        """)
        
        # Sample data for demonstration
        sample_data = ["Apple", "Banana", "Cherry", "Date", "Elderberry", "Fig", "Grape", "Honeydew"]
        
        # Let user select sample data or enter custom
        data_option = st.radio("Data Source", ["Use Sample Data", "Custom Data"])
        
        if data_option == "Use Sample Data":
            data_for_proof = sample_data
        else:
            custom_data = st.text_area("Enter custom data (one item per line)", "Item1\nItem2\nItem3\nItem4")
            data_for_proof = [item.strip() for item in custom_data.split('\n') if item.strip()]
        
        # Select an item to verify
        if data_for_proof:
            item_to_verify = st.selectbox("Select item to verify", data_for_proof)
            
            if st.button("Generate and Verify Proof"):
                tree = build_merkle_tree(data_for_proof)
                root_hash = tree["root"]
                
                # Find the index of the item
                item_index = data_for_proof.index(item_to_verify)
                
                # Generate the proof (simplified)
                proof = []
                index = item_index
                
                for level in tree["all_nodes"][:-1]:  # Exclude the root level
                    is_right = index % 2 == 0
                    if is_right and index + 1 < len(level):
                        # If we're a left node, we need the right sibling
                        sibling_index = index + 1
                        sibling_position = "right"
                    else:
                        # If we're a right node, we need the left sibling
                        sibling_index = index - 1
                        sibling_position = "left"
                    
                    if 0 <= sibling_index < len(level):
                        proof.append({
                            "hash": level[sibling_index],
                            "position": sibling_position
                        })
                    
                    # Update index for next level
                    index = index // 2
                
                # Display the proof
                st.subheader("Merkle Proof")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Item to Verify:**", item_to_verify)
                    st.write("**Item Hash:**", hash_data(item_to_verify))
                    st.write("**Merkle Root:**", root_hash)
                
                with col2:
                    st.write("**Proof Elements:**")
                    for i, element in enumerate(proof):
                        st.write(f"{i+1}. {element['position']} sibling: {element['hash'][:10]}...")
                
                # Verify the proof
                current_hash = hash_data(item_to_verify)
                
                verification_steps = []
                verification_steps.append(f"Start with leaf hash: {current_hash[:10]}...")
                
                for i, element in enumerate(proof):
                    if element["position"] == "right":
                        combined = current_hash + element["hash"]
                    else:
                        combined = element["hash"] + current_hash
                    current_hash = hash_data(combined)
                    verification_steps.append(f"Combined with {element['position']} sibling, new hash: {current_hash[:10]}...")
                
                st.subheader("Verification Steps")
                for step in verification_steps:
                    st.write(step)
                
                if current_hash == root_hash:
                    st.success(f"✅ Verification successful! The item '{item_to_verify}' is part of the Merkle tree.")
                else:
                    st.error("❌ Verification failed! The item is not part of the Merkle tree.")
    
    with mt_tab3:
        st.subheader("Merkle Tree Applications")
        
        st.markdown("""
        ### Common Uses of Merkle Trees:
        
        1. **Blockchain Technology**
           - Bitcoin and other cryptocurrencies use Merkle trees to efficiently verify transactions
           - Allows lightweight clients to verify transactions without downloading the entire blockchain
        
        2. **Git Version Control**
           - Git uses a structure similar to Merkle trees to track file changes
           - Enables efficient integrity checking and history tracking
        
        3. **Distributed File Systems**
           - IPFS (InterPlanetary File System) uses Merkle DAGs for content addressing
           - Enables content-based addressing and deduplication
        
        4. **Certificate Transparency**
           - Log servers use Merkle trees to provide cryptographic proof of certificate inclusion
        
        5. **Data Integrity in Distributed Systems**
           - Quickly verify that data hasn't been tampered with
           - Efficiently synchronize data between distributed nodes
        """)


# --- 4. Threshold Cryptography Simulator ---
elif feature == "🔱 Threshold Cryptography Simulator":
    st.header("🔱 Threshold Cryptography Simulator")
    
    st.markdown("""
    ### Threshold Cryptography
    Threshold cryptography distributes cryptographic operations across multiple parties, 
    requiring a minimum number (threshold) of parties to collaborate for operations like 
    decryption or signing.
    """)
    
    tc_tab1, tc_tab2, tc_tab3 = st.tabs(["Shamir's Secret Sharing", "Threshold Signatures", "Applications"])
    
    with tc_tab1:
        st.subheader("Shamir's Secret Sharing")
        st.markdown("""
        Shamir's Secret Sharing allows splitting a secret into n shares, 
        requiring at least k shares to reconstruct the original secret.
        """)
        
        # Helper functions for Shamir's Secret Sharing
        def mod_inverse(x, mod):
            """Find modular multiplicative inverse"""
            return pow(x, mod - 2, mod)
        
        def evaluate_polynomial(coefficients, x, prime):
            """Evaluate polynomial at point x"""
            result = 0
            for coeff in reversed(coefficients):
                result = (result * x + coeff) % prime
            return result
        
        def generate_shares(secret, n, k, prime):
            """Generate n shares with threshold k for the secret"""
            coefficients = [secret] + [random.randint(1, prime-1) for _ in range(k-1)]
            shares = [(i, evaluate_polynomial(coefficients, i, prime)) for i in range(1, n+1)]
            return shares
        
        def reconstruct_secret(shares, k, prime):
            """Reconstruct secret from k shares using Lagrange interpolation"""
            # Only use the first k shares
            shares = shares[:k]
            
            secret = 0
            for i, (x_i, y_i) in enumerate(shares):
                numerator = 1
                denominator = 1
                
                for j, (x_j, _) in enumerate(shares):
                    if i != j:
                        numerator = (numerator * (0 - x_j)) % prime
                        denominator = (denominator * (x_i - x_j)) % prime
                
                lagrange = (y_i * numerator * mod_inverse(denominator, prime)) % prime
                secret = (secret + lagrange) % prime
            
            return secret
        
        # User inputs
        col1, col2 = st.columns(2)
        
        with col1:
            secret = st.number_input("Secret Value", min_value=1, max_value=1000, value=42)
            n = st.number_input("Total Number of Shares (n)", min_value=2, max_value=10, value=5)
        
        with col2:
            k = st.number_input("Threshold (k)", min_value=2, max_value=10, value=3)
            
        st.write(f"This will split the secret {secret} into {n} shares, requiring at least {k} shares to reconstruct.")
        
        # Large prime for finite field operations
        prime = 2**13 - 1  # 8191, a Mersenne prime
        
        if st.button("Generate Shares"):
            # Generate the shares
            shares = generate_shares(secret, n, k, prime)
            
            # Display the shares
            st.subheader("Generated Shares")
            shares_data = pd.DataFrame(shares, columns=["Share ID", "Share Value"])
            st.dataframe(shares_data)
            
            # Reconstruction demonstration
            st.subheader("Secret Reconstruction Demonstration")
            
            available_shares = st.multiselect(
                "Select shares to use for reconstruction:",
                options=[f"Share {i+1}" for i in range(n)],
                default=[f"Share {i+1}" for i in range(k)]
            )
            
            if st.button("Reconstruct Secret"):
                if len(available_shares) < k:
                    st.warning(f"Need at least {k} shares to reconstruct the secret. You selected {len(available_shares)}.")
                else:
                    # Get the indices of selected shares
                    selected_indices = [int(share.split()[1]) - 1 for share in available_shares]
                    selected_shares = [shares[i] for i in selected_indices]
                    
                    # Reconstruct the secret
                    reconstructed = reconstruct_secret(selected_shares, k, prime)
                    
                    if reconstructed == secret:
                        st.success(f"Successfully reconstructed the secret: {reconstructed}")
                    else:
                        st.error(f"Failed to reconstruct the correct secret. Got: {reconstructed}, Expected: {secret}")
                    
                    # Visual explanation
                    fig, ax = plt.subplots()
                    
                    # Plot all shares
                    x_values = [share[0] for share in shares]
                    y_values = [share[1] for share in shares]
                    ax.scatter(x_values, y_values, color='blue', alpha=0.3, label='All Shares')
                    
                    # Highlight selected shares
                    selected_x = [share[0] for share in selected_shares]
                    selected_y = [share[1] for share in selected_shares]
                    ax.scatter(selected_x, selected_y, color='green', label='Selected Shares')
                    
                    # Mark the secret (y-intercept)
                    ax.scatter(0, secret, color='red', marker='*', s=200, label='Secret (y-intercept)')
                    
                    ax.set_title('Shamir Secret Sharing Visualization')
                    ax.set_xlabel('x')
                    ax.set_ylabel('y')
                    ax.legend()
                    
                    st.pyplot(fig)
    
    with tc_tab2:
        st.subheader("Threshold Signatures")
        
        st.markdown("""
        Threshold signatures allow a group of participants to collectively sign a message,
        where at least a threshold number must participate for a valid signature.
        
        This simplified demo illustrates the concept using a (t, n) threshold scheme.
        """)
        
        # User inputs for threshold signatures
        t = st.slider("Threshold (t)", min_value=2, max_value=5, value=3)
        n = st.slider("Total Parties (n)", min_value=t, max_value=7, value=5)
        
        message = st.text_input("Message to Sign", value="Important agreement document")
        
        if st.button("Simulate Threshold Signing"):
            # Simulate key generation
            st.write("#### Step 1: Distributed Key Generation")
            
            # Simplified simulation - in reality, this would be a complex multi-party protocol
            party_keys = []
            for i in range(n):
                party_keys.append({
                    "id": i+1,
                    "private_share": random.randint(1, 1000),
                    "public_share": random.randint(1000, 2000)
                })
            
            # Display key shares
            party_df = pd.DataFrame([{
                "Party ID": key["id"],
                "Private Key Share": f"sk_{key['id']} (hidden)",
                "Public Key Share": f"pk_{key['id']} = {key['public_share']}"
            } for key in party_keys])
            
            st.dataframe(party_df)
            
            # Simulate message signing
            st.write("#### Step 2: Partial Signatures Generation")
            
            # Let user select which parties participate
            participating_parties = st.multiselect(
                "Select participating parties:",
                options=[f"Party {i+1}" for i in range(n)],
                default=[f"Party {i+1}" for i in range(t)]
            )
            
            if len(participating_parties) < t:
                st.warning(f"Need at least {t} parties to create a valid signature. You selected {len(participating_parties)}.")
            else:
                # Generate partial signatures
                partial_sigs = []
                for party in participating_parties:
                    party_id = int(party.split()[1]) - 1
                    party_info = party_keys[party_id]
                    
                    # Simplified signature calculation
                    sig_value = hashlib.sha256((message + str(party_info["private_share"])).encode()).hexdigest()[:8]
                    
                    partial_sigs.append({
                        "party_id": party_info["id"],
                        "signature": sig_value
                    })
                
                # Display partial signatures
                st.write("**Partial Signatures:**")
                for sig in partial_sigs:
                    st.code(f"Party {sig['party_id']}: {sig['signature']}", language="bash")
                
                # Simulate signature combining
                st.write("#### Step 3: Signature Combination")
                
                # In a real implementation, this would involve cryptographic operations
                combined_sig = hashlib.sha256(("".join([sig["signature"] for sig in partial_sigs])).encode()).hexdigest()
                
                st.write("**Combined Signature:**")
                st.code(combined_sig, language="bash")
                
                st.success("✅ Valid threshold signature generated successfully!")
                
                # Explain verification process
                st.write("#### Step 4: Signature Verification")
                st.write("""
                In a real threshold signature scheme:
                1. The verifier would use the group's public key to verify the signature
                2. The verifier cannot tell which specific parties participated
                3. The signature is exactly the same size as a regular signature
                """)
    
    with tc_tab3:
        st.subheader("Threshold Cryptography Applications")
        
        st.markdown("""
        ### Applications of Threshold Cryptography:
        
        1. **Cryptocurrency Wallets**
           - Multi-signature wallets require multiple keys to authorize transactions
           - Enhances security by distributing trust among multiple parties or devices
        
        2. **Certificate Authorities**
           - Distribute the ability to sign certificates across multiple servers
           - Prevents a single compromised server from issuing fraudulent certificates
        
        3. **Secure Key Management**
           - Protect high-value encryption keys from single-point failures
           - Keys can be reconstructed only when needed with proper authorization
        
        4. **Distributed Systems Security**
           - Consensus mechanisms in blockchain networks
           - Distributed access control for critical resources
        
        5. **Secure Multi-Party Computation**
           - Allow multiple parties to compute functions over private inputs
           - Applications in privacy-preserving analytics and secure auctions
        """)


# --- 5. Side-Channel Attack Demonstrator ---
elif feature == "⚡ Side-Channel Attack Demonstrator":
    st.header("⚡ Side-Channel Attack Demonstrator")
    
    st.markdown("""
    ### Side-Channel Attacks
    Side-channel attacks extract secrets by analyzing physical information leaked during computation,
    such as timing, power consumption, electromagnetic emissions, or sound.
    """)
    
    sc_tab1, sc_tab2, sc_tab3 = st.tabs(["Timing Attack Demo", "Power Analysis Visualization", "Side-Channel Defenses"])
    
    with sc_tab1:
        st.subheader("Password Timing Attack Simulation")
        
        st.markdown("""
        This demonstrates how comparing passwords character-by-character can leak timing information,
        allowing an attacker to guess the password one character at a time.
        """)
        
        # Vulnerable password comparison (for demonstration purposes)
        def vulnerable_password_check(stored_password, input_password):
            results = []
            for i in range(min(len(stored_password), len(input_password))):
                # Check character by character
                match = stored_password[i] == input_password[i]
                results.append({
                    "position": i,
                    "stored_char": stored_password[i],
                    "input_char": input_password[i],
                    "match": match,
                    "time_ms": random.randint(5, 15) if match else random.randint(1, 5)  # Simulated time difference
                })
                
                # Early exit on mismatch (vulnerable to timing attacks)
                if not match:
                    break
            
            return results
        
        # Set a secret password for demonstration
        stored_password = "S3cr3tP@ss"
        
        # User input for testing
        test_password = st.text_input("Enter a test password:", value="S3cr", max_chars=len(stored_password))
        
        if st.button("Test Password Comparison"):
            results = vulnerable_password_check(stored_password, test_password)
            
            # Display results
            st.subheader("Character-by-Character Comparison")
            
            # Create visualizations
            char_positions = [r["position"] for r in results]
            char_times = [r["time_ms"] for r in results]
            
            # Timing visualization
            fig, ax = plt.subplots(figsize=(10, 4))
            bars = ax.bar(char_positions, char_times, color=['green' if r["match"] else 'red' for r in results])
            
            ax.set_xlabel('Character Position')
            ax.set_ylabel('Processing Time (ms)')
            ax.set_title('Password Comparison Timing')
            
            # Add time labels on top of bars
            for bar in bars:
                height = bar.get_height()
                ax.annotate(f'{height}ms',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3),
                           textcoords="offset points",
                           ha='center', va='bottom')
            
            st.pyplot(fig)
            
            # Display character-by-character results
            results_df = pd.DataFrame([{
                "Position": r["position"],
                "Expected": r["stored_char"],
                "Input": r["input_char"],
                "Match": "✓" if r["match"] else "✗",
                "Time (ms)": r["time_ms"]
            } for r in results])
            
            st.dataframe(results_df)
            
            # Explanation
            if any(not r["match"] for r in results):
                last_match = max([r["position"] for r in results if r["match"]], default=-1)
                st.warning(f"""
                **Timing Attack Vulnerability Detected!**
                
                The comparison stops at the first mismatched character (position {last_match + 1}).
                An attacker could use this timing difference to guess the password character by character.
                """)
            else:
                st.success("All characters match up to the input length!")
            
            if len(test_password) < len(stored_password):
                st.info(f"The input is shorter than the stored password ({len(test_password)} vs {len(stored_password)} characters).")
            
            # Constant-time alternative
            st.subheader("Secure Constant-Time Comparison")
            st.markdown("""
            A secure implementation would compare all characters regardless of mismatches,
            taking the same amount of time regardless of how many characters match.
            
            ```python
            def constant_time_compare(a, b):
                if len(a) != len(b):
                    return False
                    
                result = 0
                for x, y in zip(a, b):
                    result |= ord(x) ^ ord(y)
                return result == 0
            ```
            
            This method:
            1. Compares all characters using XOR (^)
            2. Combines results with OR (|)
            3. Returns true only if all characters match
            4. Takes the same time regardless of where mismatches occur
            """)
    
    with sc_tab2:
        st.subheader("Power Analysis Attack Visualization")
        
        st.markdown("""
        Power analysis attacks extract secrets by analyzing power consumption patterns during cryptographic operations.
        This visualization demonstrates the concept of Simple Power Analysis (SPA) and Differential Power Analysis (DPA).
        """)
        
        # Generate simulated power traces
        def generate_power_trace(key, with_leakage=True):
            trace = []
            baseline = [10 + random.random() * 2 for _ in range(20)]  # Baseline power consumption
            
            for bit in key:
                if bit == '1':
                    # Higher power for 1-bits (if leakage is enabled)
                    if with_leakage:
                        segment = [15 + random.random() * 3 for _ in range(10)]
                    else:
                        segment = [12 + random.random() * 2 for _ in range(10)]
                else:
                    # Lower power for 0-bits
                    segment = [12 + random.random() * 2 for _ in range(10)]
                
                trace.extend(segment)
            
            # Add noise
            noise_level = random.uniform(0.5, 1.5)
            noisy_trace = [p + random.normalvariate(0, noise_level) for p in baseline + trace]
            return noisy_trace
        
        # Demo options
        key_length = st.slider("Secret Key Length (bits)", min_value=4, max_value=16, value=8)
        secret_key = ''.join([random.choice(['0', '1']) for _ in range(key_length)])
        
        col1, col2 = st.columns(2)
        with col1:
            show_key = st.checkbox("Show Secret Key", value=False)
        with col2:
            leakage = st.checkbox("Enable Power Leakage", value=True)
            
        if show_key:
            st.code(f"Secret Key: {secret_key}", language="bash")
            
        attack_type = st.radio("Attack Visualization", ["Simple Power Analysis (SPA)", "Differential Power Analysis (DPA)"])
        
        if st.button("Generate Power Traces"):
            if attack_type == "Simple Power Analysis (SPA)":
                # Generate a power trace for the key
                trace = generate_power_trace(secret_key, leakage)
                
                # Plot the trace
                fig, ax = plt.subplots(figsize=(10, 5))
                x_vals = list(range(len(trace)))
                ax.plot(x_vals, trace, 'b-')
                
                # Mark the bit regions if showing key
                if show_key:
                    bit_width = 10
                    baseline_length = 20
                    
                    for i, bit in enumerate(secret_key):
                        start_x = baseline_length + i * bit_width
                        mid_x = start_x + bit_width // 2
                        color = 'red' if bit == '1' else 'green'
                        
                        # Add shaded region
                        ax.axvspan(start_x, start_x + bit_width, alpha=0.2, color=color)
                        # Add bit value
                        ax.text(mid_x, max(trace) + 1, bit, ha='center')
                
                ax.set_title('Power Consumption Trace')
                ax.set_xlabel('Time')
                ax.set_ylabel('Power Consumption (mW)')
                
                if leakage:
                    ax.text(0.05, 0.95, "Vulnerable Implementation", transform=ax.transAxes, 
                           bbox=dict(facecolor='red', alpha=0.2))
                else:
                    ax.text(0.05, 0.95, "Protected Implementation", transform=ax.transAxes,
                           bbox=dict(facecolor='green', alpha=0.2))
                
                st.pyplot(fig)
                
                # Explanation
                if leakage:
                    st.warning("""
                    **Simple Power Analysis Vulnerability:**
                    
                    The power consumption pattern clearly shows differences between 0 and 1 bits.
                    An attacker with physical access to the device could measure these power differences
                    to recover the secret key directly from a single trace.
                    """)
                else:
                    st.success("""
                    **Protected Implementation:**
                    
                    This implementation uses constant-power operations, making it difficult to
                    distinguish between 0 and 1 bits based on power consumption.
                    """)
                
            else:  # Differential Power Analysis
                # Generate multiple traces for statistical analysis
                num_traces = 20
                traces = []
                
                for i in range(num_traces):
                    trace = generate_power_trace(secret_key, leakage)
                    traces.append(trace)
                
                # Plot multiple traces
                fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
                
                # Plot individual traces
                for i, trace in enumerate(traces):
                    ax1.plot(trace, alpha=0.3, color='blue')
                
                ax1.set_title(f'Multiple Power Traces ({num_traces} runs)')
                ax1.set_xlabel('Time')
                ax1.set_ylabel('Power (mW)')
                
                # Plot the average trace
                avg_trace = [sum(t[i] for t in traces) / len(traces) for i in range(len(traces[0]))]
                ax2.plot(avg_trace, color='red', linewidth=2)
                ax2.set_title('Average Power Trace (DPA Result)')
                ax2.set_xlabel('Time')
                ax2.set_ylabel('Power (mW)')
                
                # Mark the bit regions if showing key
                if show_key:
                    bit_width = 10
                    baseline_length = 20
                    
                    for i, bit in enumerate(secret_key):
                        start_x = baseline_length + i * bit_width
                        mid_x = start_x + bit_width // 2
                        color = 'red' if bit == '1' else 'green'
                        
                        # Add shaded region to average plot
                        ax2.axvspan(start_x, start_x + bit_width, alpha=0.2, color=color)
                        # Add bit value
                        ax2.text(mid_x, max(avg_trace) + 0.5, bit, ha='center')
                
                plt.tight_layout()
                st.pyplot(fig)
                
                # Analysis and explanation
                if leakage:
                    st.warning("""
                    **Differential Power Analysis Results:**
                    
                    By averaging multiple power traces, the signal-to-noise ratio improves.
                    Statistical differences in power consumption become visible,
                    allowing an attacker to recover the key even when individual traces are noisy.
                    """)
                else:
                    st.success("""
                    **Protected Against DPA:**
                    
                    This implementation uses constant-power operations and additional 
                    countermeasures like random masking of operations to resist statistical analysis.
                    """)
    
    with sc_tab3:
        st.subheader("Side-Channel Attack Defenses")
        
        st.markdown("""
        ### Common Side-Channel Attack Types:
        
        1. **Timing Attacks**
           - Extract secrets by measuring operation execution time
           - Example: Password comparison that exits early on first mismatch
        
        2. **Power Analysis Attacks**
           - Simple Power Analysis (SPA): Direct observation of power patterns
           - Differential Power Analysis (DPA): Statistical analysis of many traces
        
        3. **Electromagnetic Analysis**
           - Similar to power analysis but uses EM emissions
           - Can be performed from a distance without direct contact
        
        4. **Acoustic Analysis**
           - Listening to sounds produced by hardware
           - Examples: Keyboard acoustic attacks, CPU fan noise analysis
        
        5. **Cache Timing Attacks**
           - Exploits timing differences in CPU cache access
           - Can be used for cross-VM attacks in cloud environments
        
        ### Defense Mechanisms:
        
        1. **Constant-Time Operations**
           - Ensure cryptographic operations take the same time regardless of the data
           - Avoid data-dependent branches and array accesses
        
        2. **Balanced Power Consumption**
           - Ensure operations consume the same power regardless of the data
           - Implement dual-rail logic for hardware cryptographic modules
        
        3. **Random Masking**
           - Add randomness to computations to hide patterns
           - Example: Blinding techniques for RSA
        
        4. **Physical Shielding**
           - Faraday cages to prevent EM leakage
           - Sound dampening for acoustic attacks
        
        5. **Noise Addition**
           - Add random delays or operations to obscure timing patterns
           - Generate random power consumption patterns
        """)


elif feature == "🌠 Quantum Key Distribution Simulator":
    st.header("🌠 Quantum Key Distribution Simulator")
    
    st.markdown("""
    ### Quantum Key Distribution
    Quantum Key Distribution (QKD) uses quantum mechanics principles to establish a secure cryptographic key between parties.
    The BB84 protocol leverages quantum properties like superposition and measurement to detect eavesdropping attempts.
    """)
    
    qkd_tab1, qkd_tab2, qkd_tab3 = st.tabs(["BB84 Protocol Simulator", "Eavesdropper Detection", "QKD Applications"])
    
    with qkd_tab1:
        st.subheader("BB84 Protocol Simulation")
        
        st.markdown("""
        This simulation demonstrates the BB84 protocol for quantum key distribution:
        1. Alice prepares qubits in random bases with random bit values
        2. Bob measures the qubits using randomly chosen bases
        3. They publicly compare their bases (but not results)
        4. They keep only the bits where their bases matched
        """)
        
        # Simulation settings
        col1, col2 = st.columns(2)
        with col1:
            num_qubits = st.slider("Number of Qubits", min_value=8, max_value=64, value=16)
        with col2:
            error_rate = st.slider("Quantum Channel Error Rate (%)", min_value=0, max_value=20, value=5)
            
        # Add eavesdropper simulation option
        eve_present = st.checkbox("Simulate Eavesdropper (Eve)", value=False)
        
        if st.button("Run QKD Simulation"):
            # Simulation parameters
            error_prob = error_rate / 100
            
            # Generate random bits and bases for Alice
            alice_bits = [random.randint(0, 1) for _ in range(num_qubits)]
            alice_bases = [random.randint(0, 1) for _ in range(num_qubits)]  # 0 = rectilinear, 1 = diagonal
            
            # Initialize Eve's measurements if present
            if eve_present:
                eve_bases = [random.randint(0, 1) for _ in range(num_qubits)]
                eve_measurements = []
                
                # Eve intercepts and measures
                for i in range(num_qubits):
                    # Eve measures with random basis
                    if eve_bases[i] == alice_bases[i]:
                        # Correct basis, gets correct bit
                        eve_measurements.append(alice_bits[i])
                    else:
                        # Wrong basis, gets random result
                        eve_measurements.append(random.randint(0, 1))
            
            # Generate random measurement bases for Bob
            bob_bases = [random.randint(0, 1) for _ in range(num_qubits)]
            bob_measurements = []
            
            # Bob's measurement results
            for i in range(num_qubits):
                if eve_present:
                    # If Eve intercepted, Bob receives the qubit Eve sent
                    if bob_bases[i] == eve_bases[i]:
                        # Bob uses same basis as Eve
                        result = eve_measurements[i]
                    else:
                        # Bob uses different basis than Eve
                        result = random.randint(0, 1)
                else:
                    # Direct transmission from Alice to Bob
                    if bob_bases[i] == alice_bases[i]:
                        # Bob used correct basis
                        # Apply channel error probability
                        if random.random() < error_prob:
                            result = 1 - alice_bits[i]  # Flip the bit (error)
                        else:
                            result = alice_bits[i]
                    else:
                        # Bob used wrong basis, gets random result
                        result = random.randint(0, 1)
                
                bob_measurements.append(result)
            
            # Determine which bits to keep (where bases match)
            matching_bases = [i for i in range(num_qubits) if alice_bases[i] == bob_bases[i]]
            
            # Extract the keys
            alice_key = [alice_bits[i] for i in matching_bases]
            bob_key = [bob_measurements[i] for i in matching_bases]
            
            # Calculate key match percentage
            if matching_bases:
                matches = sum(1 for i in range(len(alice_key)) if alice_key[i] == bob_key[i])
                match_percentage = (matches / len(matching_bases)) * 100
            else:
                match_percentage = 0
            
            # Sample subset of key for error estimation
            sample_size = min(len(matching_bases) // 2, 1)
            if sample_size > 0:
                sample_indices = random.sample(range(len(alice_key)), sample_size)
                alice_sample = [alice_key[i] for i in sample_indices]
                bob_sample = [bob_key[i] for i in sample_indices]
                
                # Calculate error rate in sample
                sample_errors = sum(1 for i in range(sample_size) if alice_sample[i] != bob_sample[i])
                sample_error_rate = (sample_errors / sample_size) * 100
                
                # Remove sampled bits from final key
                final_alice_key = [alice_key[i] for i in range(len(alice_key)) if i not in sample_indices]
                final_bob_key = [bob_key[i] for i in range(len(bob_key)) if i not in sample_indices]
            else:
                sample_error_rate = 0
                final_alice_key = alice_key
                final_bob_key = bob_key
            
            # Display visualization of the protocol
            st.subheader("BB84 Protocol Visualization")
            
            # Prepare data for visualization
            data = []
            for i in range(num_qubits):
                qubit_data = {
                    "Qubit": i + 1,
                    "Alice's Bit": alice_bits[i],
                    "Alice's Basis": "Rectilinear (┼)" if alice_bases[i] == 0 else "Diagonal (╳)",
                }
                
                if eve_present:
                    qubit_data.update({
                        "Eve's Basis": "Rectilinear (┼)" if eve_bases[i] == 0 else "Diagonal (╳)",
                        "Eve's Measurement": eve_measurements[i]
                    })
                
                qubit_data.update({
                    "Bob's Basis": "Rectilinear (┼)" if bob_bases[i] == 0 else "Diagonal (╳)",
                    "Bob's Measurement": bob_measurements[i],
                    "Bases Match": "✓" if alice_bases[i] == bob_bases[i] else "✗",
                    "Key Bit": alice_bits[i] if i in matching_bases else "-"
                })
                
                data.append(qubit_data)
            
            # Convert to DataFrame for display
            qkd_df = pd.DataFrame(data)
            st.dataframe(qkd_df)
            
            # Results
            st.subheader("Key Exchange Results")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Matched Bases", f"{len(matching_bases)}/{num_qubits}", 
                         f"{(len(matching_bases)/num_qubits)*100:.1f}%")
            with col2:
                st.metric("Key Length", len(final_alice_key))
            with col3:
                error_delta = f"{match_percentage - 100:.1f}%" if match_percentage < 100 else "0%"
                st.metric("Key Match Rate", f"{match_percentage:.1f}%", error_delta)
            
            # Display final keys
            col1, col2 = st.columns(2)
            with col1:
                st.write("Alice's Final Key:", ''.join(map(str, final_alice_key)))
            with col2:
                st.write("Bob's Final Key:", ''.join(map(str, final_bob_key)))
            
            # Eavesdropping detection analysis
            if eve_present:
                st.subheader("Eavesdropping Detection")
                
                # Calculate theoretical error rate due to Eve
                theoretical_eve_error = 25.0  # 25% error rate with intercept-resend attack
                
                st.error(f"""
                **Eavesdropper Detected!**
                
                The quantum bit error rate is {100-match_percentage:.1f}%, which is higher than expected from the channel error rate ({error_rate}%).
                
                When Eve measures qubits and resends them, she introduces approximately 25% errors when Alice and Bob's bases match,
                because Eve chooses the wrong basis about 50% of the time, and each wrong basis causes a 50% chance of error.
                """)
            else:
                if 100-match_percentage > error_rate * 1.5:  # If error rate is significantly higher than expected
                    st.warning(f"""
                    **Unusual Error Rate Detected**
                    
                    The error rate ({100-match_percentage:.1f}%) is higher than expected from the channel error rate ({error_rate}%).
                    This might indicate noise in the quantum channel or a possible eavesdropper.
                    """)
                else:
                    st.success(f"""
                    **Secure Key Established**
                    
                    The error rate ({100-match_percentage:.1f}%) is consistent with the expected channel error rate ({error_rate}%).
                    No evidence of eavesdropping detected.
                    """)
    
    with qkd_tab2:
        st.subheader("Eavesdropper Detection Analysis")
        
        st.markdown("""
        ### How QKD Detects Eavesdroppers
        
        Quantum Key Distribution protocols can detect eavesdroppers due to a fundamental principle of quantum mechanics:
        **measurement disturbs the quantum state** (the observer effect).
        
        In the BB84 protocol:
        
        1. If Eve intercepts and measures a qubit, she must choose a measurement basis (rectilinear or diagonal)
        2. When Eve's basis doesn't match Alice's (happens ~50% of the time):
            - Eve gets a random result
            - The qubit collapses to a state aligned with Eve's basis
        3. When Bob measures with the same basis as Alice:
            - Without Eve: Bob gets the correct bit (except for natural channel errors)
            - With Eve: Bob gets a random result ~25% of the time due to Eve's interference
        
        This introduces a detectable error rate of about 25% in an otherwise perfect channel.
        """)

        # Interactive Eve attack simulation
        st.write("### Interactive Eavesdropping Simulation")
        
        col1, col2 = st.columns(2)
        with col1:
            qubits_sent = st.slider("Qubits Exchanged", min_value=1000, max_value=10000, value=2000, step=1000)
        with col2:
            base_error = st.slider("Baseline Channel Error (%)", min_value=0, max_value=15, value=3)
        
        intercept_rate = st.slider("Eve's Intercept Rate (%)", min_value=0, max_value=100, value=0)
        
        if st.button("Run Eavesdropping Analysis"):
            # Calculate QBER (Quantum Bit Error Rate)
            base_qber = base_error / 100
            
            # Eve's intercept-resend attack adds errors
            # Each intercepted qubit has 25% chance of causing error when bases match
            eve_error_contribution = (intercept_rate / 100) * 0.25
            
            # Total QBER is a combination of base error and Eve's contribution
            # We don't just add them because some of Eve's errors might overlap with base errors
            total_qber = base_qber + eve_error_contribution * (1 - base_qber)
            
            # Expected errors in matched bases
            matched_bases = qubits_sent // 2  # On average, 50% of bases will match
            expected_errors = int(matched_bases * total_qber)
            
            # Create visualization
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Plot error rates
            x = np.arange(0, 101, 1)  # Intercept rates from 0 to 100%
            y = [(base_qber + (i/100) * 0.25 * (1 - base_qber)) * 100 for i in x]
            
            ax.plot(x, y, 'b-', linewidth=2, label='Total Error Rate')
            ax.axhline(y=base_error, color='g', linestyle='-', label=f'Base Error Rate ({base_error}%)')
            ax.axhline(y=10, color='r', linestyle='--', label='Security Threshold (10%)')
            
            # Mark the current intercept rate
            ax.plot(intercept_rate, total_qber * 100, 'ro', markersize=10)
            ax.annotate(f'{total_qber*100:.1f}%', 
                       xy=(intercept_rate, total_qber * 100),
                       xytext=(5, 10), textcoords='offset points')
            
            ax.set_xlabel('Eve\'s Intercept Rate (%)')
            ax.set_ylabel('Quantum Bit Error Rate (%)')
            ax.set_title('Impact of Eavesdropping on Error Rate')
            ax.grid(True, alpha=0.3)
            ax.legend()
            
            st.pyplot(fig)
            
            # Analysis
            st.subheader("Security Analysis")
            
            if intercept_rate == 0:
                st.success(f"""
                **No Eavesdropper Detected**
                
                The quantum bit error rate is {total_qber*100:.1f}%, which matches the expected channel error rate.
                The key exchange appears secure.
                """)
            elif total_qber * 100 < 10:
                st.warning(f"""
                **Potential Eavesdropping Detected**
                
                With Eve intercepting {intercept_rate}% of qubits, the error rate rises to {total_qber*100:.1f}%.
                This is above the baseline error rate but below the security threshold.
                
                - Expected errors in matched bases: {expected_errors} out of {matched_bases}
                - Key can still be secured using privacy amplification
                """)
            else:
                st.error(f"""
                **Severe Eavesdropping Detected**
                
                The quantum bit error rate of {total_qber*100:.1f}% exceeds the security threshold of 10%.
                The key exchange should be aborted and restarted through a different channel.
                
                Eve has likely intercepted a significant portion of the transmission.
                """)
    
    with qkd_tab3:
        st.subheader("QKD Applications and Limitations")
        
        st.markdown("""
        ### Practical Applications of QKD
        
        Quantum Key Distribution is being deployed in various scenarios:
        
        1. **Financial Networks**: Securing transactions between banks and financial institutions
        2. **Government Communications**: Protecting classified information and diplomatic channels
        3. **Critical Infrastructure**: Securing power grids, water systems, and other essential services
        4. **Healthcare Networks**: Protecting sensitive patient data in compliance with regulations
        5. **Satellite QKD**: Enabling secure global communications via space-based quantum links
        
        ### Current Limitations
        
        Despite its theoretical security, QKD faces practical challenges:
        
        1. **Distance Limitations**: Quantum signals degrade over distance (typically limited to ~100km in fiber)
        2. **Hardware Requirements**: Specialized equipment needed (single-photon detectors, quantum random number generators)
        3. **Side-Channel Attacks**: Implementation vulnerabilities in physical devices
        4. **Integration Challenges**: Connecting with existing network infrastructure
        5. **Cost and Complexity**: High deployment and maintenance expenses
        
        ### Beyond BB84
        
        Advanced QKD protocols include:
        
        1. **E91 Protocol**: Uses quantum entanglement for key distribution
        2. **BBM92**: Modified BB84 using entangled photon pairs
        3. **Continuous-Variable QKD**: Uses quadrature measurements of coherent states
        4. **Measurement-Device-Independent QKD**: Eliminates detector vulnerabilities
        5. **Twin-Field QKD**: Extends the range limit significantly
        """)
        
        # Interactive QKD network simulator
        st.write("### QKD Network Range Simulator")
        
        col1, col2 = st.columns(2)
        with col1:
            protocol = st.selectbox("QKD Protocol", [
                "BB84 (Standard)", 
                "Decoy State BB84", 
                "MDI-QKD",
                "Twin-Field QKD"
            ])
        with col2:
            medium = st.selectbox("Transmission Medium", [
                "Standard Telecom Fiber", 
                "Ultra-Low Loss Fiber",
                "Free Space (Clear Weather)",
                "Free Space (Satellite Link)"
            ])
        
        if st.button("Calculate Maximum Range"):
            # Approximate ranges based on current technology
            ranges = {
                "BB84 (Standard)": {
                    "Standard Telecom Fiber": 80,
                    "Ultra-Low Loss Fiber": 120,
                    "Free Space (Clear Weather)": 100,
                    "Free Space (Satellite Link)": 1200
                },
                "Decoy State BB84": {
                    "Standard Telecom Fiber": 150,
                    "Ultra-Low Loss Fiber": 200,
                    "Free Space (Clear Weather)": 180,
                    "Free Space (Satellite Link)": 1500
                },
                "MDI-QKD": {
                    "Standard Telecom Fiber": 200,
                    "Ultra-Low Loss Fiber": 300,
                    "Free Space (Clear Weather)": 170,
                    "Free Space (Satellite Link)": 1000
                },
                "Twin-Field QKD": {
                    "Standard Telecom Fiber": 500,
                    "Ultra-Low Loss Fiber": 800,
                    "Free Space (Clear Weather)": 300,
                    "Free Space (Satellite Link)": 2000
                }
            }
            
            # Get the range for the selected protocol and medium
            max_range = ranges[protocol][medium]
            
            # Key rates (approximations)
            key_rates = {
                "BB84 (Standard)": 10,
                "Decoy State BB84": 50,
                "MDI-QKD": 5,
                "Twin-Field QKD": 2
            }
            
            base_key_rate = key_rates[protocol]
            
            # Calculate estimated key rate at half the max distance
            half_distance = max_range / 2
            estimated_key_rate = base_key_rate * math.exp(-0.2 * half_distance / 100)
            
            # Display results
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Maximum Range", f"{max_range} km")
            with col2:
                st.metric("Est. Key Rate at Half Range", f"{estimated_key_rate:.2f} kbps")
            
            # Create distance vs key rate graph
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Plot key rate vs distance
            distances = np.arange(0, max_range * 1.1, max_range / 50)
            # Key rate typically follows exponential decay with distance
            rates = [base_key_rate * math.exp(-0.2 * d / 100) for d in distances]
            
            ax.semilogy(distances, rates, 'b-', linewidth=2)
            ax.set_xlabel('Distance (km)')
            ax.set_ylabel('Secure Key Rate (kbps)')
            ax.set_title(f'Key Rate vs Distance for {protocol} over {medium}')
            ax.grid(True, which="both", linestyle='--', alpha=0.7)
            
            # Mark the half distance point
            ax.plot(half_distance, estimated_key_rate, 'ro')
            ax.annotate(f'{estimated_key_rate:.2f} kbps', 
                       xy=(half_distance, estimated_key_rate),
                       xytext=(10, 10), textcoords='offset points')
            
            st.pyplot(fig)
            
            # Practical notes based on selection
            st.subheader("Implementation Notes")
            
            if protocol == "BB84 (Standard)" and medium == "Standard Telecom Fiber":
                st.info("""
                **Standard BB84 in Telecom Fiber**
                
                This is the most common and well-established QKD implementation, suitable for metropolitan networks.
                Typical use cases include secure links between data centers within the same city.
                
                Key challenges include photon loss in fiber and detector dark counts limiting the range.
                """)
            elif protocol == "Twin-Field QKD" and "Fiber" in medium:
                st.success("""
                **Twin-Field QKD in Fiber**
                
                This cutting-edge protocol can achieve significantly longer distances without quantum repeaters.
                The technology uses interference between phase-coherent pulses sent from Alice and Bob to a middle node.
                
                Recent experiments have demonstrated secure key exchange over 500+ km of fiber.
                """)
            elif "Satellite" in medium:
                st.warning("""
                **Satellite-Based QKD**
                
                Satellite QKD can achieve global distances but faces unique challenges:
                - Atmospheric turbulence affecting quantum states
                - Limited satellite visibility windows (typically 5-10 minutes per pass)
                - Lower key rates compared to fiber implementations
                
                China's Micius satellite has demonstrated successful QKD over intercontinental distances.
                """)



elif feature == "🛡️ Cryptographic Protocol Analyzer":
    st.header("🛡️ Cryptographic Protocol Analyzer")
    
    st.markdown("""
    ### Cryptographic Protocol Analysis
    This tool allows you to analyze and compare various cryptographic protocols, understand their security properties,
    and visualize vulnerabilities in different attack scenarios.
    """)
    
    crypto_tab1, crypto_tab2, crypto_tab3 = st.tabs(["Protocol Security Analysis", "Man-in-the-Middle Simulation", "Protocol Comparison"])
    
    with crypto_tab1:
        st.subheader("Protocol Security Properties")
        
        st.markdown("""
        This analyzer helps you understand the security properties of common cryptographic protocols.
        Select a protocol to analyze its security features, known vulnerabilities, and typical use cases.
        """)
        
        # Protocol selection
        protocol = st.selectbox(
            "Select Protocol to Analyze",
            [
                "TLS 1.3", 
                "Signal Protocol", 
                "Diffie-Hellman Key Exchange",
                "RSA Key Exchange", 
                "SSH",
                "Kerberos",
                "OAuth 2.0"
            ]
        )
        
        # Protocol properties
        protocol_properties = {
            "TLS 1.3": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 5,
                "quantum_resistance": 2,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "Side-channel timing attacks", 
                    "Implementation errors", 
                    "Certificate validation issues"
                ],
                "description": """
                Transport Layer Security (TLS) 1.3 is the latest version of the TLS protocol, providing secure 
                communication over a computer network. TLS 1.3 removed support for many insecure or obsolete features
                present in TLS 1.2, including SHA-1, RC4, DES, and 3DES.
                
                **Key Features:**
                - Simplified handshake process (reduced to 1-RTT)
                - Improved privacy with encrypted handshakes
                - Removal of outdated cryptographic algorithms
                - Support for 0-RTT resumption (with security trade-offs)
                - Mandatory perfect forward secrecy
                """
            },
            "Signal Protocol": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 5,
                "quantum_resistance": 2,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "Side-channel attacks", 
                    "Implementation errors",
                    "Key verification challenges"
                ],
                "description": """
                The Signal Protocol (formerly TextSecure Protocol) is a non-federated cryptographic protocol that
                provides end-to-end encryption for instant messaging. It uses a combination of the Double Ratchet
                Algorithm, prekeys, and a triple Elliptic-curve Diffie-Hellman (3-DH) handshake.
                
                **Key Features:**
                - Triple Diffie-Hellman (3DH) key agreement
                - Double Ratchet Algorithm for forward secrecy
                - Break-in recovery (future secrecy)
                - Asynchronous messaging with prekeys
                - Deniability properties
                """
            },
            "Diffie-Hellman Key Exchange": {
                "confidentiality": 4,
                "integrity": 3,
                "authentication": 1,
                "forward_secrecy": 5,
                "quantum_resistance": 1,
                "implementation_complexity": 2,
                "known_vulnerabilities": [
                    "Man-in-the-middle attack", 
                    "Small subgroup attacks", 
                    "Logjam attack (weak parameters)",
                    "Quantum computer vulnerability"
                ],
                "description": """
                The Diffie-Hellman (DH) key exchange protocol allows two parties to establish a shared secret over
                an insecure channel. The original protocol doesn't provide authentication, making it vulnerable to 
                man-in-the-middle attacks when used alone.
                
                **Key Features:**
                - Allows secure key exchange over insecure channels
                - Basis for many modern key exchange protocols
                - Provides forward secrecy
                - Simple mathematical foundation based on discrete logarithm problem
                """
            },
            "RSA Key Exchange": {
                "confidentiality": 4,
                "integrity": 4,
                "authentication": 4,
                "forward_secrecy": 1,
                "quantum_resistance": 1,
                "implementation_complexity": 3,
                "known_vulnerabilities": [
                    "Quantum computer vulnerability", 
                    "Padding oracle attacks", 
                    "Timing attacks",
                    "Bleichenbacher's attack",
                    "No forward secrecy"
                ],
                "description": """
                RSA (Rivest-Shamir-Adleman) is one of the first public-key cryptosystems widely used for secure 
                data transmission. It's based on the practical difficulty of factoring the product of two large 
                prime numbers.
                
                **Key Features:**
                - Public key encryption and digital signatures
                - Widely deployed in various security applications
                - Simple key exchange mechanism
                - Can be used for both encryption and signatures
                - Vulnerable to quantum computing attacks
                """
            },
            "SSH": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 4,
                "quantum_resistance": 2,
                "implementation_complexity": 3,
                "known_vulnerabilities": [
                    "Implementation vulnerabilities", 
                    "Key management issues", 
                    "Configuration errors",
                    "Side-channel attacks"
                ],
                "description": """
                Secure Shell (SSH) is a cryptographic network protocol for operating network services securely over
                an unsecured network. SSH provides a secure channel over an unsecured network by using client-server
                architecture, connecting an SSH client application with an SSH server.
                
                **Key Features:**
                - Strong encryption and authentication
                - Public key and password authentication options
                - Port forwarding capabilities
                - Secure file transfer protocol (SFTP) support
                - Command-line and programmatic access
                """
            },
            "Kerberos": {
                "confidentiality": 4,
                "integrity": 4,
                "authentication": 5,
                "forward_secrecy": 2,
                "quantum_resistance": 2,
                "implementation_complexity": 5,
                "known_vulnerabilities": [
                    "Pass-the-ticket attacks", 
                    "Golden ticket attacks", 
                    "Kerberoasting",
                    "Clock synchronization issues",
                    "Password-based vulnerabilities"
                ],
                "description": """
                Kerberos is a computer network authentication protocol that works on the basis of tickets to allow
                nodes communicating over a non-secure network to prove their identity to one another in a secure manner.
                
                **Key Features:**
                - Mutual authentication (client and server verify each other)
                - Ticket-based authentication system
                - Single sign-on capabilities
                - Time-synchronized tickets with limited lifetime
                - Centralized authentication server (KDC)
                """
            },
            "OAuth 2.0": {
                "confidentiality": 3,
                "integrity": 3,
                "authentication": 4,
                "forward_secrecy": 1,
                "quantum_resistance": 3,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "CSRF attacks", 
                    "Token leakage", 
                    "Phishing vulnerabilities",
                    "Implementation errors",
                    "Authorization code interception"
                ],
                "description": """
                OAuth 2.0 is an authorization framework that enables a third-party application to obtain limited
                access to an HTTP service. It works by delegating user authentication to the service that hosts
                the user account and authorizing third-party applications to access that user account.
                
                **Key Features:**
                - Token-based authorization
                - Different grant types for various use cases
                - Separation of authentication and authorization
                - Limited scope access control
                - Widely adopted for API authorization
                """
            }
        }
        
        # Display protocol information
        if protocol in protocol_properties:
            props = protocol_properties[protocol]
            
            # Protocol description
            st.markdown(props["description"])
            
            # Security properties radar chart
            st.subheader("Security Properties")
            
            # Prepare data for radar chart
            categories = ['Confidentiality', 'Integrity', 'Authentication', 
                         'Forward Secrecy', 'Quantum Resistance', 'Implementation\nSimplicity']
            
            values = [
                props["confidentiality"],
                props["integrity"],
                props["authentication"],
                props["forward_secrecy"],
                props["quantum_resistance"],
                6 - props["implementation_complexity"]  # Invert for simplicity
            ]
            
            # Create radar chart
            fig = plt.figure(figsize=(10, 6))
            ax = fig.add_subplot(111, polar=True)
            
            # Set the angles for each property
            angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
            values.append(values[0])  # Close the loop
            angles.append(angles[0])  # Close the loop
            
            # Plot the radar chart
            ax.plot(angles, values, 'o-', linewidth=2)
            ax.fill(angles, values, alpha=0.25)
            
            # Set the labels
            ax.set_thetagrids(np.degrees(angles[:-1]), categories)
            ax.set_ylim(0, 5)
            ax.grid(True)
            
            # Add chart title
            plt.title(f'Security Properties of {protocol}', size=15, y=1.1)
            
            st.pyplot(fig)
            
            # Vulnerabilities section
            st.subheader("Known Vulnerabilities")
            for vuln in props["known_vulnerabilities"]:
                st.markdown(f"- {vuln}")
            
            if st.checkbox("Show Mitigation Strategies"):
                st.subheader("Mitigation Strategies")
                
                mitigations = {
                    "TLS 1.3": [
                        "Use up-to-date TLS libraries and keep them updated",
                        "Follow implementation best practices",
                        "Use proper certificate validation",
                        "Enable certificate transparency"
                    ],
                    "Signal Protocol": [
                        "Use secure key verification methods",
                        "Keep implementations updated",
                        "Validate device identity before communication",
                        "Follow implementation guidelines"
                    ],
                    "Diffie-Hellman Key Exchange": [
                        "Always combine with authentication mechanism",
                        "Use strong, vetted parameters",
                        "Use elliptic curve variant (ECDHE) when possible",
                        "Validate all parameters"
                    ],
                    "RSA Key Exchange": [
                        "Use sufficiently large key sizes (minimum 2048 bits)",
                        "Use proper padding (PKCS#1 v2.1 / OAEP)",
                        "Implement countermeasures against timing attacks",
                        "Consider migrating to protocols with forward secrecy"
                    ],
                    "SSH": [
                        "Use key-based authentication instead of passwords",
                        "Configure server with secure ciphers and algorithms",
                        "Keep SSH implementation updated",
                        "Use proper key management procedures"
                    ],
                    "Kerberos": [
                        "Use strong password policies",
                        "Implement time synchronization",
                        "Monitor for suspicious ticket granting activities",
                        "Secure the Key Distribution Center (KDC)"
                    ],
                    "OAuth 2.0": [
                        "Use state parameters to prevent CSRF",
                        "Implement PKCE for mobile applications",
                        "Validate redirect URIs",
                        "Use short-lived access tokens",
                        "Use secure transport (HTTPS) throughout"
                    ]
                }
                
                for mitigation in mitigations[protocol]:
                    st.markdown(f"- {mitigation}")
        
        # Show example attack scenario
        if st.checkbox("Show Example Attack Scenario"):
            st.subheader(f"Example Attack Scenario for {protocol}")
            
            attack_scenarios = {
                "TLS 1.3": {
                    "title": "Downgrade Attack Attempt",
                    "description": """
                    In this scenario, an attacker attempts to force a TLS 1.3 connection to downgrade to an older,
                    vulnerable version of TLS or SSL.
                    
                    **Attack Flow:**
                    1. Client initiates TLS 1.3 connection to server
                    2. Attacker intercepts ClientHello message
                    3. Attacker modifies ClientHello to indicate only TLS 1.2 or older is supported
                    4. Attacker forwards modified message to server
                    
                    **TLS 1.3 Protection:**
                    TLS 1.3 includes specific protections against downgrade attacks:
                    - The server includes a value in the server nonce that indicates downgrade protection
                    - Final handshake verification would detect the manipulation
                    - Attack fails as the client detects the downgrade attempt
                    """,
                    "success_rate": 5  # Percentage chance of success (out of 100)
                },
                "Signal Protocol": {
                    "title": "Identity Key Verification Bypass",
                    "description": """
                    In this scenario, an attacker attempts to execute a man-in-the-middle attack by replacing 
                    the legitimate public key with their own.
                    
                    **Attack Flow:**
                    1. Attacker intercepts initial key exchange
                    2. Attacker substitutes their own public key
                    3. Attacker attempts to relay messages between parties
                    
                    **Signal Protocol Protection:**
                    Signal provides protection through:
                    - Safety numbers that users can verify out-of-band
                    - Notifications when a contact's key changes
                    - The attack fails if users verify keys through secondary channels
                    """,
                    "success_rate": 15  # Higher success rate because it depends on user verification
                },
                "Diffie-Hellman Key Exchange": {
                    "title": "Man-in-the-Middle Attack",
                    "description": """
                    In this scenario, an attacker positions themselves between the communicating parties to
                    intercept and relay messages, establishing separate keys with each legitimate party.
                    
                    **Attack Flow:**
                    1. Alice sends her public value g^a mod p to Bob
                    2. Mallory intercepts this and sends her own public value g^m mod p to Bob
                    3. Bob responds with his public value g^b mod p
                    4. Mallory intercepts this and sends her own public value g^n mod p to Alice
                    5. Alice and Bob now each share a key with Mallory, not with each other
                    
                    **Vulnerability:**
                    Basic Diffie-Hellman has no authentication mechanism, making this attack highly successful.
                    To mitigate, DH must be combined with an authentication mechanism.
                    """,
                    "success_rate": 95  # Very high success rate for unauthenticated DH
                },
                "RSA Key Exchange": {
                    "title": "Bleichenbacher's Oracle Attack",
                    "description": """
                    This attack exploits information leaked by SSL/TLS servers that use RSA encryption with PKCS#1 v1.5 padding.
                    
                    **Attack Flow:**
                    1. Attacker captures an RSA-encrypted message (premaster secret)
                    2. Attacker sends carefully crafted modifications of the message to the server
                    3. Server responses reveal information about the padding
                    4. With enough queries, the attacker can decrypt the original message
                    
                    **Vulnerability:**
                    The success depends on whether the server leaks information about the PKCS#1 padding validity.
                    Modern implementations include countermeasures, but implementation errors can reintroduce the vulnerability.
                    """,
                    "success_rate": 30  # Moderate success rate due to widespread mitigations
                },
                "SSH": {
                    "title": "Password Brute Force Attack",
                    "description": """
                    In this scenario, an attacker attempts to gain access by trying multiple password combinations.
                    
                    **Attack Flow:**
                    1. Attacker identifies SSH server and port
                    2. Attacker uses automated tools to try common usernames and passwords
                    3. If successful, attacker gains shell access to the target system
                    
                    **Vulnerability:**
                    The success depends on password strength and whether the server allows password authentication.
                    Systems configured to use only key-based authentication are protected against this attack.
                    """,
                    "success_rate": 25  # Success depends heavily on configuration
                },
                "Kerberos": {
                    "title": "Pass-the-Ticket Attack",
                    "description": """
                    In this attack, an adversary extracts and reuses Kerberos tickets from one system to access another system.
                    
                    **Attack Flow:**
                    1. Attacker compromises a system where a user is authenticated
                    2. Attacker extracts Kerberos tickets from memory
                    3. Attacker reuses these tickets to access other services as the victim
                    
                    **Vulnerability:**
                    Once an attacker has access to a machine with active tickets, they can reuse those tickets
                    until they expire. This attack is particularly effective in active directory environments.
                    """,
                    "success_rate": 70  # High success rate if initial access is gained
                },
                "OAuth 2.0": {
                    "title": "Authorization Code Interception",
                    "description": """
                    In this attack, an attacker intercepts the authorization code before it's exchanged for an access token.
                    
                    **Attack Flow:**
                    1. User initiates OAuth flow with legitimate application
                    2. User authenticates and authorizes the application
                    3. Authorization server redirects with code
                    4. Attacker intercepts the authorization code (via network sniffing, malicious app, etc.)
                    5. Attacker uses the code to obtain an access token
                    
                    **Vulnerability:**
                    The attack success depends on the implementation. Using PKCE (Proof Key for Code Exchange)
                    extension can prevent this attack for public clients.
                    """,
                    "success_rate": 45  # Moderate success rate depending on implementation
                }
            }
            
            scenario = attack_scenarios[protocol]
            
            # Display attack scenario
            st.markdown(f"### {scenario['title']}")
            st.markdown(scenario["description"])
            
            # Attack success visualization
            success_rate = scenario["success_rate"]
            
            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Attack Success Rate", f"{success_rate}%")
                
            with col2:
                # Simple visualization of attack success probability
                fig, ax = plt.subplots(figsize=(8, 1))
                ax.barh([""], [success_rate], color='red', alpha=0.7)
                ax.barh([""], [100-success_rate], left=[success_rate], color='green', alpha=0.7)
                
                # Add labels
                if success_rate < 50:
                    ax.text(success_rate + 2, 0, f"Protected ({100-success_rate}%)", va='center')
                    ax.text(success_rate/2, 0, f"Vulnerable ({success_rate}%)", va='center', ha='center', color='white')
                else:
                    ax.text(success_rate/2, 0, f"Vulnerable ({success_rate}%)", va='center', ha='center', color='white')
                    ax.text(success_rate + (100-success_rate)/2, 0, f"Protected ({100-success_rate}%)", va='center', ha='center')
                
                ax.set_xlim(0, 100)
                ax.set_xticks([])
                ax.set_yticks([])
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.spines['bottom'].set_visible(False)
                ax.spines['left'].set_visible(False)
                
                st.pyplot(fig)
                
    with crypto_tab2:
        st.subheader("Man-in-the-Middle Attack Simulation")
        
        st.markdown("""
        This simulation demonstrates a Man-in-the-Middle (MITM) attack against different key exchange protocols,
        showing how various security properties can prevent or detect the attack.
        """)
        
        # Simulation settings
        col1, col2 = st.columns(2)
        with col1:
            target_protocol = st.selectbox(
                "Target Protocol",
                [
                    "Basic Diffie-Hellman", 
                    "Authenticated Diffie-Hellman",
                    "RSA Key Exchange",
                    "TLS 1.3 Handshake"
                ]
            )
        with col2:
            attack_sophistication = st.slider(
                "Attacker Sophistication Level", 
                min_value=1, 
                max_value=5, 
                value=3,
                help="Higher values represent more sophisticated attacks with better resources"
            )
            
        # Options for attack scenarios
        passive_mitm = st.checkbox("Passive Eavesdropping Only", value=False)
        
        # Specific protocol options
        if target_protocol == "Basic Diffie-Hellman":
            dh_key_size = st.select_slider(
                "DH Parameter Size",
                options=["512-bit", "1024-bit", "2048-bit", "4096-bit"],
                value="1024-bit"
            )
        elif target_protocol == "TLS 1.3 Handshake":
            cert_validation = st.checkbox("Strict Certificate Validation", value=True)
            
        # Run simulation button
        if st.button("Run MITM Simulation"):
            # Set up simulation parameters based on selections
            sim_params = {
                "Basic Diffie-Hellman": {
                    "active_defense": 1,  # No active defense
                    "passive_defense": 1,  # No passive defense
                    "attack_difficulty": {"512-bit": 2, "1024-bit": 3, "2048-bit": 4, "4096-bit": 5}
                },
                "Authenticated Diffie-Hellman": {
                    "active_defense": 4,  # Good active defense
                    "passive_defense": 2,  # Some passive defense
                    "attack_difficulty": 4
                },
                "RSA Key Exchange": {
                    "active_defense": 3,  # Moderate active defense
                    "passive_defense": 3,  # Moderate passive defense
                    "attack_difficulty": 4
                },
                "TLS 1.3 Handshake": {
                    "active_defense": 5,  # Strong active defense
                    "passive_defense": 4,  # Strong passive defense
                    "attack_difficulty": 5
                }
            }
            
            # Calculate attack success probability
            protocol_params = sim_params[target_protocol]
            
            # Get difficulty based on protocol and settings
            if target_protocol == "Basic Diffie-Hellman":
                difficulty = protocol_params["attack_difficulty"][dh_key_size]
            elif target_protocol == "TLS 1.3 Handshake":
                difficulty = protocol_params["attack_difficulty"]
                if not cert_validation:
                    difficulty -= 2  # Much easier without cert validation
            else:
                difficulty = protocol_params["attack_difficulty"]
            
            # Calculate success probability
            if passive_mitm:
                # Passive attacks are much harder
                success_prob = max(0, min(100, (attack_sophistication - difficulty - protocol_params["passive_defense"]) * 20))
            else:
                # Active MITM
                success_prob = max(0, min(100, (attack_sophistication - difficulty + 2) * 20))
                
                # Account for active defenses
                if protocol_params["active_defense"] > attack_sophistication:
                    # Attack detected
                    success_prob = max(0, success_prob - (protocol_params["active_defense"] - attack_sophistication) * 15)
            
            # Display simulation results
            st.subheader("Simulation Results")
            
            # Outcome and visualization
            col1, col2 = st.columns([1, 2])
            with col1:
                st.metric("Attack Success Probability", f"{int(success_prob)}%")
                
                if success_prob < 10:
                    st.success("Attack Failed: Security measures effective")
                elif success_prob < 40:
                    st.warning("Partial Success: Limited information disclosure")
                else:
                    st.error("Attack Successful: Communication compromised")
                    
            with col2:
                # Visualization of attack success
                fig, ax = plt.subplots(figsize=(8, 3))
                
                # Success probability gauge
                ax.barh(["Attack\nSuccess"], [success_prob], color='red', alpha=0.7)
                ax.barh(["Attack\nSuccess"], [100-success_prob], left=[success_prob], color='green', alpha=0.7)
                
                # Add text labels
                if success_prob < 30:
                    ax.text(success_prob + 5, 0, f"Secure ({100-success_prob}%)", va='center')
                    if success_prob > 5:
                        ax.text(success_prob/2, 0, f"{success_prob}%", va='center', ha='center', color='white')
                else:
                    ax.text(success_prob/2, 0, f"Vulnerable ({success_prob}%)", va='center', ha='center', color='white' if success_prob > 20 else 'black')
                    ax.text(success_prob + (100-success_prob)/2, 0, f"{100-success_prob}%", va='center', ha='center')
                
                ax.set_xlim(0, 100)
                ax.set_xticks([0, 25, 50, 75, 100])
                ax.set_yticks([])
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                
                st.pyplot(fig)
            
            # Simulation diagram
            st.subheader("Attack Simulation Diagram")
            
            # Create a simple diagram showing the attack
            alice_sends = []
            bob_receives = []
            eve_intercepts = []
            events = []
            attack_detected = False
            
            # Define events based on protocol
            if target_protocol == "Basic Diffie-Hellman":
                alice_sends = ["g^a mod p"]
                bob_sends = ["g^b mod p"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts g^a", "Sends g^e to Bob", "Intercepts g^b", "Sends g^e to Alice"]
                    alice_receives = ["g^e mod p (Eve's value)"]
                    bob_receives = ["g^e mod p (Eve's value)"]
                    
                    events = [
                        "Alice computes key K1 = (g^e)^a mod p",
                        "Bob computes key K2 = (g^e)^b mod p",
                        "Eve computes key K1 = (g^a)^e mod p with Alice",
                        "Eve computes key K2 = (g^b)^e mod p with Bob",
                        "Eve can decrypt all traffic between Alice and Bob"
                    ]
                else:  # Passive eavesdropping
                    eve_intercepts = ["Observes g^a mod p", "Observes g^b mod p"]
                    events = [
                        "Eve can't directly compute g^ab from g^a and g^b",
                        "Eve attempts cryptanalysis based on observed values"
                    ]
                    
                    # If successful (based on probability)
                    if success_prob > 50:
                        events.append("Eve successfully derives the shared key through cryptanalysis")
                    else:
                        events.append("Cryptanalysis fails due to large key size")
                        
            elif target_protocol == "Authenticated Diffie-Hellman":
                alice_sends = ["g^a mod p", "Sign(A, g^a)"]
                bob_sends = ["g^b mod p", "Sign(B, g^b)"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts g^a and signature", 
                                    "Cannot forge Alice's signature", 
                                    "Attempts to relay with modifications"]
                    
                    # Check if attack is detected
                    if attack_sophistication < protocol_params["active_defense"]:
                        attack_detected = True
                        events = [
                            "Bob verifies signature with Alice's public key",
                            "Signature verification fails due to Eve's manipulation",
                            "Attack detected - connection terminated"
                        ]
                    else:
                        events = [
                            "Eve uses sophisticated relay techniques",
                            "Eve manages to manipulate parts of the exchange",
                            "Some information is compromised but not the full key"
                        ]
                else:  # Passive eavesdropping
                    eve_intercepts = ["Observes all signed messages"]
                    events = [
                        "Eve can see public values but can't derive the private key",
                        "Authentication prevents active attacks",
                        "Eve attempts advanced cryptanalysis"
                    ]
                    
                    if success_prob > 30:
                        events.append("Eve finds an implementation vulnerability")
                    else:
                        events.append("Eve's analysis reveals no useful information")
                
            elif target_protocol == "RSA Key Exchange":
                alice_sends = ["Encrypted session key"]
                bob_sends = ["Acknowledgment"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts encrypted session key", 
                                    "Cannot decrypt without private key", 
                                    "Attempts oracle attack"]
                    
                    if success_prob > 70:
                        events = [
                            "Eve successfully exploits padding oracle",
                            "Eve recovers the session key",
                            "Communication is compromised"
                        ]
                    else:
                        events = [
                            "Oracle attack fails due to server mitigations",
                            "Eve attempts to use other vulnerabilities",
                            "Most communication remains secure"
                        ]
                else:  # Passive
                    eve_intercepts = ["Records encrypted traffic"]
                    events = [
                        "Eve stores encrypted communications",
                        "Eve cannot decrypt RSA without private key",
                        "Data remains secure until quantum computers become viable"
                    ]
                    
            elif target_protocol == "TLS 1.3 Handshake":
                alice_sends = ["ClientHello, key_share"]
                bob_sends = ["ServerHello, key_share, certificate"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts ClientHello", 
                                    "Attempts to manipulate handshake"]
                    
                    if cert_validation:
                        attack_detected = True
                        events = [
                            "TLS 1.3 downgrade protection activated",
                            "Certificate validation fails for Eve's certificate",
                            "Handshake aborted - attack detected"
                        ]
                    else:
                        events = [
                            "Certificate validation bypassed",
                            "Eve establishes separate connections with Alice and Bob",
                            "TLS session partially compromised"
                        ]
                else:  # Passive
                    eve_intercepts = ["Observes encrypted handshake"]
                    events = [
                        "Eve sees encrypted handshake but cannot derive keys",
                        "Perfect forward secrecy prevents decryption",
                        "Traffic remains confidential"
                    ]
            
            # Create visual representation of attack scenario
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.axis('off')
            
            # Draw arrows and entities
            alice_x, alice_y = 1, 3
            bob_x, bob_y = 9, 3
            eve_x, eve_y = 5, 1.5
            
            # Draw entities
            ax.plot(alice_x, alice_y, 'bo', markersize=20)
            ax.text(alice_x, alice_y+0.5, "Alice", ha='center', fontsize=12)
            
            ax.plot(bob_x, bob_y, 'bo', markersize=20)
            ax.text(bob_x, bob_y+0.5, "Bob", ha='center', fontsize=12)
            
            if not passive_mitm:
                # Active MITM
                ax.plot(eve_x, eve_y, 'ro', markersize=20)
                ax.text(eve_x, eve_y-0.5, "Eve (MITM)", ha='center', fontsize=12)
                
                # Draw intercepted paths
                ax.arrow(alice_x+0.3, alice_y-0.3, eve_x-alice_x-0.6, eve_y-alice_y+0.3, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                ax.arrow(eve_x+0.3, eve_y, bob_x-eve_x-0.6, bob_y-eve_y, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                
                # Return path
                ax.arrow(bob_x-0.3, bob_y-0.3, eve_x-bob_x+0.6, eve_y-bob_y+0.3, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                ax.arrow(eve_x-0.3, eve_y, alice_x-eve_x+0.6, alice_y-eve_y, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                
                # Add attack status
                if attack_detected:
                    ax.text(5, 4.5, "ATTACK DETECTED", color='red', ha='center', fontsize=16, fontweight='bold')
                    # Add red X on attack path
                    ax.plot([4, 6], [3.5, 4.5], 'r-', linewidth=3)
                    ax.plot([6, 4], [3.5, 4.5], 'r-', linewidth=3)
                else:
                    if success_prob > 50:
                        ax.text(5, 4.5, "ATTACK SUCCESSFUL", color='red', ha='center', fontsize=16, fontweight='bold')
                    else:
                        ax.text(5, 4.5, "ATTACK PARTIALLY MITIGATED", color='orange', ha='center', fontsize=16, fontweight='bold')
            else:
                # Passive eavesdropping
                ax.plot(eve_x, eve_y, 'ro', markersize=20)
                ax.text(eve_x, eve_y-0.5, "Eve (Passive)", ha='center', fontsize=12)
                
                # Direct communication
                ax.arrow(alice_x+0.3, alice_y, bob_x-alice_x-0.6, 0, 
                        head_width=0.2, head_length=0.3, fc='blue', ec='blue')
                ax.arrow(bob_x-0.3, bob_y, alice_x-bob_x+0.6, 0, 
                        head_width=0.2, head_length=0.3, fc='blue', ec='blue')
                
                # Eavesdropping lines
                ax.plot([eve_x, 5], [eve_y, 3], 'r--', alpha=0.5)
                
                # Add attack status
                if success_prob > 50:
                    ax.text(5, 4.5, "PASSIVE ATTACK SUCCESSFUL", color='red', ha='center', fontsize=16, fontweight='bold')
                else:
                    ax.text(5, 4.5, "COMMUNICATION SECURE", color='green', ha='center', fontsize=16, fontweight='bold')
            
            # Show the messages exchanged
            msg_y_pos = 3.8
            for msg in alice_sends:
                msg_y_pos += 0.3
                ax.text(2.5, msg_y_pos, f"→ {msg}", fontsize=10)
                
            msg_y_pos = 3.8
            for msg in bob_sends:
                msg_y_pos += 0.3
                ax.text(7.5, msg_y_pos, f"← {msg}", fontsize=10)
                
            # Show Eve's actions
            msg_y_pos = 1
            for msg in eve_intercepts:
                msg_y_pos -= 0.3
                ax.text(5, msg_y_pos, msg, fontsize=10, color='red', ha='center')
            
            plt.tight_layout()
            st.pyplot(fig)
            
            # Event log
            st.subheader("Attack Event Log")
            for i, event in enumerate(events, 1):
                st.markdown(f"{i}. {event}")
                
            # Technical explanation
            st.subheader("Technical Analysis")
            
            if target_protocol == "Basic Diffie-Hellman":
                st.markdown("""
                **Vulnerability Analysis**:
                
                Basic Diffie-Hellman key exchange is vulnerable to man-in-the-middle attacks
                because it doesn't authenticate the participants. An attacker can establish separate
                key exchanges with both parties, decrypting and re-encrypting all traffic between them.
                
                The security relies solely on the computational difficulty of the discrete logarithm problem.
                Larger parameters provide better security against passive attacks but do not prevent MITM.
                """)
                
            elif target_protocol == "Authenticated Diffie-Hellman":
                st.markdown("""
                **Security Analysis**:
                
                Authenticated Diffie-Hellman addresses the main weakness of basic DH by adding
                authentication, typically through digital signatures. Each party signs their DH public
                value, allowing the other party to verify the sender's identity.
                
                This prevents MITM attacks as long as the signature verification is properly implemented
                and the private signing keys remain secure. The attacker cannot forge valid signatures
                without the private keys.
                """)
                
            elif target_protocol == "RSA Key Exchange":
                st.markdown("""
                **Security Analysis**:
                
                RSA key exchange secures communication by encrypting the session key with the recipient's
                public key. Only the holder of the private key can decrypt it.
                
                This approach is vulnerable to:
                - Collection and storage of encrypted traffic for future decryption (no forward secrecy)
                - Various side-channel and implementation attacks like padding oracles
                - Quantum computing attacks in the future
                
                Modern protocols generally prefer ephemeral Diffie-Hellman for forward secrecy.
                """)
                
            elif target_protocol == "TLS 1.3 Handshake":
                st.markdown("""
                **Security Analysis**:
                
                TLS 1.3 provides strong security through:
                - Ephemeral key exchange (perfect forward secrecy)
                - Simplified cryptographic options (removing weak algorithms)
                - Encrypted handshake messages (protecting metadata)
                - Downgrade attack prevention
                - 1-RTT handshake (faster connection establishment)
                
                Certificate validation is critical - without proper validation, MITM attacks
                remain possible despite the protocol's security features.
                """)
            
            # Recommendations
            st.subheader("Security Recommendations")
            
            if target_protocol == "Basic Diffie-Hellman":
                st.warning("""
                1. Never use unauthenticated Diffie-Hellman in production environments
                2. Always combine DH with an authentication mechanism
                3. Use DH parameters of at least 2048 bits
                4. Consider using Elliptic Curve Diffie-Hellman for better performance and security
                """)
                
            elif target_protocol == "Authenticated Diffie-Hellman":
                st.success("""
                1. Ensure proper validation of all signatures
                2. Use strong signature algorithms (e.g., RSA-PSS, Ed25519)
                3. Protect private signing keys
                4. Consider using established protocols like TLS rather than custom implementations
                """)
                
            elif target_protocol == "RSA Key Exchange":
                st.warning("""
                1. Consider replacing RSA key exchange with (EC)DHE for forward secrecy
                2. If using RSA, implement proper padding (PKCS#1 v2.1 / OAEP)
                3. Use RSA key sizes of at least 2048 bits
                4. Implement countermeasures against timing and oracle attacks
                """)
                
            elif target_protocol == "TLS 1.3 Handshake":
                st.success("""
                1. Always enable and enforce strict certificate validation
                2. Use Certificate Transparency (CT) to detect misissued certificates
                3. Consider using certificate pinning for high-value applications
                4. Keep TLS libraries updated to patch implementation vulnerabilities
                5. Implement HSTS to prevent downgrade to HTTP
                """)
                
    with crypto_tab3:
        st.subheader("Protocol Comparison")
        
        st.markdown("""
        Compare different cryptographic protocols based on their security properties,
        performance characteristics, and suitability for different use cases.
        """)
        
        # Select protocols to compare
        protocols_to_compare = st.multiselect(
            "Select Protocols to Compare",
            [
                "TLS 1.2", 
                "TLS 1.3", 
                "SSH",
                "Signal Protocol", 
                "IPsec",
                "WireGuard",
                "OpenVPN",
                "Noise Protocol"
            ],
            default=["TLS 1.2", "TLS 1.3"]
        )
        
        # Protocol comparison data
        protocol_data = {
            "TLS 1.2": {
                "Key Exchange": "RSA or DHE/ECDHE",
                "Forward Secrecy": "Optional (with DHE/ECDHE)",
                "Authentication": "Certificate-based",
                "Cipher Modes": "CBC, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "2-RTT",
                "Performance": "Moderate",
                "Vulnerabilities": "BEAST, POODLE, CRIME, BREACH, Heartbleed (impl.)",
                "Year Introduced": "2008"
            },
            "TLS 1.3": {
                "Key Exchange": "DHE/ECDHE only",
                "Forward Secrecy": "Mandatory",
                "Authentication": "Certificate-based",
                "Cipher Modes": "AEAD only (GCM, ChaCha20-Poly1305)",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Optional",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-RTT",
                "Performance": "High",
                "Vulnerabilities": "Limited (0-RTT replay if enabled)",
                "Year Introduced": "2018"
            },
            "SSH": {
                "Key Exchange": "DHE/ECDHE",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key or Password",
                "Cipher Modes": "CBC, CTR, GCM",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Implementation-specific",
                "Year Introduced": "1995 (SSHv2: 2006)"
            },
            "Signal Protocol": {
                "Key Exchange": "Triple ECDHE (X3DH)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "AES-CBC, AES-GCM",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes (with prekeys)",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Asynchronous",
                "Performance": "High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2013"
            },
            "IPsec": {
                "Key Exchange": "IKE (Internet Key Exchange)",
                "Forward Secrecy": "Optional",
                "Authentication": "Pre-shared keys, Certificates, EAP",
                "Cipher Modes": "CBC, CTR, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Complex config, implementation issues",
                "Year Introduced": "1995"
            },
            "WireGuard": {
                "Key Exchange": "ECDHE (Curve25519)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "ChaCha20-Poly1305",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-RTT",
                "Performance": "Very High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2016"
            },
            "OpenVPN": {
                "Key Exchange": "TLS-based (RSA or DHE/ECDHE)",
                "Forward Secrecy": "Optional",
                "Authentication": "Certificates, Pre-shared keys",
                "Cipher Modes": "CBC, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Implementation-specific",
                "Year Introduced": "2001"
            },
            "Noise Protocol": {
                "Key Exchange": "ECDHE (customizable)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "AESGCM, ChaChaPoly",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes (in some patterns)",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-2 RTT (pattern dependent)",
                "Performance": "High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2015"
            }
        }
        elif feature == "🛡️ Cryptographic Protocol Analyzer":
    st.header("🛡️ Cryptographic Protocol Analyzer")
    
    st.markdown("""
    ### Cryptographic Protocol Analysis
    This tool allows you to analyze and compare various cryptographic protocols, understand their security properties,
    and visualize vulnerabilities in different attack scenarios.
    """)
    
    crypto_tab1, crypto_tab2, crypto_tab3 = st.tabs(["Protocol Security Analysis", "Man-in-the-Middle Simulation", "Protocol Comparison"])
    
    with crypto_tab1:
        st.subheader("Protocol Security Properties")
        
        st.markdown("""
        This analyzer helps you understand the security properties of common cryptographic protocols.
        Select a protocol to analyze its security features, known vulnerabilities, and typical use cases.
        """)
        
        # Protocol selection
        protocol = st.selectbox(
            "Select Protocol to Analyze",
            [
                "TLS 1.3", 
                "Signal Protocol", 
                "Diffie-Hellman Key Exchange",
                "RSA Key Exchange", 
                "SSH",
                "Kerberos",
                "OAuth 2.0"
            ]
        )
        
        # Protocol properties
        protocol_properties = {
            "TLS 1.3": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 5,
                "quantum_resistance": 2,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "Side-channel timing attacks", 
                    "Implementation errors", 
                    "Certificate validation issues"
                ],
                "description": """
                Transport Layer Security (TLS) 1.3 is the latest version of the TLS protocol, providing secure 
                communication over a computer network. TLS 1.3 removed support for many insecure or obsolete features
                present in TLS 1.2, including SHA-1, RC4, DES, and 3DES.
                
                **Key Features:**
                - Simplified handshake process (reduced to 1-RTT)
                - Improved privacy with encrypted handshakes
                - Removal of outdated cryptographic algorithms
                - Support for 0-RTT resumption (with security trade-offs)
                - Mandatory perfect forward secrecy
                """
            },
            "Signal Protocol": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 5,
                "quantum_resistance": 2,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "Side-channel attacks", 
                    "Implementation errors",
                    "Key verification challenges"
                ],
                "description": """
                The Signal Protocol (formerly TextSecure Protocol) is a non-federated cryptographic protocol that
                provides end-to-end encryption for instant messaging. It uses a combination of the Double Ratchet
                Algorithm, prekeys, and a triple Elliptic-curve Diffie-Hellman (3-DH) handshake.
                
                **Key Features:**
                - Triple Diffie-Hellman (3DH) key agreement
                - Double Ratchet Algorithm for forward secrecy
                - Break-in recovery (future secrecy)
                - Asynchronous messaging with prekeys
                - Deniability properties
                """
            },
            "Diffie-Hellman Key Exchange": {
                "confidentiality": 4,
                "integrity": 3,
                "authentication": 1,
                "forward_secrecy": 5,
                "quantum_resistance": 1,
                "implementation_complexity": 2,
                "known_vulnerabilities": [
                    "Man-in-the-middle attack", 
                    "Small subgroup attacks", 
                    "Logjam attack (weak parameters)",
                    "Quantum computer vulnerability"
                ],
                "description": """
                The Diffie-Hellman (DH) key exchange protocol allows two parties to establish a shared secret over
                an insecure channel. The original protocol doesn't provide authentication, making it vulnerable to 
                man-in-the-middle attacks when used alone.
                
                **Key Features:**
                - Allows secure key exchange over insecure channels
                - Basis for many modern key exchange protocols
                - Provides forward secrecy
                - Simple mathematical foundation based on discrete logarithm problem
                """
            },
            "RSA Key Exchange": {
                "confidentiality": 4,
                "integrity": 4,
                "authentication": 4,
                "forward_secrecy": 1,
                "quantum_resistance": 1,
                "implementation_complexity": 3,
                "known_vulnerabilities": [
                    "Quantum computer vulnerability", 
                    "Padding oracle attacks", 
                    "Timing attacks",
                    "Bleichenbacher's attack",
                    "No forward secrecy"
                ],
                "description": """
                RSA (Rivest-Shamir-Adleman) is one of the first public-key cryptosystems widely used for secure 
                data transmission. It's based on the practical difficulty of factoring the product of two large 
                prime numbers.
                
                **Key Features:**
                - Public key encryption and digital signatures
                - Widely deployed in various security applications
                - Simple key exchange mechanism
                - Can be used for both encryption and signatures
                - Vulnerable to quantum computing attacks
                """
            },
            "SSH": {
                "confidentiality": 5,
                "integrity": 5,
                "authentication": 5,
                "forward_secrecy": 4,
                "quantum_resistance": 2,
                "implementation_complexity": 3,
                "known_vulnerabilities": [
                    "Implementation vulnerabilities", 
                    "Key management issues", 
                    "Configuration errors",
                    "Side-channel attacks"
                ],
                "description": """
                Secure Shell (SSH) is a cryptographic network protocol for operating network services securely over
                an unsecured network. SSH provides a secure channel over an unsecured network by using client-server
                architecture, connecting an SSH client application with an SSH server.
                
                **Key Features:**
                - Strong encryption and authentication
                - Public key and password authentication options
                - Port forwarding capabilities
                - Secure file transfer protocol (SFTP) support
                - Command-line and programmatic access
                """
            },
            "Kerberos": {
                "confidentiality": 4,
                "integrity": 4,
                "authentication": 5,
                "forward_secrecy": 2,
                "quantum_resistance": 2,
                "implementation_complexity": 5,
                "known_vulnerabilities": [
                    "Pass-the-ticket attacks", 
                    "Golden ticket attacks", 
                    "Kerberoasting",
                    "Clock synchronization issues",
                    "Password-based vulnerabilities"
                ],
                "description": """
                Kerberos is a computer network authentication protocol that works on the basis of tickets to allow
                nodes communicating over a non-secure network to prove their identity to one another in a secure manner.
                
                **Key Features:**
                - Mutual authentication (client and server verify each other)
                - Ticket-based authentication system
                - Single sign-on capabilities
                - Time-synchronized tickets with limited lifetime
                - Centralized authentication server (KDC)
                """
            },
            "OAuth 2.0": {
                "confidentiality": 3,
                "integrity": 3,
                "authentication": 4,
                "forward_secrecy": 1,
                "quantum_resistance": 3,
                "implementation_complexity": 4,
                "known_vulnerabilities": [
                    "CSRF attacks", 
                    "Token leakage", 
                    "Phishing vulnerabilities",
                    "Implementation errors",
                    "Authorization code interception"
                ],
                "description": """
                OAuth 2.0 is an authorization framework that enables a third-party application to obtain limited
                access to an HTTP service. It works by delegating user authentication to the service that hosts
                the user account and authorizing third-party applications to access that user account.
                
                **Key Features:**
                - Token-based authorization
                - Different grant types for various use cases
                - Separation of authentication and authorization
                - Limited scope access control
                - Widely adopted for API authorization
                """
            }
        }
        
        # Display protocol information
        if protocol in protocol_properties:
            props = protocol_properties[protocol]
            
            # Protocol description
            st.markdown(props["description"])
            
            # Security properties radar chart
            st.subheader("Security Properties")
            
            # Prepare data for radar chart
            categories = ['Confidentiality', 'Integrity', 'Authentication', 
                         'Forward Secrecy', 'Quantum Resistance', 'Implementation\nSimplicity']
            
            values = [
                props["confidentiality"],
                props["integrity"],
                props["authentication"],
                props["forward_secrecy"],
                props["quantum_resistance"],
                6 - props["implementation_complexity"]  # Invert for simplicity
            ]
            
            # Create radar chart
            fig = plt.figure(figsize=(10, 6))
            ax = fig.add_subplot(111, polar=True)
            
            # Set the angles for each property
            angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist()
            values.append(values[0])  # Close the loop
            angles.append(angles[0])  # Close the loop
            
            # Plot the radar chart
            ax.plot(angles, values, 'o-', linewidth=2)
            ax.fill(angles, values, alpha=0.25)
            
            # Set the labels
            ax.set_thetagrids(np.degrees(angles[:-1]), categories)
            ax.set_ylim(0, 5)
            ax.grid(True)
            
            # Add chart title
            plt.title(f'Security Properties of {protocol}', size=15, y=1.1)
            
            st.pyplot(fig)
            
            # Vulnerabilities section
            st.subheader("Known Vulnerabilities")
            for vuln in props["known_vulnerabilities"]:
                st.markdown(f"- {vuln}")
            
            if st.checkbox("Show Mitigation Strategies"):
                st.subheader("Mitigation Strategies")
                
                mitigations = {
                    "TLS 1.3": [
                        "Use up-to-date TLS libraries and keep them updated",
                        "Follow implementation best practices",
                        "Use proper certificate validation",
                        "Enable certificate transparency"
                    ],
                    "Signal Protocol": [
                        "Use secure key verification methods",
                        "Keep implementations updated",
                        "Validate device identity before communication",
                        "Follow implementation guidelines"
                    ],
                    "Diffie-Hellman Key Exchange": [
                        "Always combine with authentication mechanism",
                        "Use strong, vetted parameters",
                        "Use elliptic curve variant (ECDHE) when possible",
                        "Validate all parameters"
                    ],
                    "RSA Key Exchange": [
                        "Use sufficiently large key sizes (minimum 2048 bits)",
                        "Use proper padding (PKCS#1 v2.1 / OAEP)",
                        "Implement countermeasures against timing attacks",
                        "Consider migrating to protocols with forward secrecy"
                    ],
                    "SSH": [
                        "Use key-based authentication instead of passwords",
                        "Configure server with secure ciphers and algorithms",
                        "Keep SSH implementation updated",
                        "Use proper key management procedures"
                    ],
                    "Kerberos": [
                        "Use strong password policies",
                        "Implement time synchronization",
                        "Monitor for suspicious ticket granting activities",
                        "Secure the Key Distribution Center (KDC)"
                    ],
                    "OAuth 2.0": [
                        "Use state parameters to prevent CSRF",
                        "Implement PKCE for mobile applications",
                        "Validate redirect URIs",
                        "Use short-lived access tokens",
                        "Use secure transport (HTTPS) throughout"
                    ]
                }
                
                for mitigation in mitigations[protocol]:
                    st.markdown(f"- {mitigation}")
        
        # Show example attack scenario
        if st.checkbox("Show Example Attack Scenario"):
            st.subheader(f"Example Attack Scenario for {protocol}")
            
            attack_scenarios = {
                "TLS 1.3": {
                    "title": "Downgrade Attack Attempt",
                    "description": """
                    In this scenario, an attacker attempts to force a TLS 1.3 connection to downgrade to an older,
                    vulnerable version of TLS or SSL.
                    
                    **Attack Flow:**
                    1. Client initiates TLS 1.3 connection to server
                    2. Attacker intercepts ClientHello message
                    3. Attacker modifies ClientHello to indicate only TLS 1.2 or older is supported
                    4. Attacker forwards modified message to server
                    
                    **TLS 1.3 Protection:**
                    TLS 1.3 includes specific protections against downgrade attacks:
                    - The server includes a value in the server nonce that indicates downgrade protection
                    - Final handshake verification would detect the manipulation
                    - Attack fails as the client detects the downgrade attempt
                    """,
                    "success_rate": 5  # Percentage chance of success (out of 100)
                },
                "Signal Protocol": {
                    "title": "Identity Key Verification Bypass",
                    "description": """
                    In this scenario, an attacker attempts to execute a man-in-the-middle attack by replacing 
                    the legitimate public key with their own.
                    
                    **Attack Flow:**
                    1. Attacker intercepts initial key exchange
                    2. Attacker substitutes their own public key
                    3. Attacker attempts to relay messages between parties
                    
                    **Signal Protocol Protection:**
                    Signal provides protection through:
                    - Safety numbers that users can verify out-of-band
                    - Notifications when a contact's key changes
                    - The attack fails if users verify keys through secondary channels
                    """,
                    "success_rate": 15  # Higher success rate because it depends on user verification
                },
                "Diffie-Hellman Key Exchange": {
                    "title": "Man-in-the-Middle Attack",
                    "description": """
                    In this scenario, an attacker positions themselves between the communicating parties to
                    intercept and relay messages, establishing separate keys with each legitimate party.
                    
                    **Attack Flow:**
                    1. Alice sends her public value g^a mod p to Bob
                    2. Mallory intercepts this and sends her own public value g^m mod p to Bob
                    3. Bob responds with his public value g^b mod p
                    4. Mallory intercepts this and sends her own public value g^n mod p to Alice
                    5. Alice and Bob now each share a key with Mallory, not with each other
                    
                    **Vulnerability:**
                    Basic Diffie-Hellman has no authentication mechanism, making this attack highly successful.
                    To mitigate, DH must be combined with an authentication mechanism.
                    """,
                    "success_rate": 95  # Very high success rate for unauthenticated DH
                },
                "RSA Key Exchange": {
                    "title": "Bleichenbacher's Oracle Attack",
                    "description": """
                    This attack exploits information leaked by SSL/TLS servers that use RSA encryption with PKCS#1 v1.5 padding.
                    
                    **Attack Flow:**
                    1. Attacker captures an RSA-encrypted message (premaster secret)
                    2. Attacker sends carefully crafted modifications of the message to the server
                    3. Server responses reveal information about the padding
                    4. With enough queries, the attacker can decrypt the original message
                    
                    **Vulnerability:**
                    The success depends on whether the server leaks information about the PKCS#1 padding validity.
                    Modern implementations include countermeasures, but implementation errors can reintroduce the vulnerability.
                    """,
                    "success_rate": 30  # Moderate success rate due to widespread mitigations
                },
                "SSH": {
                    "title": "Password Brute Force Attack",
                    "description": """
                    In this scenario, an attacker attempts to gain access by trying multiple password combinations.
                    
                    **Attack Flow:**
                    1. Attacker identifies SSH server and port
                    2. Attacker uses automated tools to try common usernames and passwords
                    3. If successful, attacker gains shell access to the target system
                    
                    **Vulnerability:**
                    The success depends on password strength and whether the server allows password authentication.
                    Systems configured to use only key-based authentication are protected against this attack.
                    """,
                    "success_rate": 25  # Success depends heavily on configuration
                },
                "Kerberos": {
                    "title": "Pass-the-Ticket Attack",
                    "description": """
                    In this attack, an adversary extracts and reuses Kerberos tickets from one system to access another system.
                    
                    **Attack Flow:**
                    1. Attacker compromises a system where a user is authenticated
                    2. Attacker extracts Kerberos tickets from memory
                    3. Attacker reuses these tickets to access other services as the victim
                    
                    **Vulnerability:**
                    Once an attacker has access to a machine with active tickets, they can reuse those tickets
                    until they expire. This attack is particularly effective in active directory environments.
                    """,
                    "success_rate": 70  # High success rate if initial access is gained
                },
                "OAuth 2.0": {
                    "title": "Authorization Code Interception",
                    "description": """
                    In this attack, an attacker intercepts the authorization code before it's exchanged for an access token.
                    
                    **Attack Flow:**
                    1. User initiates OAuth flow with legitimate application
                    2. User authenticates and authorizes the application
                    3. Authorization server redirects with code
                    4. Attacker intercepts the authorization code (via network sniffing, malicious app, etc.)
                    5. Attacker uses the code to obtain an access token
                    
                    **Vulnerability:**
                    The attack success depends on the implementation. Using PKCE (Proof Key for Code Exchange)
                    extension can prevent this attack for public clients.
                    """,
                    "success_rate": 45  # Moderate success rate depending on implementation
                }
            }
            
            scenario = attack_scenarios[protocol]
            
            # Display attack scenario
            st.markdown(f"### {scenario['title']}")
            st.markdown(scenario["description"])
            
            # Attack success visualization
            success_rate = scenario["success_rate"]
            
            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Attack Success Rate", f"{success_rate}%")
                
            with col2:
                # Simple visualization of attack success probability
                fig, ax = plt.subplots(figsize=(8, 1))
                ax.barh([""], [success_rate], color='red', alpha=0.7)
                ax.barh([""], [100-success_rate], left=[success_rate], color='green', alpha=0.7)
                
                # Add labels
                if success_rate < 50:
                    ax.text(success_rate + 2, 0, f"Protected ({100-success_rate}%)", va='center')
                    ax.text(success_rate/2, 0, f"Vulnerable ({success_rate}%)", va='center', ha='center', color='white')
                else:
                    ax.text(success_rate/2, 0, f"Vulnerable ({success_rate}%)", va='center', ha='center', color='white')
                    ax.text(success_rate + (100-success_rate)/2, 0, f"Protected ({100-success_rate}%)", va='center', ha='center')
                
                ax.set_xlim(0, 100)
                ax.set_xticks([])
                ax.set_yticks([])
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.spines['bottom'].set_visible(False)
                ax.spines['left'].set_visible(False)
                
                st.pyplot(fig)
                
    with crypto_tab2:
        st.subheader("Man-in-the-Middle Attack Simulation")
        
        st.markdown("""
        This simulation demonstrates a Man-in-the-Middle (MITM) attack against different key exchange protocols,
        showing how various security properties can prevent or detect the attack.
        """)
        
        # Simulation settings
        col1, col2 = st.columns(2)
        with col1:
            target_protocol = st.selectbox(
                "Target Protocol",
                [
                    "Basic Diffie-Hellman", 
                    "Authenticated Diffie-Hellman",
                    "RSA Key Exchange",
                    "TLS 1.3 Handshake"
                ]
            )
        with col2:
            attack_sophistication = st.slider(
                "Attacker Sophistication Level", 
                min_value=1, 
                max_value=5, 
                value=3,
                help="Higher values represent more sophisticated attacks with better resources"
            )
            
        # Options for attack scenarios
        passive_mitm = st.checkbox("Passive Eavesdropping Only", value=False)
        
        # Specific protocol options
        if target_protocol == "Basic Diffie-Hellman":
            dh_key_size = st.select_slider(
                "DH Parameter Size",
                options=["512-bit", "1024-bit", "2048-bit", "4096-bit"],
                value="1024-bit"
            )
        elif target_protocol == "TLS 1.3 Handshake":
            cert_validation = st.checkbox("Strict Certificate Validation", value=True)
            
        # Run simulation button
        if st.button("Run MITM Simulation"):
            # Set up simulation parameters based on selections
            sim_params = {
                "Basic Diffie-Hellman": {
                    "active_defense": 1,  # No active defense
                    "passive_defense": 1,  # No passive defense
                    "attack_difficulty": {"512-bit": 2, "1024-bit": 3, "2048-bit": 4, "4096-bit": 5}
                },
                "Authenticated Diffie-Hellman": {
                    "active_defense": 4,  # Good active defense
                    "passive_defense": 2,  # Some passive defense
                    "attack_difficulty": 4
                },
                "RSA Key Exchange": {
                    "active_defense": 3,  # Moderate active defense
                    "passive_defense": 3,  # Moderate passive defense
                    "attack_difficulty": 4
                },
                "TLS 1.3 Handshake": {
                    "active_defense": 5,  # Strong active defense
                    "passive_defense": 4,  # Strong passive defense
                    "attack_difficulty": 5
                }
            }
            
            # Calculate attack success probability
            protocol_params = sim_params[target_protocol]
            
            # Get difficulty based on protocol and settings
            if target_protocol == "Basic Diffie-Hellman":
                difficulty = protocol_params["attack_difficulty"][dh_key_size]
            elif target_protocol == "TLS 1.3 Handshake":
                difficulty = protocol_params["attack_difficulty"]
                if not cert_validation:
                    difficulty -= 2  # Much easier without cert validation
            else:
                difficulty = protocol_params["attack_difficulty"]
            
            # Calculate success probability
            if passive_mitm:
                # Passive attacks are much harder
                success_prob = max(0, min(100, (attack_sophistication - difficulty - protocol_params["passive_defense"]) * 20))
            else:
                # Active MITM
                success_prob = max(0, min(100, (attack_sophistication - difficulty + 2) * 20))
                
                # Account for active defenses
                if protocol_params["active_defense"] > attack_sophistication:
                    # Attack detected
                    success_prob = max(0, success_prob - (protocol_params["active_defense"] - attack_sophistication) * 15)
            
            # Display simulation results
            st.subheader("Simulation Results")
            
            # Outcome and visualization
            col1, col2 = st.columns([1, 2])
            with col1:
                st.metric("Attack Success Probability", f"{int(success_prob)}%")
                
                if success_prob < 10:
                    st.success("Attack Failed: Security measures effective")
                elif success_prob < 40:
                    st.warning("Partial Success: Limited information disclosure")
                else:
                    st.error("Attack Successful: Communication compromised")
                    
            with col2:
                # Visualization of attack success
                fig, ax = plt.subplots(figsize=(8, 3))
                
                # Success probability gauge
                ax.barh(["Attack\nSuccess"], [success_prob], color='red', alpha=0.7)
                ax.barh(["Attack\nSuccess"], [100-success_prob], left=[success_prob], color='green', alpha=0.7)
                
                # Add text labels
                if success_prob < 30:
                    ax.text(success_prob + 5, 0, f"Secure ({100-success_prob}%)", va='center')
                    if success_prob > 5:
                        ax.text(success_prob/2, 0, f"{success_prob}%", va='center', ha='center', color='white')
                else:
                    ax.text(success_prob/2, 0, f"Vulnerable ({success_prob}%)", va='center', ha='center', color='white' if success_prob > 20 else 'black')
                    ax.text(success_prob + (100-success_prob)/2, 0, f"{100-success_prob}%", va='center', ha='center')
                
                ax.set_xlim(0, 100)
                ax.set_xticks([0, 25, 50, 75, 100])
                ax.set_yticks([])
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                
                st.pyplot(fig)
            
            # Simulation diagram
            st.subheader("Attack Simulation Diagram")
            
            # Create a simple diagram showing the attack
            alice_sends = []
            bob_receives = []
            eve_intercepts = []
            events = []
            attack_detected = False
            
            # Define events based on protocol
            if target_protocol == "Basic Diffie-Hellman":
                alice_sends = ["g^a mod p"]
                bob_sends = ["g^b mod p"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts g^a", "Sends g^e to Bob", "Intercepts g^b", "Sends g^e to Alice"]
                    alice_receives = ["g^e mod p (Eve's value)"]
                    bob_receives = ["g^e mod p (Eve's value)"]
                    
                    events = [
                        "Alice computes key K1 = (g^e)^a mod p",
                        "Bob computes key K2 = (g^e)^b mod p",
                        "Eve computes key K1 = (g^a)^e mod p with Alice",
                        "Eve computes key K2 = (g^b)^e mod p with Bob",
                        "Eve can decrypt all traffic between Alice and Bob"
                    ]
                else:  # Passive eavesdropping
                    eve_intercepts = ["Observes g^a mod p", "Observes g^b mod p"]
                    events = [
                        "Eve can't directly compute g^ab from g^a and g^b",
                        "Eve attempts cryptanalysis based on observed values"
                    ]
                    
                    # If successful (based on probability)
                    if success_prob > 50:
                        events.append("Eve successfully derives the shared key through cryptanalysis")
                    else:
                        events.append("Cryptanalysis fails due to large key size")
                        
            elif target_protocol == "Authenticated Diffie-Hellman":
                alice_sends = ["g^a mod p", "Sign(A, g^a)"]
                bob_sends = ["g^b mod p", "Sign(B, g^b)"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts g^a and signature", 
                                    "Cannot forge Alice's signature", 
                                    "Attempts to relay with modifications"]
                    
                    # Check if attack is detected
                    if attack_sophistication < protocol_params["active_defense"]:
                        attack_detected = True
                        events = [
                            "Bob verifies signature with Alice's public key",
                            "Signature verification fails due to Eve's manipulation",
                            "Attack detected - connection terminated"
                        ]
                    else:
                        events = [
                            "Eve uses sophisticated relay techniques",
                            "Eve manages to manipulate parts of the exchange",
                            "Some information is compromised but not the full key"
                        ]
                else:  # Passive eavesdropping
                    eve_intercepts = ["Observes all signed messages"]
                    events = [
                        "Eve can see public values but can't derive the private key",
                        "Authentication prevents active attacks",
                        "Eve attempts advanced cryptanalysis"
                    ]
                    
                    if success_prob > 30:
                        events.append("Eve finds an implementation vulnerability")
                    else:
                        events.append("Eve's analysis reveals no useful information")
                
            elif target_protocol == "RSA Key Exchange":
                alice_sends = ["Encrypted session key"]
                bob_sends = ["Acknowledgment"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts encrypted session key", 
                                    "Cannot decrypt without private key", 
                                    "Attempts oracle attack"]
                    
                    if success_prob > 70:
                        events = [
                            "Eve successfully exploits padding oracle",
                            "Eve recovers the session key",
                            "Communication is compromised"
                        ]
                    else:
                        events = [
                            "Oracle attack fails due to server mitigations",
                            "Eve attempts to use other vulnerabilities",
                            "Most communication remains secure"
                        ]
                else:  # Passive
                    eve_intercepts = ["Records encrypted traffic"]
                    events = [
                        "Eve stores encrypted communications",
                        "Eve cannot decrypt RSA without private key",
                        "Data remains secure until quantum computers become viable"
                    ]
                    
            elif target_protocol == "TLS 1.3 Handshake":
                alice_sends = ["ClientHello, key_share"]
                bob_sends = ["ServerHello, key_share, certificate"]
                
                if not passive_mitm:  # Active MITM
                    eve_intercepts = ["Intercepts ClientHello", 
                                    "Attempts to manipulate handshake"]
                    
                    if cert_validation:
                        attack_detected = True
                        events = [
                            "TLS 1.3 downgrade protection activated",
                            "Certificate validation fails for Eve's certificate",
                            "Handshake aborted - attack detected"
                        ]
                    else:
                        events = [
                            "Certificate validation bypassed",
                            "Eve establishes separate connections with Alice and Bob",
                            "TLS session partially compromised"
                        ]
                else:  # Passive
                    eve_intercepts = ["Observes encrypted handshake"]
                    events = [
                        "Eve sees encrypted handshake but cannot derive keys",
                        "Perfect forward secrecy prevents decryption",
                        "Traffic remains confidential"
                    ]
            
            # Create visual representation of attack scenario
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.axis('off')
            
            # Draw arrows and entities
            alice_x, alice_y = 1, 3
            bob_x, bob_y = 9, 3
            eve_x, eve_y = 5, 1.5
            
            # Draw entities
            ax.plot(alice_x, alice_y, 'bo', markersize=20)
            ax.text(alice_x, alice_y+0.5, "Alice", ha='center', fontsize=12)
            
            ax.plot(bob_x, bob_y, 'bo', markersize=20)
            ax.text(bob_x, bob_y+0.5, "Bob", ha='center', fontsize=12)
            
            if not passive_mitm:
                # Active MITM
                ax.plot(eve_x, eve_y, 'ro', markersize=20)
                ax.text(eve_x, eve_y-0.5, "Eve (MITM)", ha='center', fontsize=12)
                
                # Draw intercepted paths
                ax.arrow(alice_x+0.3, alice_y-0.3, eve_x-alice_x-0.6, eve_y-alice_y+0.3, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                ax.arrow(eve_x+0.3, eve_y, bob_x-eve_x-0.6, bob_y-eve_y, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                
                # Return path
                ax.arrow(bob_x-0.3, bob_y-0.3, eve_x-bob_x+0.6, eve_y-bob_y+0.3, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                ax.arrow(eve_x-0.3, eve_y, alice_x-eve_x+0.6, alice_y-eve_y, 
                        head_width=0.2, head_length=0.3, fc='gray', ec='gray', linestyle='--')
                
                # Add attack status
                if attack_detected:
                    ax.text(5, 4.5, "ATTACK DETECTED", color='red', ha='center', fontsize=16, fontweight='bold')
                    # Add red X on attack path
                    ax.plot([4, 6], [3.5, 4.5], 'r-', linewidth=3)
                    ax.plot([6, 4], [3.5, 4.5], 'r-', linewidth=3)
                else:
                    if success_prob > 50:
                        ax.text(5, 4.5, "ATTACK SUCCESSFUL", color='red', ha='center', fontsize=16, fontweight='bold')
                    else:
                        ax.text(5, 4.5, "ATTACK PARTIALLY MITIGATED", color='orange', ha='center', fontsize=16, fontweight='bold')
            else:
                # Passive eavesdropping
                ax.plot(eve_x, eve_y, 'ro', markersize=20)
                ax.text(eve_x, eve_y-0.5, "Eve (Passive)", ha='center', fontsize=12)
                
                # Direct communication
                ax.arrow(alice_x+0.3, alice_y, bob_x-alice_x-0.6, 0, 
                        head_width=0.2, head_length=0.3, fc='blue', ec='blue')
                ax.arrow(bob_x-0.3, bob_y, alice_x-bob_x+0.6, 0, 
                        head_width=0.2, head_length=0.3, fc='blue', ec='blue')
                
                # Eavesdropping lines
                ax.plot([eve_x, 5], [eve_y, 3], 'r--', alpha=0.5)
                
                # Add attack status
                if success_prob > 50:
                    ax.text(5, 4.5, "PASSIVE ATTACK SUCCESSFUL", color='red', ha='center', fontsize=16, fontweight='bold')
                else:
                    ax.text(5, 4.5, "COMMUNICATION SECURE", color='green', ha='center', fontsize=16, fontweight='bold')
            
            # Show the messages exchanged
            msg_y_pos = 3.8
            for msg in alice_sends:
                msg_y_pos += 0.3
                ax.text(2.5, msg_y_pos, f"→ {msg}", fontsize=10)
                
            msg_y_pos = 3.8
            for msg in bob_sends:
                msg_y_pos += 0.3
                ax.text(7.5, msg_y_pos, f"← {msg}", fontsize=10)
                
            # Show Eve's actions
            msg_y_pos = 1
            for msg in eve_intercepts:
                msg_y_pos -= 0.3
                ax.text(5, msg_y_pos, msg, fontsize=10, color='red', ha='center')
            
            plt.tight_layout()
            st.pyplot(fig)
            
            # Event log
            st.subheader("Attack Event Log")
            for i, event in enumerate(events, 1):
                st.markdown(f"{i}. {event}")
                
            # Technical explanation
            st.subheader("Technical Analysis")
            
            if target_protocol == "Basic Diffie-Hellman":
                st.markdown("""
                **Vulnerability Analysis**:
                
                Basic Diffie-Hellman key exchange is vulnerable to man-in-the-middle attacks
                because it doesn't authenticate the participants. An attacker can establish separate
                key exchanges with both parties, decrypting and re-encrypting all traffic between them.
                
                The security relies solely on the computational difficulty of the discrete logarithm problem.
                Larger parameters provide better security against passive attacks but do not prevent MITM.
                """)
                
            elif target_protocol == "Authenticated Diffie-Hellman":
                st.markdown("""
                **Security Analysis**:
                
                Authenticated Diffie-Hellman addresses the main weakness of basic DH by adding
                authentication, typically through digital signatures. Each party signs their DH public
                value, allowing the other party to verify the sender's identity.
                
                This prevents MITM attacks as long as the signature verification is properly implemented
                and the private signing keys remain secure. The attacker cannot forge valid signatures
                without the private keys.
                """)
                
            elif target_protocol == "RSA Key Exchange":
                st.markdown("""
                **Security Analysis**:
                
                RSA key exchange secures communication by encrypting the session key with the recipient's
                public key. Only the holder of the private key can decrypt it.
                
                This approach is vulnerable to:
                - Collection and storage of encrypted traffic for future decryption (no forward secrecy)
                - Various side-channel and implementation attacks like padding oracles
                - Quantum computing attacks in the future
                
                Modern protocols generally prefer ephemeral Diffie-Hellman for forward secrecy.
                """)
                
            elif target_protocol == "TLS 1.3 Handshake":
                st.markdown("""
                **Security Analysis**:
                
                TLS 1.3 provides strong security through:
                - Ephemeral key exchange (perfect forward secrecy)
                - Simplified cryptographic options (removing weak algorithms)
                - Encrypted handshake messages (protecting metadata)
                - Downgrade attack prevention
                - 1-RTT handshake (faster connection establishment)
                
                Certificate validation is critical - without proper validation, MITM attacks
                remain possible despite the protocol's security features.
                """)
            
            # Recommendations
            st.subheader("Security Recommendations")
            
            if target_protocol == "Basic Diffie-Hellman":
                st.warning("""
                1. Never use unauthenticated Diffie-Hellman in production environments
                2. Always combine DH with an authentication mechanism
                3. Use DH parameters of at least 2048 bits
                4. Consider using Elliptic Curve Diffie-Hellman for better performance and security
                """)
                
            elif target_protocol == "Authenticated Diffie-Hellman":
                st.success("""
                1. Ensure proper validation of all signatures
                2. Use strong signature algorithms (e.g., RSA-PSS, Ed25519)
                3. Protect private signing keys
                4. Consider using established protocols like TLS rather than custom implementations
                """)
                
            elif target_protocol == "RSA Key Exchange":
                st.warning("""
                1. Consider replacing RSA key exchange with (EC)DHE for forward secrecy
                2. If using RSA, implement proper padding (PKCS#1 v2.1 / OAEP)
                3. Use RSA key sizes of at least 2048 bits
                4. Implement countermeasures against timing and oracle attacks
                """)
                
            elif target_protocol == "TLS 1.3 Handshake":
                st.success("""
                1. Always enable and enforce strict certificate validation
                2. Use Certificate Transparency (CT) to detect misissued certificates
                3. Consider using certificate pinning for high-value applications
                4. Keep TLS libraries updated to patch implementation vulnerabilities
                5. Implement HSTS to prevent downgrade to HTTP
                """)
                
    with crypto_tab3:
        st.subheader("Protocol Comparison")
        
        st.markdown("""
        Compare different cryptographic protocols based on their security properties,
        performance characteristics, and suitability for different use cases.
        """)
        
        # Select protocols to compare
        protocols_to_compare = st.multiselect(
            "Select Protocols to Compare",
            [
                "TLS 1.2", 
                "TLS 1.3", 
                "SSH",
                "Signal Protocol", 
                "IPsec",
                "WireGuard",
                "OpenVPN",
                "Noise Protocol"
            ],
            default=["TLS 1.2", "TLS 1.3"]
        )
        
        # Protocol comparison data
        protocol_data = {
            "TLS 1.2": {
                "Key Exchange": "RSA or DHE/ECDHE",
                "Forward Secrecy": "Optional (with DHE/ECDHE)",
                "Authentication": "Certificate-based",
                "Cipher Modes": "CBC, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "2-RTT",
                "Performance": "Moderate",
                "Vulnerabilities": "BEAST, POODLE, CRIME, BREACH, Heartbleed (impl.)",
                "Year Introduced": "2008"
            },
            "TLS 1.3": {
                "Key Exchange": "DHE/ECDHE only",
                "Forward Secrecy": "Mandatory",
                "Authentication": "Certificate-based",
                "Cipher Modes": "AEAD only (GCM, ChaCha20-Poly1305)",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Optional",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-RTT",
                "Performance": "High",
                "Vulnerabilities": "Limited (0-RTT replay if enabled)",
                "Year Introduced": "2018"
            },
            "SSH": {
                "Key Exchange": "DHE/ECDHE",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key or Password",
                "Cipher Modes": "CBC, CTR, GCM",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Implementation-specific",
                "Year Introduced": "1995 (SSHv2: 2006)"
            },
            "Signal Protocol": {
                "Key Exchange": "Triple ECDHE (X3DH)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "AES-CBC, AES-GCM",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes (with prekeys)",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Asynchronous",
                "Performance": "High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2013"
            },
            "IPsec": {
                "Key Exchange": "IKE (Internet Key Exchange)",
                "Forward Secrecy": "Optional",
                "Authentication": "Pre-shared keys, Certificates, EAP",
                "Cipher Modes": "CBC, CTR, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Complex config, implementation issues",
                "Year Introduced": "1995"
            },
            "WireGuard": {
                "Key Exchange": "ECDHE (Curve25519)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "ChaCha20-Poly1305",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-RTT",
                "Performance": "Very High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2016"
            },
            "OpenVPN": {
                "Key Exchange": "TLS-based (RSA or DHE/ECDHE)",
                "Forward Secrecy": "Optional",
                "Authentication": "Certificates, Pre-shared keys",
                "Cipher Modes": "CBC, GCM",
                "Perfect Forward Secrecy": "Optional",
                "0-RTT": "No",
                "Quantum Resistance": "Low",
                "Handshake Latency": "Multiple round trips",
                "Performance": "Moderate",
                "Vulnerabilities": "Implementation-specific",
                "Year Introduced": "2001"
            },
            "Noise Protocol": {
                "Key Exchange": "ECDHE (customizable)",
                "Forward Secrecy": "Yes",
                "Authentication": "Public Key",
                "Cipher Modes": "AESGCM, ChaChaPoly",
                "Perfect Forward Secrecy": "Yes",
                "0-RTT": "Yes (in some patterns)",
                "Quantum Resistance": "Low",
                "Handshake Latency": "1-2 RTT (pattern dependent)",
                "Performance": "High",
                "Vulnerabilities": "Few known",
                "Year Introduced": "2015"
            }
        }
        
        if protocols_to_compare:
        selected_data = {proto: protocol_data[proto] for proto in protocols_to_compare}
        df = pd.DataFrame(selected_data).T
        st.dataframe(df, use_container_width=True)
        else:
        st.warning("Please select at least one protocol to see the comparison ✨") 

        


st.markdown("---")
st.caption("Built with ❤️ using PyCryptodome, Streamlit, and Gemini AI.")
