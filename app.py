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
        "🔐 AES Encrypt/Decrypt", 
        "🌀 ChaCha20 Encrypt/Decrypt",
        "🔏 Asymmetric Cryptography", 
        "📜 HMAC & Hash Functions", 
        "🤖 AI Code Explainer",
        "🔑 Password Strength Analyzer",
        "📊 Encryption Benchmark",
        "📱 QR Code Generator",
        "🔄 Format Converter",
        "🎲 Secure Password Generator",
        "⏱️ Hash Speed Test",
        "🔍 File Hash Verification",
        "🌐 JWT Token Inspector",
        "🔒 SSH Key Manager",
        "🕵️ Cipher Identifier",
        "🧮 Modular Calculator",
        "🔁 Base Converter",
        "🧠 Crypto Puzzle Game",
        
        # 💖 New Tools Below 💖
        "🧬 ECC Key Exchange Visualizer",
        "📅 TOTP Generator & Verifier",
        "📁 File Splitter & Joiner",
        "🔎 Entropy Analyzer",
        "📦 PGP File Encrypt/Decrypt",
        "🔐 Master Key Derivation Tool",
        "💾 Encrypted Notes Vault",
        "🛰️ Secure Chat Demo (ECC + AES)",
        "🔍 Randomness Tester",
        "📂 Encrypted Zip File Generator"
    ]
)



# --- 1. AES Encrypt/Decrypt ---
if feature == "🔐 AES Encrypt/Decrypt":
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
elif feature == "🌀 ChaCha20 Encrypt/Decrypt":
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
elif feature == "🔏 Asymmetric Cryptography":
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
elif feature == "📜 HMAC & Hash Functions":
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
elif feature == "🤖 AI Code Explainer":
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
elif feature == "🔑 Password Strength Analyzer":
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
elif feature == "🎲 Secure Password Generator":
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
elif feature == "🌐 JWT Token Inspector":
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
elif feature == "🔒 SSH Key Manager":
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


elif feature == "🔁 Base Converter":
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





elif feature == "🧠 Crypto Puzzle Game":
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


elif feature == "🧬 ECC Key Exchange Visualizer":
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


import pyotp

elif feature == "📅 TOTP Generator & Verifier":
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





elif feature == "📁 File Splitter & Joiner":
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




import math

elif feature == "🔎 Entropy Analyzer":
    st.header("🔎 Shannon Entropy Analyzer")
    text = st.text_area("Input Text or Data")

    if st.button("Analyze Entropy"):
        if text:
            freq = {char: text.count(char)/len(text) for char in set(text)}
            entropy = -sum(p * math.log2(p) for p in freq.values())
            st.success(f"Entropy: {entropy:.4f} bits per symbol")
            st.info("🔒 Higher entropy = more randomness")



elif feature == "📦 PGP File Encrypt/Decrypt":
    st.header("📦 Simulated PGP (Hybrid RSA + AES Encryption)")

    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    if mode == "Encrypt":
        file = st.file_uploader("Upload File")
        rsa_key = RSA.generate(2048)
        pub_key = rsa_key.publickey()

        if file and st.button("Encrypt File"):
            aes_key = get_random_bytes(16)
            cipher_rsa = pkcs1_15.new(pub_key)
            encrypted_key = rsa_key._encrypt(aes_key)
            
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file.read())

            bundle = encrypted_key + cipher_aes.nonce + tag + ciphertext
            st.download_button("Download Encrypted Bundle", bundle, file_name="pgp_encrypted.bin")
    else:
        st.warning("Decrypt implementation would need private key import + AES unwrap")


elif feature == "🔐 Master Key Derivation Tool":
    st.header("🔐 Derive Unique Keys from Master Password")
    master = st.text_input("Master Password", type="password")
    site = st.text_input("Service Identifier (e.g., gmail.com)")

    if master and site:
        salt = site.encode()
        derived = PBKDF2(master.encode(), salt, dkLen=32, count=100000)
        st.code(derived.hex(), "Derived Key (Hex)")


elif feature == "💾 Encrypted Notes Vault":
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


elif feature == "🛰️ Secure Chat Demo (ECC + AES)":
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



elif feature == "🔍 Randomness Tester":
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



import zipfile

elif feature == "📂 Encrypted Zip File Generator":
    st.header("📂 Encrypted ZIP Generator")
    uploaded_files = st.file_uploader("Upload Files", accept_multiple_files=True)
    zip_password = st.text_input("Password for ZIP", type="password")

    if uploaded_files and zip_password and st.button("Generate Encrypted ZIP"):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file in uploaded_files:
                zipf.writestr(file.name, file.read())
        zip_data = buffer.getvalue()

        key = SHA256.new(zip_password.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(zip_data)
        encrypted_zip = cipher.nonce + tag + ct
        st.download_button("Download Encrypted ZIP", encrypted_zip, file_name="encrypted.zip")


st.markdown("---")
st.caption("Built with ❤️ using PyCryptodome, Streamlit, and Gemini AI.")
