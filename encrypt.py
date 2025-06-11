import os
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
from utils import derive_key

# --- Dane wejściowe ---
password = getpass.getpass()
repeat_pass = getpass.getpass("Repeat Password: ")

if password == repeat_pass:

    plaintext = bytes(str(input("Text to encrypt: ")).encode(encoding="utf-8"))
    print(plaintext)

    # --- Szyfrowanie ---
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # --- Zapis jako jeden ciąg: salt + nonce + ciphertext ---
    encrypted_blob = urlsafe_b64encode(salt + nonce + ciphertext).decode()
    print("🔐 Encrypted string:\n", encrypted_blob)

    with open("output.txt", "w") as f:
        f.write(encrypted_blob + "\n\n" + password)

else:
    print("Passwords doesn't match")