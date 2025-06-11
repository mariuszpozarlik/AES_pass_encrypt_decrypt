from utils import derive_key
from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
# ======================================
# --- DESZYFROWANIE ---
# ======================================

# --- Odczyt ciągu ---
encrypted_blob = str(input("ciphertext: ")).encode(encoding="utf-8")
password = getpass.getpass()
decoded = urlsafe_b64decode(encrypted_blob)

# --- Rozdzielenie: salt (16 B), nonce (12 B), ciphertext (reszta) ---
salt = decoded[:16]
nonce = decoded[16:28]
ciphertext = decoded[28:]

# --- Wyprowadzenie klucza ponownie z hasła i soli ---
key = derive_key(password, salt)
aesgcm = AESGCM(key)

# --- Deszyfrowanie ---
decrypted = aesgcm.decrypt(nonce, ciphertext, None)
print("\n🔓 Decrypted string:\n", decrypted.decode())