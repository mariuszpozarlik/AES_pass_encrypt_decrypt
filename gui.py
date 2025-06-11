import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class EncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Text Encrypt/Decrypt (AES-GCM)")

        # Text input
        self.input_label = tk.Label(master, text="Input text:")
        self.input_label.pack()
        self.input_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=10)
        self.input_text.pack()

        # Password entry
        self.password_label = tk.Label(master, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(master, show="*", width=40)
        self.password_entry.pack()

        self.confirm_label = tk.Label(master, text="Confirm Password:")
        self.confirm_label.pack()
        self.confirm_entry = tk.Entry(master, show="*", width=40)
        self.confirm_entry.pack()

        # Buttons
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        self.file_encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file)
        self.file_encrypt_button.pack(pady=5)

        self.file_decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file)
        self.file_decrypt_button.pack(pady=5)

        # Output
        self.output_label = tk.Label(master, text="Output:")
        self.output_label.pack()
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=10)
        self.output_text.pack()
        self.password = ""

    def derive_key(self, password: bytes, salt: bytes, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=200_000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def check_passwords(self):
        password = self.password_entry.get().encode()
        confirm_password = self.confirm_entry.get().encode()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return False

        if len(password) < 16:
            messagebox.showerror("Error", "Password must be at least 16 bytes (characters) long")
            return False

        self.password = password
        return True


    def encrypt(self):

        if self.check_passwords():
            text = self.input_text.get("1.0", tk.END).strip().encode()
            if not text:
                messagebox.showerror("Error", "Input text cannot be empty")
                return

            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = self.derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, text, None)
            data = base64.b64encode(salt + nonce + ciphertext).decode()
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, data)

    def decrypt(self):

        if self.check_passwords():
            data = self.input_text.get("1.0", tk.END).strip()
            if not data:
                messagebox.showerror("Error", "Encrypted input cannot be empty")
                return

            try:
                raw = base64.b64decode(data)
                if len(raw) < 28:
                    raise ValueError("Encoded input is too short")
                salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
                key = self.derive_key(self.password, salt)
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode()
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, decrypted)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def encrypt_file(self):
        filepath = filedialog.askopenfilename(title="Select file to encrypt")
        if not filepath:
            return

        if self.check_passwords():
            with open(filepath, "rb") as f:
                data = f.read()
            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = self.derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(nonce, data, None)
            out_data = salt + nonce + encrypted
            outpath = filedialog.asksaveasfilename(defaultextension=".enc", title="Save encrypted file as")
            if not outpath:
                return
            with open(outpath, "wb") as f:
                f.write(out_data)
            messagebox.showinfo("Success", f"Encrypted file saved to {outpath}")

    def decrypt_file(self):
        filepath = filedialog.askopenfilename(title="Select encrypted file")
        if not filepath:
            return
        if self.check_passwords():
            with open(filepath, "rb") as f:
                raw = f.read()
            if len(raw) < 28:
                messagebox.showerror("Error", "Encrypted file is too short or invalid")
                return
            salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
            key = self.derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            try:
                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                outpath = filedialog.asksaveasfilename(title="Save decrypted file as")
                if not outpath:
                    return
                with open(outpath, "wb") as f:
                    f.write(decrypted)
                messagebox.showinfo("Success", f"Decrypted file saved to {outpath}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
