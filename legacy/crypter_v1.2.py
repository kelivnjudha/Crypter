#!/usr/bin/env python3
import sys
import os
import json
import difflib
import re
from io import BytesIO
from PyQt5 import QtWidgets, QtGui, QtCore
from cryptography.fernet import Fernet, InvalidToken
import qrcode
from PIL import Image

KEY_FILE = "keys.json"
MASTER_KEY = b'pHU06D7jwltszEqKvKBFUtB2sXOJntqSDlv1XYhaLeE='  # Fixed master key for JSON encryption
SIMILARITY_THRESHOLD = 0.8  # Threshold for fuzzy matching of encrypted texts

def sanitize_filename(filename):
    return re.sub(r'[\\/*?:"<>|]', "", filename)

class EncryptionApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crypter v1.2")
        self.setWindowIcon(QtGui.QIcon("logo.ico"))  # Set the application logo
        self.setGeometry(100, 100, 600, 500)
        self.setup_ui()
        
        # Master cipher for keys file encryption/decryption
        self.master_cipher = Fernet(MASTER_KEY)
        # Load persistent keys and encrypted texts
        self.keys_data = self.load_keys()

    def setup_ui(self):
        # Create a central widget and layout
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)
        
        # Create buttons for file operations arranged in a horizontal layout
        btn_layout = QtWidgets.QHBoxLayout()
        self.encrypt_file_btn = QtWidgets.QPushButton("Encrypt File")
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        btn_layout.addWidget(self.encrypt_file_btn)
        
        self.decrypt_file_btn = QtWidgets.QPushButton("Decrypt File")
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        btn_layout.addWidget(self.decrypt_file_btn)
        
        self.encrypt_dir_btn = QtWidgets.QPushButton("Encrypt Directory")
        self.encrypt_dir_btn.clicked.connect(self.encrypt_directory)
        btn_layout.addWidget(self.encrypt_dir_btn)
        
        self.decrypt_dir_btn = QtWidgets.QPushButton("Decrypt Directory")
        self.decrypt_dir_btn.clicked.connect(self.decrypt_directory)
        btn_layout.addWidget(self.decrypt_dir_btn)
        
        layout.addLayout(btn_layout)
        
        # QR Code generator section
        qr_layout = QtWidgets.QHBoxLayout()
        self.url_input = QtWidgets.QLineEdit()
        self.url_input.setPlaceholderText("Enter URL for QR Code")
        qr_layout.addWidget(self.url_input)
        self.generate_qr_btn = QtWidgets.QPushButton("Generate QR Code")
        self.generate_qr_btn.clicked.connect(self.generate_qr_code)
        qr_layout.addWidget(self.generate_qr_btn)
        layout.addLayout(qr_layout)
        
        # Terminal output window (acting as a console)
        self.terminal = QtWidgets.QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setFontFamily("Courier New")
        self.terminal.setStyleSheet("background-color: #1e1e1e; color: #dcdcdc;")
        layout.addWidget(self.terminal)
        
        # Modern style for buttons and inputs
        self.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
        """)

    def log_message(self, message, color="white"):
        """Log a message to the terminal window with specified color."""
        self.terminal.append(f'<span style="color:{color};">{message}</span>')

    def load_keys(self):
        if os.path.exists(KEY_FILE):
            try:
                with open(KEY_FILE, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.master_cipher.decrypt(encrypted_data)
                return json.loads(decrypted_data.decode('utf-8'))
            except (json.decoder.JSONDecodeError, InvalidToken, Exception):
                self.log_message("Failed to load keys. Starting fresh.", "orange")
                return {}
        else:
            return {}

    def save_keys(self):
        try:
            data = json.dumps(self.keys_data).encode('utf-8')
            encrypted_data = self.master_cipher.encrypt(data)
            with open(KEY_FILE, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            self.log_message("Failed to save keys.", "red")

    def encrypt_file(self, file_path=None):
        if not file_path:
            file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    original = f.read()
                key = Fernet.generate_key()
                cipher = Fernet(key)
                encrypted = cipher.encrypt(original)
                with open(file_path, 'wb') as f:
                    f.write(encrypted)
                # Store both the key and the full encrypted text for recovery
                self.keys_data[file_path] = {
                    "key": key.decode(),
                    "encrypted": encrypted.decode()
                }
                self.save_keys()
                self.log_message(f"File encrypted: {file_path}", "green")
            except Exception as e:
                self.log_message(f"Encryption failed: {str(e)}", "red")

    def decrypt_file(self, file_path=None):
        if not file_path:
            file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            if file_path not in self.keys_data:
                self.log_message("No key data found for this file.", "orange")
                return
            try:
                with open(file_path, 'rb') as f:
                    current_encrypted = f.read().decode()
                stored_encrypted = self.keys_data[file_path]["encrypted"]
                if current_encrypted != stored_encrypted:
                    ratio = difflib.SequenceMatcher(None, stored_encrypted, current_encrypted).ratio()
                    if ratio >= SIMILARITY_THRESHOLD:
                        self.log_message("Partial data detected. Recovering from stored encrypted text.", "blue")
                        current_encrypted = stored_encrypted
                    else:
                        self.log_message("Encrypted file does not match stored data. Decryption aborted.", "red")
                        return
                key = self.keys_data[file_path]["key"].encode()
                cipher = Fernet(key)
                decrypted = cipher.decrypt(current_encrypted.encode())
                with open(file_path, 'wb') as f:
                    f.write(decrypted)
                self.log_message(f"File decrypted: {file_path}", "green")
            except Exception as e:
                self.log_message(f"Decryption failed: {str(e)}", "red")

    def encrypt_directory(self):
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Encrypt")
        if dir_path:
            for file_name in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_name)
                if os.path.isfile(file_path):
                    self.encrypt_file(file_path)
            self.log_message("Directory encryption completed.", "green")

    def decrypt_directory(self):
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Decrypt")
        if dir_path:
            for file_name in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_name)
                if os.path.isfile(file_path):
                    self.decrypt_file(file_path)
            self.log_message("Directory decryption completed.", "green")

    def generate_qr_code(self):
        url = self.url_input.text().strip()
        if url:
            sanitized_url = sanitize_filename(url)
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10,
                    border=4,
                )
                qr.add_data(url)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = BytesIO()
                img.save(buffer, format="PNG")
                qimg = QtGui.QImage()
                qimg.loadFromData(buffer.getvalue(), "PNG")
                pixmap = QtGui.QPixmap.fromImage(qimg)
                self.qr_window = QtWidgets.QWidget()
                self.qr_window.setWindowTitle("QR Code")
                self.qr_window.setWindowIcon(QtGui.QIcon("logo.ico"))  # Optional: Set logo for QR window as well
                layout = QtWidgets.QVBoxLayout()
                label = QtWidgets.QLabel()
                label.setPixmap(pixmap)
                layout.addWidget(label)
                self.qr_window.setLayout(layout)
                self.qr_window.show()
                self.log_message("QR Code generated.", "green")
            except Exception as e:
                self.log_message(f"QR generation failed: {str(e)}", "red")
        else:
            self.log_message("Please enter a URL.", "orange")

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setWindowIcon(QtGui.QIcon("logo.ico"))
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
