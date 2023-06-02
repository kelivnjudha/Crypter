import json
import tkinter as tk
from tkinter import ttk
import os
from tkinter import Tk, Button, filedialog, messagebox, Entry, Label
from cryptography.fernet import Fernet, InvalidToken
import qrcode
import re

json_key = b'pHU06D7jwltszEqKvKBFUtB2sXOJntqSDlv1XYhaLeE='
KEY_FILE = "keys.json"

def sanitize_filename(filename):
    return re.sub(r'[\\/*?:"<>|]', "", filename)

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Encryption App')

        # Initialize Buttons
        self.init_buttons()
        self.init_search_box()

        # Initialize or load keys
        # Initialize or load keys
        self.json_cipher_suite = Fernet(json_key)

        if os.path.exists(KEY_FILE):
            try:
                with open(KEY_FILE, 'rb') as f: # Note: 'rb' for reading bytes
                    encrypted_data = f.read()
                    decrypted_data = self.json_cipher_suite.decrypt(encrypted_data)
                    self.keys = json.loads(decrypted_data.decode('utf-8'))
            except (json.decoder.JSONDecodeError, InvalidToken):
                self.keys = {}
        else:
            self.keys = {}

    def init_buttons(self):
        style = ttk.Style()

        style.configure('TButton', 
                        background='white',
                        foreground='gray',
                        font=('Arial', 10),
                        bordercolor='gray',
                        borderwidth=2)
        
        self.encrypt_button = ttk.Button(root, text='Encrypt File', command=self.encrypt_file, style='TButton')
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=10)

        self.decrypt_button = ttk.Button(root, text='Decrypt File', command=self.decrypt_file, style='TButton')
        self.decrypt_button.grid(row=0, column=2, padx=10, pady=10)

        self.encrypt_dir_button = ttk.Button(root, text='Encrypt Directory', command=self.encrypt_directory, style='TButton')
        self.encrypt_dir_button.grid(row=1, column=0, padx=10, pady=10)

        self.decrypt_dir_button = ttk.Button(root, text='Decrypt Directory', command=self.decrypt_directory, style='TButton')
        self.decrypt_dir_button.grid(row=1, column=2, padx=10, pady=10)

    def init_search_box(self):
        self.head_label = Label(root, text="QR Generater")
        self.head_label.grid(row=2, column=1, padx=10, pady=10)

        self.water_mark = Label(root, text="Crypter v1.1", fg='gray')
        self.water_mark.grid(row=7, column=1, padx=10, pady=10)

        self.search_label = Label(root, text="URL:")
        self.search_label.grid(row=3, column=0, padx=10, pady=10)

        self.search_entry = Entry(root)
        self.search_entry.grid(row=3, column=1, padx=10, pady=10)

        # Button that triggers the QR code generation
        self.generate_button = ttk.Button(root, text='Generate', command=self.generate_qr_code, style='TButton')
        self.generate_button.grid(row=3, column=2, padx=10, pady=10)


    def generate_qr_code(self):
        url = self.search_entry.get()
        sanitized_url = sanitize_filename(url)
        qr_image_name = f"{sanitized_url}_qr.png"
        if url:
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10,
                    border=4,
                )
                qr.add_data(url)
                qr.make(fit=True)

                img = qr.make_image(fill='black', back_color='white')
                img.save(f"{qr_image_name}")

                messagebox.showinfo("QR Code", f"QR Code has been generated for your url at {os.getcwd()}")
            except Exception as e:
                messagebox.showerror("Error", e)

    
    def encrypt_directory(self):
        dir_path = filedialog.askdirectory()
        try:
            if dir_path:
                for file_name in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file_name)
                    if os.path.isfile(file_path):
                        self.encrypt_file(file_path)
            messagebox.showinfo("Files Encrypted", "The selected folder has been encrypted!")

        except NotADirectoryError:
            messagebox.showerror("Error", "Please select a valid directory!")

    def decrypt_directory(self):
        dir_path = filedialog.askdirectory()
        try:
            if dir_path:
                for file_name in os.listdir(dir_path):
                    file_path = os.path.join(dir_path, file_name)
                    if os.path.isfile(file_path):
                        self.decrypt_file(file_path)
            messagebox.showinfo("Files Decrypted", "The selected folder has been decrypted!")

        except NotADirectoryError:
            messagebox.showerror("Error", "Please select a valid directory!")

    def encrypt_file(self, file_path = None):
        if file_path is None:
            file_path = filedialog.askopenfilename()
        if file_path:
            # Generate a key for this file
            key = Fernet.generate_key()
            fernet = Fernet(key)

            # Encrypt the file
            with open(file_path, 'rb') as file:
                original = file.read()

            encrypted = fernet.encrypt(original)

            with open(file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

            # Store the key
            self.keys[file_path] = key.decode()  # Store the key as a string
            with open(KEY_FILE, 'w') as f:
                json.dump(self.keys, f)

            messagebox.showinfo("File Encrypted", "The selected file has been encrypted!")

    def decrypt_file(self, file_path = None):
        if file_path is None:
            file_path = filedialog.askopenfilename()
        if file_path:
            # Retrieve the key
            if file_path in self.keys:
                key = self.keys[file_path].encode()  # Convert the key back to bytes
            else:
                messagebox.showinfo("Error", "No key found for this file.")
                return

            fernet = Fernet(key)

            # Decrypt the file
            with open(file_path, 'rb') as enc_file:
                encrypted = enc_file.read()

            try:
                decrypted = fernet.decrypt(encrypted)
            except:
                messagebox.showinfo("Error", "Decryption failed.")
                return

            with open(file_path, 'wb') as dec_file:
                dec_file.write(decrypted)

            messagebox.showinfo("File Decrypted", "The selected file has been decrypted!")

root = Tk()
my_gui = EncryptionApp(root)
root.geometry('400x290')
root.iconbitmap('logo.ico')
root.resizable(False, False)
root.mainloop()
