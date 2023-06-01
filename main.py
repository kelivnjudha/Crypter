import json
import tkinter as tk
import os
from tkinter import Tk, Button, filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken

json_key = b'pHU06D7jwltszEqKvKBFUtB2sXOJntqSDlv1XYhaLeE='
KEY_FILE = "keys.json"


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Encryption App')

        # Initialize Buttons
        self.init_buttons()

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
        self.encrypt_button = Button(root, text='Encrypt File', command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = Button(root, text='Decrypt File', command=self.decrypt_file)
        self.decrypt_button.pack()

        self.encrypt_dir_button = Button(root, text='Encrypt Directory', command=self.encrypt_directory)
        self.encrypt_dir_button.pack()

        self.decrypt_dir_button = Button(root, text='Decrypt Directory', command=self.decrypt_directory)
        self.decrypt_dir_button.pack()

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

    def encrypt_file(self):
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

    def decrypt_file(self):
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
root.geometry('600x400')
root.iconbitmap('logo.ico')
root.resizable(False, False)
root.mainloop()
