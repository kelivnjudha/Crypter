# Crypter

This Python script implements a simple desktop application using the Tkinter library that allows a user to encrypt or decrypt files and directories. It also provides the functionality to generate QR codes from URLs. Here's a detailed description of the script's main components and functionalities:

1 Key Handling: The application uses symmetric encryption provided by the cryptography.fernet module. A separate key is generated for each file or directory that's encrypted. The keys are stored in a JSON file, with the file paths as the keys and the encryption keys as the values. The JSON file itself is encrypted using a master key json_key.

2 File and Directory Encryption/Decryption: The script provides functionality to encrypt or decrypt files and directories. When encrypting, a unique key is generated for each file, and the file's content is replaced with its encrypted form. When decrypting, the original key is retrieved from the JSON file, and the file's content is replaced with its decrypted form.

3 QR Code Generation: The script also provides the ability to generate QR codes from URLs. The user can enter a URL into a Tkinter Entry widget, and when they press the 'Generate' button, a QR code is generated and saved to a file named after the sanitized URL.

4 User Interface: The script uses Tkinter to provide a simple graphical user interface for the application. The user can choose to encrypt or decrypt a file or directory by pressing the appropriate button. They can also generate a QR code for a URL by entering the URL into a text box and pressing the 'Generate' button. All buttons and labels are customized with a certain style, and the overall layout of the application is grid-based for easy use and understanding.

5 Error Handling: The script includes error handling for several scenarios, such as when a file or directory doesn't exist, if no key is found for a file during decryption, or if decryption fails.

6 This script is an excellent starting point for understanding file encryption and decryption, as well as QR code generation and the development of GUIs in Python

## Download

Download from [release](https://github.com/kelivnjudha/Crypter/releases/tag/v1.1)
. If QR Generater doesn't work, Please run the app as administrator.

## Install from source

```
git clone https://github.com/kelivnjudha/Crypter.git
cd Crypter
pip install qrcode[pil]
pip install tkinter
python3 main.py
```
