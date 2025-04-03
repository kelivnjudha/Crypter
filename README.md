# Crypter v1.2

Crypter is a robust desktop application that securely encrypts and decrypts files and directories using advanced encryption techniques. With a modern, PyQt5-based user interface featuring an integrated terminal for real-time, color-coded logs, and built-in QR code generation, Crypter provides an intuitive and powerful tool for protecting your data.

## Features

- **Advanced Encryption/Decryption**  
  - Uses Fernet symmetric encryption to protect files with a unique key for each file.
  - Stores both the encryption key and the full encrypted text in an encrypted JSON file for robust data recovery.
  - Implements a fuzzy matching recovery mechanism to restore files even if data is partially lost or altered.

- **Secure Key Storage**  
  - Encryption keys and encrypted content are stored persistently in an encrypted JSON file, ensuring data integrity across system restarts.

- **Modern PyQt5 GUI**  
  - Sleek and creative user interface with an integrated terminal window that displays color-coded log messages.
  - Custom application logo (`logo.ico`) is used throughout the app for a polished, professional look.

- **QR Code Generation**  
  - Generate and display QR codes from user-provided URLs.
  - Automatically saves QR codes with sanitized filenames.

- **Cross-Platform and Easy Deployment**  
  - Compatible with Python 3.10.11.
  - Easily compile to a standalone executable using PyInstaller.

## Installation

### Download from [release](https://github.com/kelivnjudha/Crypter/releases/tag/v1.2)

### From Source

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/Crypter.git
   cd Crypter
