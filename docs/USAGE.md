# Crypter v2 Setup And Usage

This guide covers setup, desktop usage, CLI usage, legacy recovery, and testing.

## Requirements

- Python 3.10 or newer.
- Windows, macOS, or Linux with a working Python environment.
- Dependencies from `requirements.txt`.

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

## Desktop App

Start the GUI:

```bash
python crypter_v2.py
```

The compatibility launcher also starts v2:

```bash
python crypter_v1.2.py
```

### File Encryption

1. Open the `Files` tab.
2. Select the input file.
3. Optionally choose an output path. If you leave it blank, Crypter creates
   `filename.crypter`.
4. Choose `AES-256-GCM` or `CHACHA20-POLY1305`.
5. Use password mode or key-file mode.
6. Click `Encrypt File`.

Decryption uses the same tab. Select the encrypted `.crypter` file, enter the
same password or key file, then click `Decrypt File`.

### Directory Encryption

1. Open the `Directories` tab.
2. Select a folder to encrypt.
3. Optionally choose an output path. The recommended extension is
   `.crypterdir`.
4. Enter the password or choose a key file.
5. Click `Encrypt Directory`.

To decrypt, select the `.crypterdir` package, enter the same password or key
file, and click `Decrypt Directory Package`.

### Text Encryption

1. Open the `Text` tab.
2. Paste text into the input panel.
3. Enter the password or choose a key file.
4. Click `Encrypt Text`.

The output is a portable `crypter2:` token. To decrypt it, move the token to the
input panel, enter the same password or key file, then click `Decrypt Text`.

### Tools

The `Tools` tab includes:

- Key-file generation.
- Legacy v1.x recovery using `legacy/keys.json`.
- QR code generation.

## CLI Reference

Show all commands:

```bash
python crypter_v2.py --help
```

Show help for one command:

```bash
python crypter_v2.py encrypt-file --help
```

### Password Mode

If `--password` is omitted, Crypter prompts securely in the terminal.

```bash
python crypter_v2.py encrypt-file report.pdf
python crypter_v2.py decrypt-file report.pdf.crypter
```

You can pass a password directly for automation, but terminal history may store
the command:

```bash
python crypter_v2.py encrypt-file report.pdf --password "change-me"
```

### File Commands

Encrypt with compression:

```bash
python crypter_v2.py encrypt-file report.pdf --compress
```

Encrypt with ChaCha20-Poly1305:

```bash
python crypter_v2.py encrypt-file report.pdf --algorithm CHACHA20-POLY1305
```

Write to a specific output path:

```bash
python crypter_v2.py encrypt-file report.pdf -o safe-report.crypter
```

Decrypt to a specific output path:

```bash
python crypter_v2.py decrypt-file safe-report.crypter -o report-restored.pdf
```

Use `--overwrite` only when you intentionally want to replace an existing output
file.

### Directory Commands

Encrypt a directory package:

```bash
python crypter_v2.py encrypt-dir MyFolder -o MyFolder.crypterdir
```

Decrypt a directory package:

```bash
python crypter_v2.py decrypt-dir MyFolder.crypterdir -o MyFolder-restored
```

Directory encryption stores the folder as a zip archive inside the encrypted
package.

### Key-File Mode

Create a key file:

```bash
python crypter_v2.py make-key recovery.crypterkey
```

Encrypt and decrypt with it:

```bash
python crypter_v2.py encrypt-file report.pdf --key-file recovery.crypterkey
python crypter_v2.py decrypt-file report.pdf.crypter --key-file recovery.crypterkey
```

Back up key files carefully. If the key file is lost, Crypter cannot recover
the encrypted data.

### Text Commands

Encrypt text from an argument:

```bash
python crypter_v2.py encrypt-text --text "secret message"
```

Encrypt text from stdin:

```bash
echo secret message | python crypter_v2.py encrypt-text
```

Decrypt a token:

```bash
python crypter_v2.py decrypt-text "crypter2:..."
```

### Legacy Recovery

The old v1.x app stored file keys in `keys.json`. Those files now live in
`legacy/`.

Recover an old encrypted file:

```bash
python crypter_v2.py legacy-decrypt encrypted-file.ext --keys legacy/keys.json
```

If the old key entry used a different absolute file path, recovery may require
placing the file back at its original path or updating the legacy key store.
Use legacy recovery only for v1.x files. New v2 files do not use `keys.json`.

## Output Files

Default output naming:

- File encryption: `filename.crypter`
- Directory encryption: `foldername.crypterdir`
- Legacy recovery: `filename.legacy-decrypted`

If the default output path already exists, Crypter chooses a new sibling path
instead of overwriting. Use `--overwrite` only when replacement is intended.

## Development

Run syntax checks:

```bash
python -m compileall crypter_core.py crypter_v2.py crypter_v1.2.py tests
```

Run tests:

```bash
python -m pytest --basetemp .pytest-tmp
```

Remove test caches if needed:

```powershell
Remove-Item -LiteralPath .pytest-tmp,.pytest_cache,__pycache__,tests\__pycache__ -Recurse -Force -ErrorAction SilentlyContinue
```
