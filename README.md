# Crypter v2

Crypter v2 is a safer rebuild of the original Python encryption app. It keeps
the old v1.x files in `legacy/` for recovery, while new encryption uses
self-describing encrypted files so decryption no longer depends on a fragile
absolute path entry in `keys.json`.

## Highlights

- Password encryption by default with Scrypt key derivation.
- AES-256-GCM streaming encryption for stable large-file handling.
- ChaCha20-Poly1305 option for files and text.
- File, directory, and text encryption workflows.
- Atomic writes and new output files by default to reduce data-loss risk.
- Optional 256-bit key-file mode.
- Legacy recovery for old v1.x Fernet files using `legacy/keys.json`.
- PyQt5 desktop UI plus CLI commands.

## Setup

Use Python 3.10 or newer.

```bash
python -m pip install -r requirements.txt
```

For development and tests:

```bash
python -m pip install -r requirements-dev.txt
```

## Start The App

Launch the v2 desktop app:

```bash
python crypter_v2.py
```

The old root launcher still works and now opens v2:

```bash
python crypter_v1.2.py
```

## Quick CLI Usage

Encrypt a file with a password:

```bash
python crypter_v2.py encrypt-file report.pdf --compress
```

Decrypt a file:

```bash
python crypter_v2.py decrypt-file report.pdf.crypter
```

Encrypt a folder:

```bash
python crypter_v2.py encrypt-dir MyFolder -o MyFolder.crypterdir
```

Decrypt a folder package:

```bash
python crypter_v2.py decrypt-dir MyFolder.crypterdir
```

Create and use a key file:

```bash
python crypter_v2.py make-key recovery.crypterkey
python crypter_v2.py encrypt-file report.pdf --key-file recovery.crypterkey
python crypter_v2.py decrypt-file report.pdf.crypter --key-file recovery.crypterkey
```

Encrypt and decrypt text:

```bash
python crypter_v2.py encrypt-text --text "secret message"
python crypter_v2.py decrypt-text "crypter2:..."
```

Recover an old v1.x encrypted file:

```bash
python crypter_v2.py legacy-decrypt encrypted-file.ext --keys legacy/keys.json
```

See [docs/USAGE.md](docs/USAGE.md) for full setup, GUI, CLI, recovery, and
development instructions.

## Project Layout

- `crypter_v2.py`: v2 GUI and CLI entry point.
- `crypter_core.py`: reusable encryption/decryption engine.
- `crypter_v1.2.py`: compatibility launcher that starts v2.
- `legacy/`: original v1.x app files and old key store for recovery.
- `tests/`: core encryption and legacy recovery tests.

## Safety Notes

- Password mode has no key database to lose, but the password cannot be
  recovered if forgotten.
- Key-file mode requires backing up the `.crypterkey` file. Losing it means
  encrypted data cannot be decrypted.
- New file encryption writes `filename.crypter` by default and leaves the
  original file untouched.
- Keep `legacy/keys.json` only for v1.x recovery. It is not used for new v2
  encryption.

## Verification

```bash
python -m compileall crypter_core.py crypter_v2.py crypter_v1.2.py tests
python -m pytest --basetemp .pytest-tmp
```
