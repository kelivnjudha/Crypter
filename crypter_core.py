#!/usr/bin/env python3
"""Core encryption logic for Crypter v2.

The module is intentionally independent from any GUI framework so it can be
tested, scripted, and reused by the desktop app.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import struct
import tempfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Dict, Iterable, Optional, Tuple
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


MAGIC = b"CRYPTER2\n"
TEXT_PREFIX = "crypter2:"
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024
RAW_KEY_BYTES = 32
LEGACY_MASTER_KEY = b"pHU06D7jwltszEqKvKBFUtB2sXOJntqSDlv1XYhaLeE="
DEFAULT_LEGACY_KEY_STORE = Path("legacy") / "keys.json"

AES_256_GCM = "AES-256-GCM"
CHACHA20_POLY1305 = "CHACHA20-POLY1305"
SUPPORTED_ALGORITHMS = {AES_256_GCM, CHACHA20_POLY1305}


class CrypterError(Exception):
    """Base exception for expected Crypter failures."""


class CrypterDependencyError(CrypterError):
    """Raised when a required third-party package is missing."""


class UnsupportedFormatError(CrypterError):
    """Raised when data is not a supported Crypter format."""


class WrongPasswordOrKeyError(CrypterError):
    """Raised when authentication fails during decryption."""


class OutputExistsError(CrypterError):
    """Raised when the target path exists and overwrite is disabled."""


@dataclass(frozen=True)
class OperationResult:
    input_path: Optional[Path]
    output_path: Optional[Path]
    header: Dict[str, object]
    bytes_read: int = 0
    bytes_written: int = 0


ProgressCallback = Optional[Callable[[int, int], None]]


def _require_crypto():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise CrypterDependencyError(
            "Missing dependency: install requirements with "
            "`python -m pip install -r requirements.txt`."
        ) from exc

    return {
        "InvalidTag": InvalidTag,
        "InvalidToken": InvalidToken,
        "Fernet": Fernet,
        "hashes": hashes,
        "Cipher": Cipher,
        "algorithms": algorithms,
        "modes": modes,
        "ChaCha20Poly1305": ChaCha20Poly1305,
        "PBKDF2HMAC": PBKDF2HMAC,
        "Scrypt": Scrypt,
    }


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def normalize_algorithm(name: str) -> str:
    normalized = name.strip().upper().replace("_", "-")
    aliases = {
        "AES": AES_256_GCM,
        "AES-GCM": AES_256_GCM,
        "AES-256-GCM": AES_256_GCM,
        "CHACHA": CHACHA20_POLY1305,
        "CHACHA20": CHACHA20_POLY1305,
        "CHACHA20-POLY1305": CHACHA20_POLY1305,
    }
    algorithm = aliases.get(normalized)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise CrypterError(f"Unsupported algorithm: {name}")
    return algorithm


def available_path(path: Path) -> Path:
    """Return a non-existing sibling path without deleting anything."""

    path = Path(path)
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for index in range(1, 1000):
        candidate = parent / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
    raise OutputExistsError(f"Could not find an available output path near {path}")


def _prepare_output(path: Path, overwrite: bool) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if overwrite:
            return path
        return available_path(path)
    return path


def _temp_output_path(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=str(output_path.parent)
    )
    os.close(handle)
    return Path(temp_name)


def _replace_output(temp_path: Path, output_path: Path) -> None:
    os.replace(str(temp_path), str(output_path))


def _json_bytes(header: Dict[str, object]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_envelope_header(handle: BinaryIO, header: Dict[str, object]) -> bytes:
    header_bytes = _json_bytes(header)
    handle.write(MAGIC)
    handle.write(struct.pack(">I", len(header_bytes)))
    handle.write(header_bytes)
    return header_bytes


def _read_envelope_header(handle: BinaryIO) -> Tuple[Dict[str, object], bytes, int]:
    magic = handle.read(len(MAGIC))
    if magic != MAGIC:
        raise UnsupportedFormatError("Not a Crypter v2 encrypted file.")

    raw_len = handle.read(4)
    if len(raw_len) != 4:
        raise UnsupportedFormatError("Encrypted file header is truncated.")

    header_len = struct.unpack(">I", raw_len)[0]
    if header_len <= 0 or header_len > 1024 * 1024:
        raise UnsupportedFormatError("Encrypted file header length is invalid.")

    header_bytes = handle.read(header_len)
    if len(header_bytes) != header_len:
        raise UnsupportedFormatError("Encrypted file header is incomplete.")

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise UnsupportedFormatError("Encrypted file header is not valid JSON.") from exc

    return header, header_bytes, len(MAGIC) + 4 + header_len


def read_header(path: str | os.PathLike[str]) -> Dict[str, object]:
    with Path(path).open("rb") as handle:
        header, _, _ = _read_envelope_header(handle)
        return header


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _password_bytes(password: str | bytes) -> bytes:
    if isinstance(password, bytes):
        data = password
    else:
        data = password.encode("utf-8")
    if not data:
        raise CrypterError("Password cannot be empty.")
    return data


def _new_kdf_header(kdf_name: str = "scrypt") -> Dict[str, object]:
    salt = os.urandom(16)
    if kdf_name == "scrypt":
        return {
            "name": "scrypt",
            "salt": _b64e(salt),
            "length": RAW_KEY_BYTES,
            "n": 2**14,
            "r": 8,
            "p": 1,
        }
    if kdf_name == "pbkdf2-sha256":
        return {
            "name": "pbkdf2-sha256",
            "salt": _b64e(salt),
            "length": RAW_KEY_BYTES,
            "iterations": 390000,
        }
    raise CrypterError(f"Unsupported KDF: {kdf_name}")


def _derive_key(password: str | bytes, kdf_header: Dict[str, object]) -> bytes:
    crypto = _require_crypto()
    salt = _b64d(str(kdf_header["salt"]))
    length = int(kdf_header.get("length", RAW_KEY_BYTES))
    name = str(kdf_header["name"]).lower()

    if name == "scrypt":
        kdf = crypto["Scrypt"](
            salt=salt,
            length=length,
            n=int(kdf_header["n"]),
            r=int(kdf_header["r"]),
            p=int(kdf_header["p"]),
        )
        return kdf.derive(_password_bytes(password))

    if name == "pbkdf2-sha256":
        kdf = crypto["PBKDF2HMAC"](
            algorithm=crypto["hashes"].SHA256(),
            length=length,
            salt=salt,
            iterations=int(kdf_header["iterations"]),
        )
        return kdf.derive(_password_bytes(password))

    raise CrypterError(f"Unsupported KDF: {name}")


def generate_raw_key() -> str:
    """Generate a portable 256-bit key for raw key mode."""

    return _b64e(os.urandom(RAW_KEY_BYTES))


def save_key_file(
    path: str | os.PathLike[str],
    key: Optional[str] = None,
    *,
    overwrite: bool = False,
) -> Path:
    output_path = Path(path)
    if output_path.exists() and not overwrite:
        raise OutputExistsError(f"Key file already exists: {output_path}")
    key = key or generate_raw_key()
    payload = {
        "format": "crypter-key",
        "version": 2,
        "created_utc": _utc_now(),
        "key": key,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _temp_output_path(output_path)
    try:
        temp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        _replace_output(temp_path, output_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return output_path


def load_key_file(path: str | os.PathLike[str]) -> bytes:
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        payload = json.loads(text)
        key_text = str(payload["key"])
    except json.JSONDecodeError:
        key_text = text
    key = _b64d(key_text)
    if len(key) != RAW_KEY_BYTES:
        raise CrypterError("Raw key file must contain a 256-bit key.")
    return key


def _resolve_key(
    *,
    header: Dict[str, object],
    password: Optional[str | bytes],
    raw_key: Optional[bytes],
) -> bytes:
    key_info = header.get("key")
    if not isinstance(key_info, dict):
        raise UnsupportedFormatError("Encrypted data has no key information.")

    mode = str(key_info.get("mode", "")).lower()
    if mode == "password":
        if password is None:
            raise CrypterError("Password is required for this encrypted data.")
        kdf_header = key_info.get("kdf")
        if not isinstance(kdf_header, dict):
            raise UnsupportedFormatError("Encrypted data has no KDF information.")
        return _derive_key(password, kdf_header)

    if mode == "raw-key":
        if raw_key is None:
            raise CrypterError("Raw key file is required for this encrypted data.")
        if len(raw_key) != RAW_KEY_BYTES:
            raise CrypterError("Raw key must be 256 bits.")
        return raw_key

    raise UnsupportedFormatError(f"Unsupported key mode: {mode}")


def _new_header(
    *,
    algorithm: str,
    key_mode: str,
    password_kdf: str,
    raw_key: Optional[bytes],
    data_type: str,
    original_name: Optional[str],
    original_size: Optional[int],
    compression: bool,
    extra_metadata: Optional[Dict[str, object]] = None,
) -> Tuple[Dict[str, object], bytes]:
    algorithm = normalize_algorithm(algorithm)
    nonce_size = 12
    header: Dict[str, object] = {
        "format": "crypter-v2",
        "version": 2,
        "created_utc": _utc_now(),
        "algorithm": algorithm,
        "nonce": _b64e(os.urandom(nonce_size)),
        "data_type": data_type,
        "compression": "zlib" if compression else "none",
    }
    if original_name is not None:
        header["original_name"] = original_name
    if original_size is not None:
        header["original_size"] = original_size
    if extra_metadata:
        header.update(extra_metadata)

    if key_mode == "password":
        header["key"] = {"mode": "password", "kdf": _new_kdf_header(password_kdf)}
        key = b""
    elif key_mode == "raw-key":
        if raw_key is None:
            raise CrypterError("Raw key mode requires a key.")
        if len(raw_key) != RAW_KEY_BYTES:
            raise CrypterError("Raw key must be 256 bits.")
        header["key"] = {"mode": "raw-key"}
        key = raw_key
    else:
        raise CrypterError(f"Unsupported key mode: {key_mode}")

    return header, key


def _encrypt_bytes_with_header(
    plaintext: bytes,
    header: Dict[str, object],
    key: bytes,
    *,
    password: Optional[str | bytes],
) -> bytes:
    crypto = _require_crypto()
    if not key:
        key = _resolve_key(header=header, password=password, raw_key=None)

    header_bytes = _json_bytes(header)
    compressed = header.get("compression") == "zlib"
    payload = zlib.compress(plaintext) if compressed else plaintext
    algorithm = normalize_algorithm(str(header["algorithm"]))
    nonce = _b64d(str(header["nonce"]))

    if algorithm == AES_256_GCM:
        encryptor = crypto["Cipher"](
            crypto["algorithms"].AES(key), crypto["modes"].GCM(nonce)
        ).encryptor()
        encryptor.authenticate_additional_data(header_bytes)
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        body = ciphertext + encryptor.tag
    elif algorithm == CHACHA20_POLY1305:
        body = crypto["ChaCha20Poly1305"](key).encrypt(nonce, payload, header_bytes)
    else:
        raise CrypterError(f"Unsupported algorithm: {algorithm}")

    return MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + body


def _decrypt_envelope_bytes(
    envelope: bytes,
    *,
    password: Optional[str | bytes],
    raw_key: Optional[bytes],
) -> Tuple[bytes, Dict[str, object]]:
    crypto = _require_crypto()
    if not envelope.startswith(MAGIC):
        raise UnsupportedFormatError("Not a Crypter v2 token.")
    header_len_offset = len(MAGIC)
    header_len = struct.unpack(">I", envelope[header_len_offset : header_len_offset + 4])[0]
    header_start = header_len_offset + 4
    header_end = header_start + header_len
    header_bytes = envelope[header_start:header_end]
    body = envelope[header_end:]
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise UnsupportedFormatError("Encrypted token header is not valid JSON.") from exc

    key = _resolve_key(header=header, password=password, raw_key=raw_key)
    algorithm = normalize_algorithm(str(header["algorithm"]))
    nonce = _b64d(str(header["nonce"]))

    try:
        if algorithm == AES_256_GCM:
            if len(body) < TAG_SIZE:
                raise UnsupportedFormatError("Encrypted token is truncated.")
            ciphertext, tag = body[:-TAG_SIZE], body[-TAG_SIZE:]
            decryptor = crypto["Cipher"](
                crypto["algorithms"].AES(key), crypto["modes"].GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header_bytes)
            payload = decryptor.update(ciphertext) + decryptor.finalize()
        elif algorithm == CHACHA20_POLY1305:
            payload = crypto["ChaCha20Poly1305"](key).decrypt(nonce, body, header_bytes)
        else:
            raise CrypterError(f"Unsupported algorithm: {algorithm}")
    except crypto["InvalidTag"] as exc:
        raise WrongPasswordOrKeyError("Wrong password/key or encrypted data was modified.") from exc

    if header.get("compression") == "zlib":
        payload = zlib.decompress(payload)
    return payload, header


def encrypt_text(
    text: str,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
    algorithm: str = AES_256_GCM,
    key_mode: str = "password",
    password_kdf: str = "scrypt",
    compression: bool = False,
) -> str:
    if key_mode == "password" and password is None:
        raise CrypterError("Password is required.")
    header, key = _new_header(
        algorithm=algorithm,
        key_mode=key_mode,
        password_kdf=password_kdf,
        raw_key=raw_key,
        data_type="text",
        original_name=None,
        original_size=len(text.encode("utf-8")),
        compression=compression,
    )
    envelope = _encrypt_bytes_with_header(text.encode("utf-8"), header, key, password=password)
    return TEXT_PREFIX + _b64e(envelope)


def decrypt_text(
    token: str,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
) -> str:
    token = token.strip()
    if token.startswith(TEXT_PREFIX):
        token = token[len(TEXT_PREFIX) :]
    envelope = _b64d(token)
    plaintext, header = _decrypt_envelope_bytes(envelope, password=password, raw_key=raw_key)
    if header.get("data_type") != "text":
        raise UnsupportedFormatError("This token is not encrypted text.")
    return plaintext.decode("utf-8")


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: Optional[str | os.PathLike[str]] = None,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
    key_file: Optional[str | os.PathLike[str]] = None,
    algorithm: str = AES_256_GCM,
    key_mode: str = "password",
    password_kdf: str = "scrypt",
    compression: bool = False,
    overwrite: bool = False,
    data_type: str = "file",
    original_name: Optional[str] = None,
    extra_metadata: Optional[Dict[str, object]] = None,
    progress: ProgressCallback = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> OperationResult:
    crypto = _require_crypto()
    input_path = Path(input_path)
    if not input_path.is_file():
        raise CrypterError(f"Input file does not exist: {input_path}")

    if key_file is not None:
        raw_key = load_key_file(key_file)
        key_mode = "raw-key"
    if key_mode == "password" and password is None:
        raise CrypterError("Password is required.")

    if output_path is None:
        output_path = input_path.with_name(input_path.name + ".crypter")
    output_path = _prepare_output(Path(output_path), overwrite)
    if input_path.resolve() == output_path.resolve():
        raise CrypterError("Input and output paths must be different.")

    total_size = input_path.stat().st_size
    header, key = _new_header(
        algorithm=algorithm,
        key_mode=key_mode,
        password_kdf=password_kdf,
        raw_key=raw_key,
        data_type=data_type,
        original_name=original_name or input_path.name,
        original_size=total_size,
        compression=compression,
        extra_metadata=extra_metadata,
    )
    if not key:
        key = _resolve_key(header=header, password=password, raw_key=None)

    algorithm = normalize_algorithm(str(header["algorithm"]))
    nonce = _b64d(str(header["nonce"]))
    temp_path = _temp_output_path(output_path)
    bytes_read = 0
    bytes_written = 0

    try:
        if algorithm == CHACHA20_POLY1305:
            data = input_path.read_bytes()
            payload = zlib.compress(data) if compression else data
            with temp_path.open("wb") as out_handle:
                header_bytes = _write_envelope_header(out_handle, header)
                body = crypto["ChaCha20Poly1305"](key).encrypt(nonce, payload, header_bytes)
                out_handle.write(body)
                bytes_read = len(data)
                bytes_written = out_handle.tell()
        else:
            with input_path.open("rb") as in_handle, temp_path.open("wb") as out_handle:
                header_bytes = _write_envelope_header(out_handle, header)
                encryptor = crypto["Cipher"](
                    crypto["algorithms"].AES(key), crypto["modes"].GCM(nonce)
                ).encryptor()
                encryptor.authenticate_additional_data(header_bytes)
                compressor = zlib.compressobj(level=6) if compression else None

                while True:
                    chunk = in_handle.read(chunk_size)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    if compressor is not None:
                        chunk = compressor.compress(chunk)
                    if chunk:
                        out_handle.write(encryptor.update(chunk))
                    if progress:
                        progress(bytes_read, total_size)

                if compressor is not None:
                    tail = compressor.flush()
                    if tail:
                        out_handle.write(encryptor.update(tail))
                out_handle.write(encryptor.finalize())
                out_handle.write(encryptor.tag)
                bytes_written = out_handle.tell()

        _replace_output(temp_path, output_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return OperationResult(input_path, output_path, header, bytes_read, bytes_written)


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: Optional[str | os.PathLike[str]] = None,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
    key_file: Optional[str | os.PathLike[str]] = None,
    overwrite: bool = False,
    progress: ProgressCallback = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> OperationResult:
    crypto = _require_crypto()
    input_path = Path(input_path)
    if not input_path.is_file():
        raise CrypterError(f"Input file does not exist: {input_path}")
    if key_file is not None:
        raw_key = load_key_file(key_file)

    with input_path.open("rb") as in_handle:
        header, header_bytes, data_offset = _read_envelope_header(in_handle)

    if output_path is None:
        original_name = str(header.get("original_name") or input_path.stem)
        output_path = input_path.with_name(original_name)
    output_path = _prepare_output(Path(output_path), overwrite)
    if input_path.resolve() == output_path.resolve():
        raise CrypterError("Input and output paths must be different.")

    key = _resolve_key(header=header, password=password, raw_key=raw_key)
    algorithm = normalize_algorithm(str(header["algorithm"]))
    nonce = _b64d(str(header["nonce"]))
    compressed = header.get("compression") == "zlib"
    total_body = input_path.stat().st_size - data_offset
    if total_body < TAG_SIZE:
        raise UnsupportedFormatError("Encrypted file is truncated.")

    temp_path = _temp_output_path(output_path)
    bytes_read = 0
    bytes_written = 0

    try:
        if algorithm == CHACHA20_POLY1305:
            with input_path.open("rb") as in_handle:
                in_handle.seek(data_offset)
                body = in_handle.read()
            try:
                payload = crypto["ChaCha20Poly1305"](key).decrypt(nonce, body, header_bytes)
            except crypto["InvalidTag"] as exc:
                raise WrongPasswordOrKeyError(
                    "Wrong password/key or encrypted file was modified."
                ) from exc
            if compressed:
                payload = zlib.decompress(payload)
            temp_path.write_bytes(payload)
            bytes_read = len(body)
            bytes_written = len(payload)
        else:
            ciphertext_len = total_body - TAG_SIZE
            with input_path.open("rb") as tag_handle:
                tag_handle.seek(data_offset + ciphertext_len)
                tag = tag_handle.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise UnsupportedFormatError("Encrypted file authentication tag is missing.")

            decryptor = crypto["Cipher"](
                crypto["algorithms"].AES(key), crypto["modes"].GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header_bytes)
            decompressor = zlib.decompressobj() if compressed else None

            with input_path.open("rb") as in_handle, temp_path.open("wb") as out_handle:
                in_handle.seek(data_offset)
                remaining = ciphertext_len
                while remaining:
                    chunk = in_handle.read(min(chunk_size, remaining))
                    if not chunk:
                        raise UnsupportedFormatError("Encrypted file body is truncated.")
                    remaining -= len(chunk)
                    bytes_read += len(chunk)
                    plain = decryptor.update(chunk)
                    if plain:
                        if decompressor is not None:
                            plain = decompressor.decompress(plain)
                        out_handle.write(plain)
                    if progress:
                        progress(bytes_read, ciphertext_len)

                try:
                    final = decryptor.finalize()
                except crypto["InvalidTag"] as exc:
                    raise WrongPasswordOrKeyError(
                        "Wrong password/key or encrypted file was modified."
                    ) from exc
                if decompressor is not None:
                    final = decompressor.decompress(final) + decompressor.flush()
                out_handle.write(final)
                bytes_written = out_handle.tell()

        _replace_output(temp_path, output_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return OperationResult(input_path, output_path, header, bytes_read, bytes_written)


def _iter_directory_entries(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        yield path


def _zip_directory(source_dir: Path, zip_path: Path) -> int:
    count = 0
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in _iter_directory_entries(source_dir):
            rel = path.relative_to(source_dir).as_posix()
            if path.is_dir():
                if not any(path.iterdir()):
                    info = ZipInfo(rel + "/")
                    archive.writestr(info, b"")
                    count += 1
            elif path.is_file():
                archive.write(path, rel)
                count += 1
    return count


def _safe_extract_zip(zip_path: Path, output_dir: Path) -> None:
    output_root = output_dir.resolve()
    with ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            target = (output_dir / member.filename).resolve()
            try:
                target.relative_to(output_root)
            except ValueError as exc:
                raise UnsupportedFormatError("Directory archive contains an unsafe path.") from exc
        archive.extractall(output_dir)


def encrypt_directory(
    directory_path: str | os.PathLike[str],
    output_path: Optional[str | os.PathLike[str]] = None,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
    key_file: Optional[str | os.PathLike[str]] = None,
    algorithm: str = AES_256_GCM,
    key_mode: str = "password",
    password_kdf: str = "scrypt",
    overwrite: bool = False,
    progress: ProgressCallback = None,
) -> OperationResult:
    directory_path = Path(directory_path)
    if not directory_path.is_dir():
        raise CrypterError(f"Directory does not exist: {directory_path}")
    if output_path is None:
        output_path = directory_path.with_name(directory_path.name + ".crypterdir")

    with tempfile.TemporaryDirectory(prefix="crypter-dir-") as temp_dir:
        archive_path = Path(temp_dir) / f"{directory_path.name}.zip"
        entry_count = _zip_directory(directory_path, archive_path)
        return encrypt_file(
            archive_path,
            output_path,
            password=password,
            raw_key=raw_key,
            key_file=key_file,
            algorithm=algorithm,
            key_mode=key_mode,
            password_kdf=password_kdf,
            compression=False,
            overwrite=overwrite,
            data_type="directory",
            original_name=directory_path.name,
            extra_metadata={"archive": "zip", "entry_count": entry_count},
            progress=progress,
        )


def decrypt_directory(
    input_path: str | os.PathLike[str],
    output_dir: Optional[str | os.PathLike[str]] = None,
    *,
    password: Optional[str | bytes] = None,
    raw_key: Optional[bytes] = None,
    key_file: Optional[str | os.PathLike[str]] = None,
    overwrite: bool = False,
    progress: ProgressCallback = None,
) -> OperationResult:
    input_path = Path(input_path)
    header = read_header(input_path)
    if header.get("data_type") != "directory":
        raise UnsupportedFormatError("Encrypted file is not a directory package.")

    if output_dir is None:
        output_dir = input_path.with_name(str(header.get("original_name") or input_path.stem))
    output_dir = Path(output_dir)
    if output_dir.exists() and not overwrite:
        output_dir = available_path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise OutputExistsError(f"Output directory is not empty: {output_dir}")

    with tempfile.TemporaryDirectory(prefix="crypter-open-dir-") as temp_dir:
        temp_dir_path = Path(temp_dir)
        archive_path = temp_dir_path / "archive.zip"
        result = decrypt_file(
            input_path,
            archive_path,
            password=password,
            raw_key=raw_key,
            key_file=key_file,
            overwrite=True,
            progress=progress,
        )
        extract_path = temp_dir_path / "extract"
        extract_path.mkdir()
        _safe_extract_zip(archive_path, extract_path)
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        if output_dir.exists():
            if not overwrite:
                raise OutputExistsError(f"Output directory already exists: {output_dir}")
            if any(output_dir.iterdir()):
                raise OutputExistsError(f"Output directory is not empty: {output_dir}")
            output_dir.rmdir()
        shutil.move(str(extract_path), str(output_dir))

    return OperationResult(input_path, output_dir, result.header, result.bytes_read, 0)


def load_legacy_key_store(
    path: str | os.PathLike[str] = DEFAULT_LEGACY_KEY_STORE,
) -> Dict[str, object]:
    crypto = _require_crypto()
    key_path = Path(path)
    if not key_path.exists():
        raise CrypterError(f"Legacy key store does not exist: {key_path}")
    raw = key_path.read_bytes()

    try:
        decrypted = crypto["Fernet"](LEGACY_MASTER_KEY).decrypt(raw)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise CrypterError("Could not read legacy keys.json.") from exc


def decrypt_legacy_file(
    input_path: str | os.PathLike[str],
    key_store_path: str | os.PathLike[str] = DEFAULT_LEGACY_KEY_STORE,
    output_path: Optional[str | os.PathLike[str]] = None,
    *,
    overwrite: bool = False,
) -> OperationResult:
    crypto = _require_crypto()
    input_path = Path(input_path)
    if not input_path.is_file():
        raise CrypterError(f"Input file does not exist: {input_path}")

    keys = load_legacy_key_store(key_store_path)
    candidates = [
        str(input_path),
        str(input_path.resolve()),
        os.path.normpath(str(input_path)),
        os.path.normpath(str(input_path.resolve())),
    ]
    record = None
    for candidate in candidates:
        if candidate in keys:
            record = keys[candidate]
            break
    if record is None:
        raise CrypterError("No legacy key entry found for this file path.")

    if isinstance(record, dict):
        key_text = str(record.get("key", ""))
        stored_encrypted = record.get("encrypted")
    else:
        key_text = str(record)
        stored_encrypted = None
    if not key_text:
        raise CrypterError("Legacy key entry is missing the file key.")

    encrypted = input_path.read_bytes()
    if stored_encrypted:
        try:
            stored_bytes = str(stored_encrypted).encode("utf-8")
            crypto["Fernet"](key_text.encode("utf-8")).decrypt(encrypted)
        except Exception:
            encrypted = stored_bytes

    try:
        decrypted = crypto["Fernet"](key_text.encode("utf-8")).decrypt(encrypted)
    except crypto["InvalidToken"] as exc:
        raise WrongPasswordOrKeyError("Legacy decryption failed.") from exc

    if output_path is None:
        output_path = input_path.with_name(input_path.name + ".legacy-decrypted")
    output_path = _prepare_output(Path(output_path), overwrite)
    temp_path = _temp_output_path(output_path)
    try:
        temp_path.write_bytes(decrypted)
        _replace_output(temp_path, output_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return OperationResult(input_path, output_path, {"format": "legacy-fernet"}, len(encrypted), len(decrypted))
