import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.fernet import Fernet

import crypter_core as core


def test_file_password_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "plain.txt"
    source.write_text("hello stable encryption", encoding="utf-8")

    encrypted = core.encrypt_file(source, password="correct horse", compression=True)
    decrypted = core.decrypt_file(encrypted.output_path, password="correct horse")

    assert decrypted.output_path.read_text(encoding="utf-8") == "hello stable encryption"
    assert source.read_text(encoding="utf-8") == "hello stable encryption"


def test_text_round_trip() -> None:
    token = core.encrypt_text(
        "text secret",
        password="passphrase",
        algorithm=core.CHACHA20_POLY1305,
    )

    assert token.startswith(core.TEXT_PREFIX)
    assert core.decrypt_text(token, password="passphrase") == "text secret"


def test_wrong_password_rejected(tmp_path: Path) -> None:
    source = tmp_path / "plain.txt"
    source.write_text("protected", encoding="utf-8")
    encrypted = core.encrypt_file(source, password="right")

    with pytest.raises(core.WrongPasswordOrKeyError):
        core.decrypt_file(encrypted.output_path, password="wrong")


def test_key_file_round_trip(tmp_path: Path) -> None:
    key_file = core.save_key_file(tmp_path / "recovery.crypterkey")
    source = tmp_path / "image.bin"
    source.write_bytes(b"\x00\x01\x02" * 128)

    encrypted = core.encrypt_file(source, key_file=key_file)
    decrypted = core.decrypt_file(encrypted.output_path, key_file=key_file)

    assert decrypted.output_path.read_bytes() == source.read_bytes()


def test_directory_round_trip(tmp_path: Path) -> None:
    source_dir = tmp_path / "docs"
    nested = source_dir / "nested"
    nested.mkdir(parents=True)
    (source_dir / "a.txt").write_text("alpha", encoding="utf-8")
    (nested / "b.txt").write_text("beta", encoding="utf-8")

    encrypted = core.encrypt_directory(source_dir, password="folder password")
    restored = core.decrypt_directory(encrypted.output_path, password="folder password")

    assert (restored.output_path / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (restored.output_path / "nested" / "b.txt").read_text(encoding="utf-8") == "beta"


def test_legacy_fernet_recovery(tmp_path: Path) -> None:
    source = tmp_path / "old.txt"
    source.write_bytes(b"legacy secret")
    file_key = Fernet.generate_key()
    encrypted = Fernet(file_key).encrypt(source.read_bytes())
    source.write_bytes(encrypted)

    key_store = {
        str(source): {
            "key": file_key.decode("ascii"),
            "encrypted": encrypted.decode("ascii"),
        }
    }
    key_store_path = tmp_path / "keys.json"
    key_store_path.write_bytes(
        Fernet(core.LEGACY_MASTER_KEY).encrypt(json.dumps(key_store).encode("utf-8"))
    )

    recovered = core.decrypt_legacy_file(source, key_store_path)

    assert recovered.output_path.read_bytes() == b"legacy secret"
