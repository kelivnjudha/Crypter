#!/usr/bin/env python3
"""Crypter v2 desktop app and command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

import crypter_core as core


APP_TITLE = "Crypter v2"


def _read_password(args: argparse.Namespace, *, confirm: bool = False) -> Optional[str]:
    if getattr(args, "key_file", None):
        return None
    password = getattr(args, "password", None)
    if password is None:
        password = getpass.getpass("Password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if password != again:
            raise core.CrypterError("Passwords do not match.")
    return password


def _print_result(result: core.OperationResult) -> None:
    if result.output_path is not None:
        print(f"Output: {result.output_path}")
    if result.header:
        print(f"Format: {result.header.get('format', 'unknown')}")
        print(f"Type: {result.header.get('data_type', 'file')}")
        print(f"Algorithm: {result.header.get('algorithm', 'legacy')}")


def _cmd_encrypt_file(args: argparse.Namespace) -> None:
    result = core.encrypt_file(
        args.input,
        args.output,
        password=_read_password(args, confirm=True),
        key_file=args.key_file,
        algorithm=args.algorithm,
        compression=args.compress,
        overwrite=args.overwrite,
    )
    _print_result(result)


def _cmd_decrypt_file(args: argparse.Namespace) -> None:
    result = core.decrypt_file(
        args.input,
        args.output,
        password=_read_password(args),
        key_file=args.key_file,
        overwrite=args.overwrite,
    )
    _print_result(result)


def _cmd_encrypt_dir(args: argparse.Namespace) -> None:
    result = core.encrypt_directory(
        args.input,
        args.output,
        password=_read_password(args, confirm=True),
        key_file=args.key_file,
        algorithm=args.algorithm,
        overwrite=args.overwrite,
    )
    _print_result(result)


def _cmd_decrypt_dir(args: argparse.Namespace) -> None:
    result = core.decrypt_directory(
        args.input,
        args.output,
        password=_read_password(args),
        key_file=args.key_file,
        overwrite=args.overwrite,
    )
    _print_result(result)


def _cmd_encrypt_text(args: argparse.Namespace) -> None:
    text = args.text if args.text is not None else sys.stdin.read()
    token = core.encrypt_text(
        text,
        password=_read_password(args, confirm=True),
        raw_key=core.load_key_file(args.key_file) if args.key_file else None,
        key_mode="raw-key" if args.key_file else "password",
        algorithm=args.algorithm,
        compression=args.compress,
    )
    print(token)


def _cmd_decrypt_text(args: argparse.Namespace) -> None:
    token = args.token if args.token is not None else sys.stdin.read()
    text = core.decrypt_text(
        token,
        password=_read_password(args),
        raw_key=core.load_key_file(args.key_file) if args.key_file else None,
    )
    print(text)


def _cmd_make_key(args: argparse.Namespace) -> None:
    path = core.save_key_file(args.output, overwrite=args.overwrite)
    print(f"Key file created: {path}")


def _cmd_legacy_decrypt(args: argparse.Namespace) -> None:
    result = core.decrypt_legacy_file(
        args.input,
        args.keys,
        args.output,
        overwrite=args.overwrite,
    )
    _print_result(result)


def _add_common_encrypt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--algorithm", default=core.AES_256_GCM, choices=sorted(core.SUPPORTED_ALGORITHMS))
    parser.add_argument("--password", help="Password to use. Omit to be prompted securely.")
    parser.add_argument("--key-file", help="Use a 256-bit Crypter key file instead of a password.")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output path.")


def _add_common_decrypt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--password", help="Password to use. Omit to be prompted securely.")
    parser.add_argument("--key-file", help="Use a 256-bit Crypter key file instead of a password.")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output path.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crypter v2 encryption utility")
    subparsers = parser.add_subparsers(dest="command")

    encrypt_file = subparsers.add_parser("encrypt-file", help="Encrypt one file")
    encrypt_file.add_argument("input")
    encrypt_file.add_argument("-o", "--output")
    encrypt_file.add_argument("--compress", action="store_true")
    _add_common_encrypt_args(encrypt_file)
    encrypt_file.set_defaults(func=_cmd_encrypt_file)

    decrypt_file = subparsers.add_parser("decrypt-file", help="Decrypt one file")
    decrypt_file.add_argument("input")
    decrypt_file.add_argument("-o", "--output")
    _add_common_decrypt_args(decrypt_file)
    decrypt_file.set_defaults(func=_cmd_decrypt_file)

    encrypt_dir = subparsers.add_parser("encrypt-dir", help="Zip and encrypt a directory")
    encrypt_dir.add_argument("input")
    encrypt_dir.add_argument("-o", "--output")
    _add_common_encrypt_args(encrypt_dir)
    encrypt_dir.set_defaults(func=_cmd_encrypt_dir)

    decrypt_dir = subparsers.add_parser("decrypt-dir", help="Decrypt and extract a directory package")
    decrypt_dir.add_argument("input")
    decrypt_dir.add_argument("-o", "--output")
    _add_common_decrypt_args(decrypt_dir)
    decrypt_dir.set_defaults(func=_cmd_decrypt_dir)

    encrypt_text = subparsers.add_parser("encrypt-text", help="Encrypt text from --text or stdin")
    encrypt_text.add_argument("--text")
    encrypt_text.add_argument("--compress", action="store_true")
    _add_common_encrypt_args(encrypt_text)
    encrypt_text.set_defaults(func=_cmd_encrypt_text)

    decrypt_text = subparsers.add_parser("decrypt-text", help="Decrypt text token from argument or stdin")
    decrypt_text.add_argument("token", nargs="?")
    _add_common_decrypt_args(decrypt_text)
    decrypt_text.set_defaults(func=_cmd_decrypt_text)

    make_key = subparsers.add_parser("make-key", help="Create a raw key file")
    make_key.add_argument("output")
    make_key.add_argument("--overwrite", action="store_true")
    make_key.set_defaults(func=_cmd_make_key)

    legacy = subparsers.add_parser("legacy-decrypt", help="Decrypt files from the old Fernet keys.json format")
    legacy.add_argument("input")
    legacy.add_argument("-o", "--output")
    legacy.add_argument("--keys", default=str(core.DEFAULT_LEGACY_KEY_STORE))
    legacy.add_argument("--overwrite", action="store_true")
    legacy.set_defaults(func=_cmd_legacy_decrypt)

    subparsers.add_parser("gui", help="Launch the PyQt desktop app").set_defaults(func=lambda _: run_gui())
    return parser


def run_gui() -> None:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
    except ImportError as exc:
        raise core.CrypterDependencyError(
            "PyQt5 is not installed. Run `python -m pip install -r requirements.txt`."
        ) from exc

    class CrypterWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle(APP_TITLE)
            if Path("logo.ico").exists():
                self.setWindowIcon(QtGui.QIcon("logo.ico"))
            self.resize(860, 620)
            self._build_ui()

        def _build_ui(self) -> None:
            central = QtWidgets.QWidget()
            root = QtWidgets.QVBoxLayout(central)
            self.tabs = QtWidgets.QTabWidget()
            root.addWidget(self.tabs)
            self._build_file_tab()
            self._build_directory_tab()
            self._build_text_tab()
            self._build_tools_tab()

            self.log = QtWidgets.QTextEdit()
            self.log.setReadOnly(True)
            self.log.setMinimumHeight(130)
            self.log.setFontFamily("Consolas")
            root.addWidget(self.log)
            self.setCentralWidget(central)

            self.setStyleSheet(
                """
                QMainWindow, QWidget { background: #f6f7f9; color: #1f2933; }
                QGroupBox { border: 1px solid #d5dbe3; border-radius: 6px; margin-top: 12px; padding: 12px; }
                QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
                QPushButton { background: #235789; color: white; border: 0; border-radius: 5px; padding: 8px 12px; }
                QPushButton:hover { background: #1d4a73; }
                QPushButton#secondary { background: #455a64; }
                QLineEdit, QTextEdit, QComboBox { background: white; border: 1px solid #ccd4dd; border-radius: 4px; padding: 6px; }
                QTabWidget::pane { border: 1px solid #d5dbe3; background: white; }
                """
            )

        def _path_row(
            self,
            layout: "QtWidgets.QGridLayout",
            row: int,
            label: str,
            line_edit: "QtWidgets.QLineEdit",
            browse_action: Callable[[], None],
        ) -> None:
            layout.addWidget(QtWidgets.QLabel(label), row, 0)
            layout.addWidget(line_edit, row, 1)
            button = QtWidgets.QPushButton("Browse")
            button.setObjectName("secondary")
            button.clicked.connect(browse_action)
            layout.addWidget(button, row, 2)

        def _crypto_box(self, *, include_confirm: bool, include_algorithm: bool = True) -> Dict[str, object]:
            box = QtWidgets.QGroupBox("Encryption Options")
            form = QtWidgets.QGridLayout(box)
            controls: Dict[str, object] = {"box": box}
            row = 0

            if include_algorithm:
                algorithm = QtWidgets.QComboBox()
                algorithm.addItems([core.AES_256_GCM, core.CHACHA20_POLY1305])
                form.addWidget(QtWidgets.QLabel("Algorithm"), row, 0)
                form.addWidget(algorithm, row, 1, 1, 2)
                controls["algorithm"] = algorithm
                row += 1

            mode = QtWidgets.QComboBox()
            mode.addItem("Password", "password")
            mode.addItem("Key file", "raw-key")
            form.addWidget(QtWidgets.QLabel("Key mode"), row, 0)
            form.addWidget(mode, row, 1, 1, 2)
            controls["mode"] = mode
            row += 1

            password = QtWidgets.QLineEdit()
            password.setEchoMode(QtWidgets.QLineEdit.Password)
            form.addWidget(QtWidgets.QLabel("Password"), row, 0)
            form.addWidget(password, row, 1, 1, 2)
            controls["password"] = password
            row += 1

            if include_confirm:
                confirm = QtWidgets.QLineEdit()
                confirm.setEchoMode(QtWidgets.QLineEdit.Password)
                form.addWidget(QtWidgets.QLabel("Confirm"), row, 0)
                form.addWidget(confirm, row, 1, 1, 2)
                controls["confirm"] = confirm
                row += 1

            key_file = QtWidgets.QLineEdit()
            key_button = QtWidgets.QPushButton("Browse")
            key_button.setObjectName("secondary")
            key_button.clicked.connect(lambda: self._browse_open(key_file, "Select Key File"))
            form.addWidget(QtWidgets.QLabel("Key file"), row, 0)
            form.addWidget(key_file, row, 1)
            form.addWidget(key_button, row, 2)
            controls["key_file"] = key_file
            return controls

        def _build_file_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            grid = QtWidgets.QGridLayout()
            self.file_input = QtWidgets.QLineEdit()
            self.file_output = QtWidgets.QLineEdit()
            self._path_row(grid, 0, "Input file", self.file_input, lambda: self._browse_open(self.file_input, "Select File"))
            self._path_row(grid, 1, "Output file", self.file_output, lambda: self._browse_save(self.file_output, "Select Output File"))
            layout.addLayout(grid)
            self.file_controls = self._crypto_box(include_confirm=True)
            self.file_compress = QtWidgets.QCheckBox("Compress before encryption")
            layout.addWidget(self.file_controls["box"])
            layout.addWidget(self.file_compress)
            row = QtWidgets.QHBoxLayout()
            enc = QtWidgets.QPushButton("Encrypt File")
            dec = QtWidgets.QPushButton("Decrypt File")
            enc.clicked.connect(self._encrypt_file)
            dec.clicked.connect(self._decrypt_file)
            row.addWidget(enc)
            row.addWidget(dec)
            row.addStretch()
            layout.addLayout(row)
            layout.addStretch()
            self.tabs.addTab(tab, "Files")

        def _build_directory_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            grid = QtWidgets.QGridLayout()
            self.dir_input = QtWidgets.QLineEdit()
            self.dir_output = QtWidgets.QLineEdit()
            grid.addWidget(QtWidgets.QLabel("Input folder/package"), 0, 0)
            grid.addWidget(self.dir_input, 0, 1)
            folder_button = QtWidgets.QPushButton("Folder")
            folder_button.setObjectName("secondary")
            folder_button.clicked.connect(self._browse_directory_or_file)
            file_button = QtWidgets.QPushButton("File")
            file_button.setObjectName("secondary")
            file_button.clicked.connect(lambda: self._browse_open(self.dir_input, "Select Directory Package"))
            browse_buttons = QtWidgets.QHBoxLayout()
            browse_buttons.addWidget(folder_button)
            browse_buttons.addWidget(file_button)
            grid.addLayout(browse_buttons, 0, 2)
            self._path_row(grid, 1, "Output", self.dir_output, lambda: self._browse_save(self.dir_output, "Select Output"))
            layout.addLayout(grid)
            self.dir_controls = self._crypto_box(include_confirm=True)
            layout.addWidget(self.dir_controls["box"])
            row = QtWidgets.QHBoxLayout()
            enc = QtWidgets.QPushButton("Encrypt Directory")
            dec = QtWidgets.QPushButton("Decrypt Directory Package")
            enc.clicked.connect(self._encrypt_directory)
            dec.clicked.connect(self._decrypt_directory)
            row.addWidget(enc)
            row.addWidget(dec)
            row.addStretch()
            layout.addLayout(row)
            layout.addStretch()
            self.tabs.addTab(tab, "Directories")

        def _build_text_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            self.text_input = QtWidgets.QTextEdit()
            self.text_output = QtWidgets.QTextEdit()
            self.text_output.setReadOnly(False)
            splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
            input_box = QtWidgets.QGroupBox("Input")
            input_layout = QtWidgets.QVBoxLayout(input_box)
            input_layout.addWidget(self.text_input)
            output_box = QtWidgets.QGroupBox("Output")
            output_layout = QtWidgets.QVBoxLayout(output_box)
            output_layout.addWidget(self.text_output)
            splitter.addWidget(input_box)
            splitter.addWidget(output_box)
            layout.addWidget(splitter)
            self.text_controls = self._crypto_box(include_confirm=True)
            self.text_compress = QtWidgets.QCheckBox("Compress before encryption")
            layout.addWidget(self.text_controls["box"])
            layout.addWidget(self.text_compress)
            row = QtWidgets.QHBoxLayout()
            enc = QtWidgets.QPushButton("Encrypt Text")
            dec = QtWidgets.QPushButton("Decrypt Text")
            swap = QtWidgets.QPushButton("Move Output To Input")
            swap.setObjectName("secondary")
            enc.clicked.connect(self._encrypt_text)
            dec.clicked.connect(self._decrypt_text)
            swap.clicked.connect(lambda: self.text_input.setPlainText(self.text_output.toPlainText()))
            row.addWidget(enc)
            row.addWidget(dec)
            row.addWidget(swap)
            row.addStretch()
            layout.addLayout(row)
            self.tabs.addTab(tab, "Text")

        def _build_tools_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)

            key_box = QtWidgets.QGroupBox("Key File")
            key_grid = QtWidgets.QGridLayout(key_box)
            self.key_output = QtWidgets.QLineEdit()
            self._path_row(key_grid, 0, "Save key as", self.key_output, lambda: self._browse_save(self.key_output, "Save Key File"))
            make_key = QtWidgets.QPushButton("Generate Key File")
            make_key.clicked.connect(self._generate_key_file)
            key_grid.addWidget(make_key, 1, 1)
            layout.addWidget(key_box)

            legacy_box = QtWidgets.QGroupBox("Legacy v1.x Recovery")
            legacy_grid = QtWidgets.QGridLayout(legacy_box)
            self.legacy_input = QtWidgets.QLineEdit()
            self.legacy_keys = QtWidgets.QLineEdit(str(core.DEFAULT_LEGACY_KEY_STORE))
            self.legacy_output = QtWidgets.QLineEdit()
            self._path_row(legacy_grid, 0, "Encrypted file", self.legacy_input, lambda: self._browse_open(self.legacy_input, "Select Legacy File"))
            self._path_row(legacy_grid, 1, "Key store", self.legacy_keys, lambda: self._browse_open(self.legacy_keys, "Select keys.json"))
            self._path_row(legacy_grid, 2, "Output file", self.legacy_output, lambda: self._browse_save(self.legacy_output, "Select Output File"))
            legacy_btn = QtWidgets.QPushButton("Decrypt Legacy File")
            legacy_btn.clicked.connect(self._decrypt_legacy)
            legacy_grid.addWidget(legacy_btn, 3, 1)
            layout.addWidget(legacy_box)

            qr_box = QtWidgets.QGroupBox("QR Code")
            qr_grid = QtWidgets.QGridLayout(qr_box)
            self.qr_input = QtWidgets.QLineEdit()
            self.qr_output = QtWidgets.QLineEdit()
            qr_grid.addWidget(QtWidgets.QLabel("Text or URL"), 0, 0)
            qr_grid.addWidget(self.qr_input, 0, 1, 1, 2)
            self._path_row(qr_grid, 1, "PNG output", self.qr_output, lambda: self._browse_save(self.qr_output, "Save QR Code"))
            qr_btn = QtWidgets.QPushButton("Generate QR")
            qr_btn.clicked.connect(self._generate_qr)
            qr_grid.addWidget(qr_btn, 2, 1)
            layout.addWidget(qr_box)

            layout.addStretch()
            self.tabs.addTab(tab, "Tools")

        def _browse_open(self, target: "QtWidgets.QLineEdit", title: str) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, title)
            if path:
                target.setText(path)

        def _browse_save(self, target: "QtWidgets.QLineEdit", title: str) -> None:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, title)
            if path:
                target.setText(path)

        def _browse_directory_or_file(self) -> None:
            path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory")
            if path:
                self.dir_input.setText(path)

        def _log(self, message: str, color: str = "#1f2933") -> None:
            self.log.append(f'<span style="color:{color};">{message}</span>')

        def _run(self, description: str, action: Callable[[], core.OperationResult | str | Path]) -> Optional[object]:
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
            try:
                result = action()
            except Exception as exc:
                self._log(f"{description} failed: {exc}", "#b42318")
                QtWidgets.QMessageBox.critical(self, APP_TITLE, str(exc))
                return None
            finally:
                QtWidgets.QApplication.restoreOverrideCursor()

            if isinstance(result, core.OperationResult):
                self._log(f"{description} complete: {result.output_path}", "#146c2e")
            else:
                self._log(f"{description} complete: {result}", "#146c2e")
            return result

        def _kwargs(self, controls: Dict[str, object], *, encrypting: bool, include_algorithm: bool = True) -> Dict[str, object]:
            mode = controls["mode"].currentData()
            kwargs: Dict[str, object] = {"key_mode": mode}
            if include_algorithm and "algorithm" in controls:
                kwargs["algorithm"] = controls["algorithm"].currentText()
            if mode == "password":
                password = controls["password"].text()
                if not password:
                    raise core.CrypterError("Password is required.")
                if encrypting and "confirm" in controls:
                    confirm = controls["confirm"].text()
                    if password != confirm:
                        raise core.CrypterError("Passwords do not match.")
                kwargs["password"] = password
            else:
                key_file = controls["key_file"].text().strip()
                if not key_file:
                    raise core.CrypterError("Key file is required.")
                kwargs["key_file"] = key_file
            return kwargs

        def _encrypt_file(self) -> None:
            def action() -> core.OperationResult:
                kwargs = self._kwargs(self.file_controls, encrypting=True)
                return core.encrypt_file(
                    self.file_input.text().strip(),
                    self.file_output.text().strip() or None,
                    compression=self.file_compress.isChecked(),
                    **kwargs,
                )

            self._run("File encryption", action)

        def _decrypt_file(self) -> None:
            def action() -> core.OperationResult:
                kwargs = self._kwargs(self.file_controls, encrypting=False, include_algorithm=False)
                kwargs.pop("key_mode", None)
                return core.decrypt_file(
                    self.file_input.text().strip(),
                    self.file_output.text().strip() or None,
                    **kwargs,
                )

            self._run("File decryption", action)

        def _encrypt_directory(self) -> None:
            def action() -> core.OperationResult:
                kwargs = self._kwargs(self.dir_controls, encrypting=True)
                return core.encrypt_directory(
                    self.dir_input.text().strip(),
                    self.dir_output.text().strip() or None,
                    **kwargs,
                )

            self._run("Directory encryption", action)

        def _decrypt_directory(self) -> None:
            def action() -> core.OperationResult:
                kwargs = self._kwargs(self.dir_controls, encrypting=False, include_algorithm=False)
                kwargs.pop("key_mode", None)
                return core.decrypt_directory(
                    self.dir_input.text().strip(),
                    self.dir_output.text().strip() or None,
                    **kwargs,
                )

            self._run("Directory decryption", action)

        def _encrypt_text(self) -> None:
            def action() -> str:
                kwargs = self._kwargs(self.text_controls, encrypting=True)
                if kwargs.get("key_mode") == "raw-key":
                    kwargs["raw_key"] = core.load_key_file(str(kwargs.pop("key_file")))
                token = core.encrypt_text(
                    self.text_input.toPlainText(),
                    compression=self.text_compress.isChecked(),
                    **kwargs,
                )
                self.text_output.setPlainText(token)
                return "text token generated"

            self._run("Text encryption", action)

        def _decrypt_text(self) -> None:
            def action() -> str:
                kwargs = self._kwargs(self.text_controls, encrypting=False, include_algorithm=False)
                if kwargs.get("key_mode") == "raw-key":
                    kwargs["raw_key"] = core.load_key_file(str(kwargs.pop("key_file")))
                kwargs.pop("key_mode", None)
                text = core.decrypt_text(self.text_input.toPlainText(), **kwargs)
                self.text_output.setPlainText(text)
                return "text decrypted"

            self._run("Text decryption", action)

        def _generate_key_file(self) -> None:
            def action() -> Path:
                output = self.key_output.text().strip()
                if not output:
                    raise core.CrypterError("Choose where to save the key file.")
                return core.save_key_file(output)

            self._run("Key generation", action)

        def _decrypt_legacy(self) -> None:
            def action() -> core.OperationResult:
                return core.decrypt_legacy_file(
                    self.legacy_input.text().strip(),
                    self.legacy_keys.text().strip() or str(core.DEFAULT_LEGACY_KEY_STORE),
                    self.legacy_output.text().strip() or None,
                )

            self._run("Legacy decryption", action)

        def _generate_qr(self) -> None:
            def action() -> Path:
                try:
                    import qrcode
                except ImportError as exc:
                    raise core.CrypterDependencyError(
                        "qrcode is not installed. Run `python -m pip install -r requirements.txt`."
                    ) from exc
                text = self.qr_input.text().strip()
                if not text:
                    raise core.CrypterError("Enter text or a URL for the QR code.")
                output = self.qr_output.text().strip() or "qr-code.png"
                img = qrcode.make(text)
                img.save(output)
                return Path(output)

            self._run("QR generation", action)

    app = QtWidgets.QApplication(sys.argv)
    if Path("logo.ico").exists():
        app.setWindowIcon(QtGui.QIcon("logo.ico"))
    window = CrypterWindow()
    window.show()
    sys.exit(app.exec_())


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not hasattr(args, "func"):
            run_gui()
            return 0
        args.func(args)
        return 0
    except core.CrypterError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
