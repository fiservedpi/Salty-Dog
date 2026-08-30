import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class Vault:
    def __init__(self, path: Path, fernet: Fernet, salt: bytes) -> None:
        self.path = path
        self.fernet = fernet
        self.salt = salt
        self.data: dict[str, str] = {}

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

        return base64.urlsafe_b64encode(
            kdf.derive(password.encode("utf-8"))
        )

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        salt = os.urandom(16)
        key = cls._derive_key(password, salt)

        vault = cls(
            path=path,
            fernet=Fernet(key),
            salt=salt,
        )

        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        if not path.exists():
            raise FileNotFoundError(f"Vault not found: {path}")

        vault_file = json.loads(
            path.read_text(encoding="utf-8")
        )

        salt = base64.b64decode(vault_file["salt"])
        encrypted_data = base64.b64decode(vault_file["data"])

        key = cls._derive_key(password, salt)
        fernet = Fernet(key)

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken as error:
            raise ValueError("Incorrect master password.") from error

        vault = cls(
            path=path,
            fernet=fernet,
            salt=salt,
        )

        vault.data = json.loads(
            decrypted_data.decode("utf-8")
        )

        return vault

    def save(self) -> None:
        encrypted_data = self.fernet.encrypt(
            json.dumps(self.data).encode("utf-8")
        )

        vault_file = {
            "version": 1,
            "kdf": "scrypt",
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "data": base64.b64encode(encrypted_data).decode("ascii"),
        }

        self.path.write_text(
            json.dumps(vault_file, indent=2),
            encoding="utf-8",
        )