import base64
from typing import Protocol

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pydentity.interfaces.dataprotector import IDataProtector
from pydentity.utils import ensure_bytes, ensure_str

__all__ = ("BaseDataProtector", "PersonalDataProtector", "FernetBackend", "AesBackend")


def get_machineid_key(key: str = "pydentity") -> bytes:
    try:
        import machineid
    except ImportError:
        raise RuntimeError(
            'The installed "py-machineid" package is required to generate key.\n'
            'You can install "py-machineid" with:\n'
            "pip install py-machineid"
        )

    return ensure_bytes(machineid.hashed_id(key))


def _hash_key(
    key: str | bytes,
    salt: str | bytes = b"pydentity",
    *,
    algorithm: hashes.HashAlgorithm | None = None,
    length: int = 32,
    iterations: int = 720000,
) -> bytes:
    pbkdf2 = PBKDF2HMAC(
        algorithm=algorithm or hashes.SHA256(), length=length, salt=ensure_bytes(salt), iterations=iterations
    )
    return pbkdf2.derive(ensure_bytes(key))


class EncryptionBackend(Protocol):
    def encrypt(self, plaintext: str | bytes) -> bytes:
        pass

    def decrypt(self, ciphertext: str | bytes) -> bytes:
        pass


class FernetBackend(EncryptionBackend):
    __slots__ = ("_fernet",)

    def __init__(self, key: str | bytes | None = None, salt: str | bytes = b"pydentity.hasher") -> None:
        if key is None:
            key = get_machineid_key()

        hashed_key = _hash_key(key, salt)
        self._fernet = Fernet(base64.urlsafe_b64encode(hashed_key))

    def encrypt(self, plaintext: str | bytes) -> bytes:
        encrypted_data = self._fernet.encrypt(ensure_bytes(plaintext))
        return base64.b64encode(encrypted_data)

    def decrypt(self, ciphertext: str | bytes) -> bytes:
        return self._fernet.decrypt(base64.b64decode(ensure_bytes(ciphertext)))


class AesBackend(EncryptionBackend):
    __slots__ = ("_cipher", "_padding")

    def __init__(self, key: str | bytes | None = None, salt: str | bytes = b"pydentity.hasher") -> None:
        if key is None:
            key = get_machineid_key()

        hashed_key = _hash_key(key, salt)
        self._cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(hashed_key[:16]))
        self._padding = padding.PKCS7(128)

    def encrypt(self, plaintext: str | bytes) -> bytes:
        padder = self._padding.padder()
        plaintext = padder.update(ensure_bytes(plaintext)) + padder.finalize()
        encryptor = self._cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return base64.b64encode(encrypted)

    def decrypt(self, ciphertext: str | bytes) -> bytes:
        decryptor = self._cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(ensure_bytes(ciphertext))) + decryptor.finalize()
        unpadder = self._padding.unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()


class BaseDataProtector(IDataProtector):
    __slots__ = ("_engine",)

    def __init__(self, engine: EncryptionBackend) -> None:
        self._engine = engine

    def protect(self, data: str | bytes) -> str:
        return ensure_str(self._engine.encrypt(data))

    def unprotect(self, data: str | bytes) -> str:
        return ensure_str(self._engine.decrypt(data))


class PersonalDataProtector(BaseDataProtector):
    def __init__(self, key: str | bytes | None = None) -> None:
        super().__init__(AesBackend(key))
