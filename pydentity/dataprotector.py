import base64
import json
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pydentity.interfaces import IPersonalDataProtector

__all__ = ("DefaultPersonalDataProtector",)

from pydentity.utils import ensure_bytes, ensure_str


class DefaultPersonalDataProtector(IPersonalDataProtector):
    __slots__ = (
        "_fernet",
        "_serializer",
    )

    def __init__(
        self,
        key: bytes | str | None = None,
        serializer: Any = None,
    ) -> None:
        _key = base64.urlsafe_b64encode(ensure_bytes(key)) if key else self.generate_key()
        self._fernet = Fernet(_key)
        self._serializer = serializer or json

    @classmethod
    def generate_key(cls) -> bytes:
        try:
            import machineid
        except ImportError:
            raise RuntimeError(
                'The installed "py-machineid" package is required to generate salt.\n'
                'You can install "py-machineid" with:\npip install py-machineid'
            )

        key = ensure_bytes(machineid.hashed_id("pydentity.protector"))
        salt = ensure_bytes(cls.__name__)
        pbkdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        return base64.urlsafe_b64encode(pbkdf2.derive(key))

    def _serialize(self, data: Any) -> str:
        return self._serializer.dumps(data)

    def _deserialize(self, data: str | bytes) -> Any:
        return self._serializer.loads(data)

    def protect(self, data: Any) -> str:
        encrypted_data = self._fernet.encrypt(ensure_bytes(self._serialize(data)))
        return ensure_str(base64.urlsafe_b64encode(encrypted_data))

    def unprotect(self, data: str | bytes) -> Any:
        decrypted_data = self._fernet.decrypt(base64.urlsafe_b64decode(data))
        return self._deserialize(decrypted_data)
