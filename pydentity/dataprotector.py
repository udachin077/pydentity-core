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
        purpose: str | None = None,
        salt: str | None = None,
        serializer: Any = None,
    ) -> None:
        self._fernet = Fernet(self._generate_key(purpose, salt))
        self._serializer = serializer or json

    @classmethod
    def _generate_key(cls, purpose: str | None, salt: str | None) -> bytes:
        purpose = purpose if purpose else cls.__name__

        if salt is None:
            try:
                import machineid
            except ImportError:
                raise RuntimeError(
                    'The installed "py-machineid" package is required to generate salt.\n'
                    'You can install "py-machineid" with:\npip install py-machineid'
                )

            salt = machineid.hashed_id(purpose)

        pbkdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=ensure_bytes(salt), iterations=480000)
        return base64.urlsafe_b64encode(pbkdf2.derive(ensure_bytes(purpose)))

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
