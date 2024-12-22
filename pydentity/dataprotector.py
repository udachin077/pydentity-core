import base64
import json
from typing import Any, Protocol

from cryptography.fernet import Fernet

from pydentity.interfaces import IPersonalDataProtector
from pydentity.utils import ensure_bytes, ensure_str, generate_security_key

__all__ = (
    "DefaultPersonalDataProtector",
    "JsonSerializer",
)


class JsonSerializer(Protocol):
    def loads(self, data: str | bytes) -> Any:
        pass

    def dumps(self, obj: Any) -> str:
        pass


class DefaultPersonalDataProtector(IPersonalDataProtector):
    __slots__ = (
        "_fernet",
        "_json_serializer",
    )

    def __init__(
        self,
        key: bytes | str | None = None,
        json_serializer: JsonSerializer = None,
    ) -> None:
        _key = base64.urlsafe_b64encode(ensure_bytes(key)) if key else generate_security_key(self.__class__)
        self._fernet = Fernet(_key)
        self._json_serializer = json_serializer or json

    def _serialize(self, data: Any) -> str:
        return self._json_serializer.dumps(data)

    def _deserialize(self, data: str | bytes) -> Any:
        return self._json_serializer.loads(data)

    def protect(self, data: Any) -> str:
        encrypted_data = self._fernet.encrypt(ensure_bytes(self._serialize(data)))
        return ensure_str(base64.urlsafe_b64encode(encrypted_data))

    def unprotect(self, data: str | bytes) -> Any:
        decrypted_data = self._fernet.decrypt(base64.urlsafe_b64decode(data))
        return self._deserialize(decrypted_data)
