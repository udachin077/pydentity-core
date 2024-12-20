import base64
from datetime import datetime as _datetime, timedelta, UTC

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = (
    "datetime",
    "is_none_or_space",
    "ensure_str",
    "ensure_bytes",
    "generate_security_key",
)


class datetime(_datetime):
    @classmethod
    def utcnow(cls) -> "datetime":
        return datetime.now(UTC)

    def add(self, __td: timedelta, /) -> "datetime":
        return self.__add__(__td)

    def add_days(self, days: float, /) -> "datetime":
        return self.add(timedelta(days=days))

    def add_seconds(self, seconds: float, /) -> "datetime":
        return self.add(timedelta(seconds=seconds))

    def add_microseconds(self, microseconds: float, /) -> "datetime":
        return self.add(timedelta(microseconds=microseconds))

    def add_milliseconds(self, milliseconds: float, /) -> "datetime":
        return self.add(timedelta(milliseconds=milliseconds))

    def add_minutes(self, minutes: float, /) -> "datetime":
        return self.add(timedelta(minutes=minutes))

    def add_hours(self, hours: float, /) -> "datetime":
        return self.add(timedelta(hours=hours))

    def add_weeks(self, weeks: float, /) -> "datetime":
        return self.add(timedelta(weeks=weeks))


def is_none_or_space(v: str | None, /) -> bool:
    """
    Indicates whether a specified string is `None`, `empty`, or consists only of `white-space` characters.

    :param v: The string to test.
    :return: ``True`` if the value parameter is `None` or `empty`, or if value consists exclusively of `white-space` characters.
    """
    return bool(not v or v.isspace())


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


def generate_security_key(cls) -> bytes:
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
