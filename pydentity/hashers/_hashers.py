import base64
import math
import secrets
import string
from collections.abc import Sequence

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pwdlib.hashers import HasherProtocol
from pwdlib.hashers.argon2 import Argon2Hasher as Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher as BcryptHasher

from pydentity.utils import ensure_str, ensure_bytes

__all__ = (
    "Argon2Hasher",
    "BcryptHasher",
    "PBKDF2Hasher",
)

ALLOWED_CHARS = string.ascii_letters + string.digits


def get_random_string(length: int, allowed_chars: Sequence[str] = ALLOWED_CHARS) -> str:
    return "".join(secrets.choice(allowed_chars) for _ in range(length))


def must_update_salt(salt: str, expected_entropy: int) -> bool:
    return len(salt) * math.log2(len(ALLOWED_CHARS)) < expected_entropy


class PBKDF2Hasher(HasherProtocol):
    salt_entropy: int = 128
    prefix = "$pbkdf2$"

    __slots__ = (
        "_algorithm",
        "_hash_len",
        "_iterations",
    )

    def __init__(
        self,
        algorithm: HashAlgorithm | None = None,
        hash_len: int = 32,
        iterations: int = 720000,
    ):
        self._algorithm = algorithm or hashes.SHA256()
        self._hash_len = hash_len
        self._iterations = iterations

    def _generate_salt(self) -> str:
        char_count = math.ceil(self.salt_entropy / math.log2(len(ALLOWED_CHARS)))
        return get_random_string(char_count, allowed_chars=ALLOWED_CHARS)

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:  # noqa
        return ensure_str(hash).startswith(cls.prefix)

    def hash(  # noqa
        self,
        password: str | bytes,
        *,
        salt: bytes | None = None,
    ) -> str:
        if salt and "$" in ensure_str(salt):
            raise ValueError("salt must be provided and cannot contain $.")

        salt = ensure_bytes(salt or self._generate_salt())
        pbkdf2 = PBKDF2HMAC(
            algorithm=self._algorithm,
            length=self._hash_len,
            salt=salt,
            iterations=self._iterations,
        )
        _hash = base64.b64encode(pbkdf2.derive(ensure_bytes(password)))
        return f"{self.prefix}{self._algorithm.name}${self._iterations}${ensure_str(salt)}${ensure_str(_hash)}"

    def verify(
        self,
        password: str | bytes,
        hash: str | bytes,  # noqa
    ) -> bool:
        algorithm, iterations, salt, _hash = self._get_scheme_param(hash)
        pbkdf2 = PBKDF2HMAC(
            algorithm=self._algorithm,
            length=self._hash_len,
            salt=ensure_bytes(salt),
            iterations=int(iterations),
        )
        try:
            pbkdf2.verify(ensure_bytes(password), base64.b64decode(_hash))
            return True
        except InvalidKey:
            return False

    def check_needs_rehash(self, hash: str | bytes) -> bool:  # noqa
        algorithm, iterations, salt, _hash = self._get_scheme_param(hash)
        update_salt = must_update_salt(salt, self.salt_entropy)
        return (int(iterations) != self._iterations) or update_salt

    def _get_scheme_param(self, hash: str | bytes) -> list[str]:  # noqa
        return ensure_str(hash).removeprefix(self.prefix).split("$", 3)
