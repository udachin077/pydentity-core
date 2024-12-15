from typing import Generic, Sequence, TYPE_CHECKING

from pydentity.interfaces import PasswordVerificationResult, IPasswordHasher
from pydentity.exc import ArgumentNoneException
from pydentity.types import TUser
from pydentity.utils import is_none_or_space

if TYPE_CHECKING:
    from pwdlib.hashers import HasherProtocol

__all__ = (
    "PasswordHasher",
    "BcryptPasswordHasher",
    "Argon2PasswordHasher",
)


class PasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    """Implements the standard password hashing."""

    __slots__ = ("_hasher",)

    def __init__(self, hashers: Sequence["HasherProtocol"]) -> None:
        from pwdlib import PasswordHash

        self._hasher = PasswordHash(hashers)

    def hash_password(self, user: TUser, password: str) -> str:
        if password is None:
            raise ArgumentNoneException("password")
        return self._hasher.hash(password)

    def verify_hashed_password(self, user: TUser, hashed_password: str, password: str) -> PasswordVerificationResult:
        if is_none_or_space(password) or is_none_or_space(hashed_password):
            return PasswordVerificationResult.Failed

        valid, hash_updated = self._hasher.verify_and_update(password, hashed_password)

        if valid:
            if hash_updated is not None:
                return PasswordVerificationResult.SuccessRehashNeeded
            return PasswordVerificationResult.Success
        return PasswordVerificationResult.Failed


class BcryptPasswordHasher(PasswordHasher[TUser], Generic[TUser]):
    def __init__(self) -> None:
        from pwdlib.hashers.bcrypt import BcryptHasher

        super().__init__((BcryptHasher(),))


class Argon2PasswordHasher(PasswordHasher[TUser], Generic[TUser]):
    def __init__(self) -> None:
        from pwdlib.hashers.argon2 import Argon2Hasher

        super().__init__((Argon2Hasher(),))
