from typing import Generic, Sequence, Literal

from cryptography.hazmat.primitives.hashes import HashAlgorithm
from pwdlib.hashers import HasherProtocol

from pydentity.exc import ArgumentNoneException
from pydentity.interfaces import PasswordVerificationResult, IPasswordHasher
from pydentity.types import TUser
from pydentity.utils import is_none_or_space

__all__ = (
    "PasswordHasher",
    "BcryptPasswordHasher",
    "Argon2PasswordHasher",
    "PBKDF2PasswordHasher",
)


class PasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    """Implements the standard password hashing."""

    __slots__ = ("_hasher",)

    def __init__(self, hashers: Sequence[HasherProtocol]) -> None:
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
    def __init__(self, rounds: int = 12, prefix: Literal["2a", "2b"] = "2b") -> None:
        from ._hashers import BcryptHasher

        super().__init__((BcryptHasher(rounds=rounds, prefix=prefix),))


class Argon2PasswordHasher(PasswordHasher[TUser], Generic[TUser]):
    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        from ._hashers import Argon2Hasher

        super().__init__(
            (
                Argon2Hasher(
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    salt_len=salt_len,
                ),
            )
        )


class PBKDF2PasswordHasher(PasswordHasher[TUser], Generic[TUser]):
    def __init__(
        self,
        algorithm: HashAlgorithm | None = None,
        hash_len: int = 32,
        iterations: int = 720000,
    ) -> None:
        from ._hashers import PBKDF2Hasher

        super().__init__((PBKDF2Hasher(algorithm=algorithm, hash_len=hash_len, iterations=iterations),))
