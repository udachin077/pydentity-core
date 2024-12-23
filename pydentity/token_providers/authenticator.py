from typing import TYPE_CHECKING, Generic, override, Any

from pydentity.interfaces import IUserTwoFactorTokenProvider
from pydentity.rfc6238service import validate_code
from pydentity.types import TUser
from pydentity.utils import is_none_or_space

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("AuthenticatorTokenProvider",)


class AuthenticatorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    def __init__(self, digits: int = 6, digest: Any = None, interval: int = 30) -> None:
        """

        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        """
        self.digits = digits
        self.digest = digest
        self.interval = interval

    @override
    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        return ""

    @override
    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        if is_none_or_space(key):
            return False

        assert key is not None
        return validate_code(key, token, self.digits, self.digest, self.interval)

    @override
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        key = await manager.get_authenticator_key(user)
        return not is_none_or_space(key)
