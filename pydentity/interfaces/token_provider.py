from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class IUserTwoFactorTokenProvider(Generic[TUser], ABC):
    """Provides an abstraction for token generators."""

    @abstractmethod
    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        """
        Generates a token for the specified user and purpose.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return:
        """

    @abstractmethod
    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        """
        Returns a flag indicating whether the specified token is valid for the given user and purpose.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param token: The token to validate.
        :param user: The user a token should be validated for.
        :return:
        """

    @abstractmethod
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        """
        Returns a flag indicating whether the token provider can generate a token suitable for two-factor authentication
        token for the specified user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user a token could be generated for.
        :return:
        """
