from abc import ABC, abstractmethod
from typing import Generic, TYPE_CHECKING

from pydentity.identity_result import IdentityResult
from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class IPasswordValidator(Generic[TUser], ABC):
    """Provides an abstraction for validating passwords."""

    @abstractmethod
    async def validate(self, manager: "UserManager[TUser]", password: str) -> IdentityResult:
        """
        Validates a password.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param password: The password to validate.
        :return:
        """
