from abc import ABC, abstractmethod
from typing import Generic, TYPE_CHECKING

from pydentity.identity_result import IdentityResult
from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class IUserValidator(Generic[TUser], ABC):
    """Provides an abstraction for user validation."""

    @abstractmethod
    async def validate(self, manager: "UserManager[TUser]", user: TUser) -> IdentityResult:
        """
        Validates a user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user to validate.
        :return:
        """
