from abc import ABC, abstractmethod
from typing import Generic, TYPE_CHECKING

from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager


class IUserConfirmation(Generic[TUser], ABC):
    """Provides an abstraction for confirmation of user accounts."""

    @abstractmethod
    async def is_confirmed(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        """
        Determines whether the specified user is confirmed.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user.
        :return: Whether the user is confirmed.
        """
