from typing import TYPE_CHECKING, Generic

from pydentity.interfaces.user_confirmation import IUserConfirmation
from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("DefaultUserConfirmation",)


class DefaultUserConfirmation(IUserConfirmation[TUser], Generic[TUser]):
    """Default implementation of *IUserConfirmation[TUser]*."""

    async def is_confirmed(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        return await manager.is_email_confirmed(user)
