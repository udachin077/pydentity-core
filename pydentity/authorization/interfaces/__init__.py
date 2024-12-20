from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pydentity.authorization.base import (
        AuthorizationPolicy,
        AuthorizationHandlerContext,
    )


class IAuthorizationHandler(ABC):
    """Classes implementing this interface are able to make a decision if authorization is allowed."""

    @abstractmethod
    async def handle(self, context: "AuthorizationHandlerContext") -> None:
        """
        Makes a decision if authorization is allowed.

        :param context: The authorization information.
        :return:
        """


class IAuthorizationPolicyProvider:
    """A type which can provide ``AuthorizationPolicy`` for a particular name."""

    @abstractmethod
    async def get_policy(self, name: str) -> Optional["AuthorizationPolicy"]:
        """
        Gets a ``AuthorizationPolicy`` from the given policy name.

        :param name: The policy name to retrieve.
        :return:
        """

    @abstractmethod
    async def get_default_policy(self) -> Optional["AuthorizationPolicy"]:
        """Gets the default authorization policy."""
