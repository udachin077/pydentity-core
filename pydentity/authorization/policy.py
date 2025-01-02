from typing import Iterable

from pydentity.authorization.interfaces import IAuthorizationHandler
from pydentity.exc import ArgumentNullException

from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthorizationPolicy",)


class AuthorizationPolicy:
    """Represents a collection of authorization requirements evaluated against, all of which must succeed for authorization to succeed."""

    __slots__ = (
        "_name",
        "_requirements",
    )

    def __init__(self, name: str, requirements: Iterable[IAuthorizationHandler]) -> None:
        """

        :param name: Policy name.
        :param requirements: The iterable of *IAuthorizationRequirement* which must succeed for this policy to be successful.
        """
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        self._name = name
        self._requirements: tuple[IAuthorizationHandler, ...] = tuple(requirements or [])

    @property
    def name(self) -> str:
        """Gets policy name."""
        return self._name

    @property
    def requirements(self) -> tuple[IAuthorizationHandler, ...]:
        """Gets a tuple of *IAuthorizationHandlers* which must succeed for this policy to be successful."""
        return self._requirements
