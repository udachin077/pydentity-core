from typing import Any

from pydentity.security.claims import ClaimsPrincipal

__all__ = ("AuthorizationHandlerContext",)


class AuthorizationHandlerContext:
    __slots__ = (
        "_request",
        "_fail_called",
        "_succeeded_called",
    )

    def __init__(self, request: Any) -> None:
        self._request = request
        self._fail_called = False
        self._succeeded_called = False

    @property
    def user(self) -> ClaimsPrincipal | None:
        """The ClaimsPrincipal representing the current user."""
        return self._request.user  # type: ignore

    @property
    def has_succeeded(self) -> bool:
        """Flag indicating whether the current authorization processing has succeeded."""
        return not self._fail_called and self._succeeded_called

    def fail(self) -> None:
        """
        Called to indicate *AuthorizationHandlerContext.has_succeeded* will
        never return true, even if all requirements are met.
        """
        self._fail_called = True

    def succeed(self) -> None:
        """Called to mark the specified requirement as being successfully evaluated."""
        self._succeeded_called = True
