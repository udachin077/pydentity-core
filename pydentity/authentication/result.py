from typing import Any

from pydentity.security.claims import ClaimsPrincipal

__all__ = ("AuthenticationResult",)


class AuthenticationResult:
    """Contains the result of an Authenticate call."""

    __slots__ = (
        "_principal",
        "_properties",
    )

    def __init__(self, principal: ClaimsPrincipal, properties: dict[str, Any]) -> None:
        self._principal = principal
        self._properties = properties

    @property
    def principal(self) -> ClaimsPrincipal:
        """Gets the claims-principal with authenticated user identities."""
        return self._principal

    @property
    def properties(self) -> dict[str, Any]:
        """Additional state values for the authentication session."""
        return self._properties

    def __bool__(self) -> bool:
        return self._principal.identity is not None and self._principal.identity.is_authenticated
