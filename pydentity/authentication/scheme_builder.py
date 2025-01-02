from pydentity.authentication.scheme import AuthenticationScheme
from pydentity.authentication.interfaces import IAuthenticationHandler
from pydentity.exc import ArgumentNullException, InvalidOperationException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthenticationSchemeBuilder",)


class AuthenticationSchemeBuilder:
    __slots__ = (
        "_name",
        "handler",
        "display_name",
    )

    def __init__(
        self,
        name: str,
        handler: IAuthenticationHandler | None = None,
        display_name: str | None = None,
    ) -> None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        self._name = name
        self.handler = handler
        """Gets or sets the *IAuthenticationHandler* type responsible for this scheme."""
        self.display_name = display_name
        """Gets or sets the display name for the scheme being built."""

    @property
    def name(self) -> str:
        """Gets the name of the scheme being built."""
        return self._name

    def build(self) -> AuthenticationScheme:
        """Builds the *AuthenticationScheme* instance."""
        if not self.handler:
            raise InvalidOperationException("'handler' must be configured to build an 'AuthenticationScheme'.")

        return AuthenticationScheme(self.name, self.handler, self.display_name)
