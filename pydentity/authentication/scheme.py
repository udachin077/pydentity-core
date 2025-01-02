from pydentity.authentication.interfaces import IAuthenticationHandler
from pydentity.exc import ArgumentNullException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthenticationScheme",)


class AuthenticationScheme:
    """*AuthenticationSchemes* assign a name to a specific *IAuthenticationHandler*."""

    __slots__ = (
        "_name",
        "_handler",
        "_display_name",
    )

    def __init__(
        self,
        name: str,
        handler: IAuthenticationHandler,
        display_name: str | None = None,
    ) -> None:
        """

        :param name: The name for the authentication scheme.
        :param handler: The *IAuthenticationHandler* that handles this scheme.
        :param display_name: The display name for the authentication scheme.
        """
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        if handler is None:
            raise ArgumentNullException("handler")

        if not issubclass(type(handler), IAuthenticationHandler):
            raise ValueError("'handler' must implement 'IAuthenticationHandler'.")

        self._name = name
        self._display_name = display_name
        self._handler = handler

    @property
    def name(self) -> str:
        """The name of the authentication scheme."""
        return self._name

    @property
    def display_name(self) -> str | None:
        """The display name for the scheme. Null is valid and used for non user facing schemes."""
        return self._display_name

    @property
    def handler(self) -> IAuthenticationHandler:
        """The *IAuthenticationHandler* that handles this scheme."""
        return self._handler
