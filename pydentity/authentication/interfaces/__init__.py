from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from pydentity.interfaces.dataprotector import IDataProtector
from pydentity.security.claims import ClaimsPrincipal

if TYPE_CHECKING:
    from pydentity.http.context import HttpContext
    from pydentity.authentication.result import AuthenticationResult
    from pydentity.authentication.scheme import AuthenticationScheme


class IAuthenticationHandler(ABC):
    """Used to provide authentication."""

    @abstractmethod
    async def authenticate(self, context: "HttpContext", scheme: str) -> "AuthenticationResult":
        """
        Authenticate for the specified authentication scheme.

        :param context: The *HttpContext*.
        :param scheme: The name of the authentication scheme.
        :return:
        """

    @abstractmethod
    async def sign_in(self, context: "HttpContext", scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        """
        Sign a principal in for the specified authentication scheme.

        :param context: The *HttpContext*.
        :param scheme: The name of the authentication scheme.
        :param principal: The *ClaimsPrincipal* to sign in.
        :param properties: The *AuthenticationProperties*.
        :return:
        """

    @abstractmethod
    async def sign_out(self, context: "HttpContext", scheme: str) -> None:
        """
        Sign out the specified authentication scheme.

        :param context: The *HttpContext*.
        :param scheme: The name of the authentication scheme.
        :return:
        """


class IAuthenticationSchemeProvider:
    """Responsible for managing what authenticationSchemes are supported."""

    @abstractmethod
    def get_all_schemes(self) -> Iterable["AuthenticationScheme"]:
        """Returns all currently registered *AuthenticationSchemes*."""

    @abstractmethod
    def get_scheme(self, name: str) -> "AuthenticationScheme | None":
        """
        Returns the *AuthenticationScheme* matching the name, or null.

        :param name: The name of the authentication scheme.
        :return:
        """

    @abstractmethod
    def get_default_authentication_scheme(self) -> "AuthenticationScheme | None":
        """
        Returns the scheme that will be used by default for `authenticate(HttpContext, str)`.
        This is typically specified via AuthenticationOptions.default_authenticate_scheme.
        Otherwise, this will fallback to AuthenticationOptions.default_scheme.

        :return:
        """

    @abstractmethod
    def get_default_sign_in_scheme(self) -> "AuthenticationScheme | None":
        """
        Returns the scheme that will be used by default for `sign_in(HttpContext, str, ClaimsPrincipal, dict[str, ...])`.
        This is typically specified via AuthenticationOptions.default_sign_in_scheme.
        Otherwise, this will fallback to AuthenticationOptions.default_scheme.

        :return:
        """

    @abstractmethod
    def get_default_sign_out_scheme(self) -> "AuthenticationScheme | None":
        """
        Returns the scheme that will be used by default for `sign_out(HttpContext, str)`.
        This is typically specified via AuthenticationOptions.default_sign_out_scheme.
        Otherwise, this will fallback to AuthenticationOptions.default_scheme.

        :return:
        """


class IAuthenticationDataProtector(IDataProtector, ABC):
    pass
