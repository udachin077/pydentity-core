from typing import Self, overload, Callable, Any

from pydentity.authentication.bearer.handlers import JWTBearerAuthenticationHandler
from pydentity.authentication.bearer.param import TokenValidationParameters
from pydentity.authentication.cookie.handlers import CookieAuthenticationHandler
from pydentity.authentication.cookie.param import CookieAuthenticationOptions
from pydentity.authentication.interfaces import IAuthenticationDataProtector
from pydentity.authentication.options import AuthenticationOptions
from pydentity.authentication.scheme import AuthenticationScheme
from pydentity.authentication.scheme_builder import AuthenticationSchemeBuilder
from pydentity.identity_constants import IdentityConstants

__all__ = ("AuthenticationBuilder",)


class AuthenticationBuilder:
    """Used to configure authentication."""

    __slots__ = ("__options",)

    def __init__(self, default_scheme: str | None = None):
        self.__options = AuthenticationOptions()

        if default_scheme:
            self.set_default_scheme(default_scheme)

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme, /) -> Self:
        """
        Adds a *AuthenticationScheme*.

        :param name: The name of this scheme.
        :param scheme:
        :return:
        """

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None], /) -> Self:
        """
        Adds a *AuthenticationScheme*.

        :param name: The name of this scheme.
        :param configure_scheme:
        :return:
        """

    def add_scheme(
        self,
        name: str,
        scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None],
    ) -> Self:
        self.__options.add_scheme(name, scheme_or_builder)
        return self

    def __iadd__(self, scheme: AuthenticationScheme) -> Self:
        return self.add_scheme(scheme.name, scheme)

    @overload
    def replace_scheme(self, name: str, scheme: AuthenticationScheme, /) -> Self:
        """
        Replaces an *AuthenticationScheme*.

        :param name: The name of the scheme.
        :param scheme: The scheme.
        :return:
        """

    @overload
    def replace_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None], /) -> Self:
        """
        Replace a scheme that is built from a delegate with the provided name.

        :param name: The name of the scheme.
        :param configure_scheme: Configures the scheme.
        :return:
        """

    def replace_scheme(
        self, name: str, scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None], /
    ) -> Self:
        self.__options.replace_scheme(name, scheme_or_builder)
        return self

    def add_cookie(
        self,
        scheme: str = "Cookie",
        cookie_options: CookieAuthenticationOptions | None = None,
        protector: IAuthenticationDataProtector | None = None,
        serializer: Any | None = None,
    ) -> Self:
        """
        Adds cookie authentication to *AuthenticationBuilder* using the specified scheme.

        :param scheme: The authentication scheme.
        :param cookie_options:
        :param protector:
        :param serializer:
        :return:
        """
        return self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, CookieAuthenticationHandler(cookie_options, protector, serializer)),
        )

    def add_bearer(
        self,
        scheme: str = "Bearer",
        *,
        validation_parameters: TokenValidationParameters,
    ) -> Self:
        """
        Enables JWT-bearer authentication using the default scheme Bearer.

        :param scheme: The authentication scheme.
        :param validation_parameters:
        :return:
        """
        self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, JWTBearerAuthenticationHandler(validation_parameters)),
        )
        return self

    def set_default_scheme(self, scheme: str) -> Self:
        self.__options.default_scheme = scheme
        return self

    def add_identity_cookies(self) -> Self:
        self.add_cookie(IdentityConstants.ApplicationScheme)
        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme)
        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme)
        self.add_cookie(
            IdentityConstants.ExternalScheme,
            CookieAuthenticationOptions(expires_timedelta=600),
        )
        return self
