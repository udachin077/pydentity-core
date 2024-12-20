from datetime import timedelta
from typing import overload, Callable, Self

from pydentity import IdentityConstants
from pydentity.authentication import AuthenticationScheme, AuthenticationSchemeBuilder, AuthenticationOptions
from pydentity.authentication.bearer import (
    TokenValidationParameters,
    JWTBearerAuthenticationHandler,
    IPrincipalClaimsSerializer,
    JWTSecurityToken,
)
from pydentity.authentication.cookie import CookieAuthenticationOptions, CookieAuthenticationHandler
from pydentity.authentication.interfaces import IAuthenticationDataProtector


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
        Adds a ``AuthenticationScheme``.

        :param name: The name of this scheme.
        :param scheme:
        :return:
        """

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None], /) -> Self:
        """
        Adds a ``AuthenticationScheme``.

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

    def add_cookie(
        self,
        scheme: str = "Cookie",
        cookie_options: CookieAuthenticationOptions | None = None,
        protector: IAuthenticationDataProtector | None = None,
    ) -> Self:
        """
        Adds cookie authentication to ``AuthenticationBuilder`` using the specified scheme.

        :param scheme: The authentication scheme.
        :param cookie_options:
        :param protector:
        :return:
        """
        return self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, CookieAuthenticationHandler(cookie_options, protector)),
        )

    def add_identity_cookies(self) -> "AuthenticationBuilder":
        self.add_cookie(IdentityConstants.ApplicationScheme)
        self.add_cookie(
            IdentityConstants.ExternalScheme,
            CookieAuthenticationOptions(expires_timedelta=timedelta(minutes=10)),
        )
        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme)
        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme)
        return self

    def add_bearer(
        self,
        scheme: str = "Bearer",
        *,
        validation_parameters: TokenValidationParameters,
        serializer: IPrincipalClaimsSerializer | None = None,
    ) -> Self:
        """
        Enables JWT-bearer authentication using the default scheme 'Bearer'.

        :param scheme: The authentication scheme.
        :param validation_parameters:
        :param serializer:
        :return:
        """
        if serializer is not None:
            JWTSecurityToken.serializer = serializer

        self.add_scheme(
            scheme,
            AuthenticationScheme(scheme, JWTBearerAuthenticationHandler(validation_parameters)),
        )
        return self

    def set_default_scheme(self, scheme: str) -> Self:
        self.__options.default_scheme = scheme
        return self
