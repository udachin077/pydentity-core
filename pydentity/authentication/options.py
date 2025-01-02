from inspect import isfunction
from typing import overload, Callable

from pydentity._meta import SingletonMeta
from pydentity.authentication.scheme import AuthenticationScheme
from pydentity.authentication.scheme_builder import AuthenticationSchemeBuilder
from pydentity.exc import ArgumentNullException, InvalidOperationException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthenticationOptions",)


class AuthenticationOptions(metaclass=SingletonMeta):
    __slots__ = (
        "__scheme_map",
        "default_scheme",
        "default_authentication_scheme",
        "default_sign_in_scheme",
        "default_sign_out_scheme",
        "required_authenticated_signin",
    )

    def __init__(self) -> None:
        self.__scheme_map: dict[str, AuthenticationScheme] = {}
        self.default_scheme: str = ""
        """Used as the fallback default scheme for all the other defaults."""
        self.default_authentication_scheme: str = ""
        """Used as the default scheme by *authenticate(HttpContext, str)*."""
        self.default_sign_in_scheme: str = ""
        """Used as the default scheme sign_in(HttpContext, str, ClaimsPrincipal, dict[str, ...])."""
        self.default_sign_out_scheme: str = ""
        """Used as the default scheme by sign_out(HttpContext, str, dict[str, ...])."""
        self.required_authenticated_signin: bool = True
        """
        If true, sign_in should throw if attempted with a user is not authenticated.
        A user is considered authenticated if *ClaimsIdentity.is_authenticated* returns *True* 
        for the *ClaimsPrincipal* associated with the HTTP request.
        """

    @property
    def scheme_map(self) -> dict[str, AuthenticationScheme]:
        """Maps schemes by name."""
        return self.__scheme_map

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme, /) -> None:
        """
        Adds an *AuthenticationScheme*.

        :param name: The name of the scheme.
        :param scheme: The scheme.
        :return:
        """

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None], /) -> None:
        """
        Add a scheme that is built from a delegate with the provided name.

        :param name: The name of the scheme.
        :param configure_scheme: Configures the scheme.
        :return:
        """

    def add_scheme(
        self, name: str, scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None], /
    ) -> None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        if scheme_or_builder is None:
            raise ArgumentNullException("scheme_or_builder")

        if name in self.__scheme_map:
            raise InvalidOperationException(f"Scheme already exists: {name}.")

        self._replace_or_add_scheme(name, scheme_or_builder)

    @overload
    def replace_scheme(self, name: str, scheme: AuthenticationScheme, /) -> None:
        """
        Replaces an *AuthenticationScheme*.

        :param name: The name of the scheme.
        :param scheme: The scheme.
        :return:
        """

    @overload
    def replace_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None], /) -> None:
        """
        Replace a scheme that is built from a delegate with the provided name.

        :param name: The name of the scheme.
        :param configure_scheme: Configures the scheme.
        :return:
        """

    def replace_scheme(
        self, name: str, scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None], /
    ) -> None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        if not scheme_or_builder:
            raise ArgumentNullException("scheme_or_builder")

        if name not in self.__scheme_map:
            raise InvalidOperationException(f"Scheme not exists: {name}.")

        self._replace_or_add_scheme(name, scheme_or_builder)

    def _replace_or_add_scheme(
        self, name: str, scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> None:
        if isinstance(scheme_or_builder, AuthenticationScheme):
            self.__scheme_map[name] = scheme_or_builder
        elif isfunction(scheme_or_builder):
            builder = AuthenticationSchemeBuilder(name)
            scheme_or_builder(builder)
            self.__scheme_map[name] = builder.build()
        else:
            raise NotImplementedError
