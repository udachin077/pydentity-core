from functools import cache
from typing import Iterable

from pydentity.authentication.options import AuthenticationOptions
from pydentity.authentication.interfaces import IAuthenticationSchemeProvider
from pydentity.authentication.scheme import AuthenticationScheme
from pydentity.exc import ArgumentNullException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthenticationSchemeProvider",)


class AuthenticationSchemeProvider(IAuthenticationSchemeProvider):
    """Implements *IAuthenticationSchemeProvider*."""

    __slots__ = ("_options",)

    def __init__(self) -> None:
        self._options = AuthenticationOptions()

    @cache
    def get_all_schemes(self) -> Iterable[AuthenticationScheme]:
        return self._options.scheme_map.values()

    @cache
    def get_scheme(self, name: str) -> AuthenticationScheme | None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        return self._options.scheme_map.get(name)

    @cache
    def get_default_authentication_scheme(self) -> AuthenticationScheme | None:
        if name := self._options.default_authentication_scheme:
            return self.get_scheme(name)

        return self.get_default_scheme()

    @cache
    def get_default_sign_in_scheme(self) -> AuthenticationScheme | None:
        if name := self._options.default_sign_in_scheme:
            return self.get_scheme(name)

        return self.get_default_scheme()

    @cache
    def get_default_sign_out_scheme(self) -> AuthenticationScheme | None:
        if name := self._options.default_sign_out_scheme:
            return self.get_scheme(name)

        return self.get_default_sign_in_scheme()

    @cache
    def get_default_scheme(self) -> AuthenticationScheme | None:
        if name := self._options.default_scheme:
            return self.get_scheme(name)
        # Return the first of the schemes
        return next(s for s in self._options.scheme_map.values())
