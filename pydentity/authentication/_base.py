import base64
import platform
from collections.abc import Iterable, Callable
from inspect import isfunction
from typing import overload, Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pydentity.authentication.interfaces import (
    IAuthenticationDataProtector,
    IAuthenticationHandler,
    IAuthenticationSchemeProvider,
    IAuthenticationOptionsAccessor,
)
from pydentity.exc import ArgumentNoneException, InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal

__all__ = (
    "AuthenticationError",
    "AuthenticationOptions",
    "AuthenticationResult",
    "AuthenticationScheme",
    "AuthenticationSchemeBuilder",
    "AuthenticationSchemeProvider",
    "DefaultAuthenticationDataProtector",
)


class AuthenticationError(Exception):
    pass


class AuthenticationResult:
    """ Contains the result of an Authenticate call."""

    __slots__ = ("_principal", "_properties",)

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
        return bool(self._principal.identity and self._principal.identity.is_authenticated)


class AuthenticationScheme:
    """``AuthenticationSchemes`` assign a name to a specific ``IAuthenticationHandler``."""

    __slots__ = ("_name", "_handler", "_display_name",)

    def __init__(self, name: str, handler: IAuthenticationHandler, display_name: str | None = None) -> None:
        """

        :param name: The name for the authentication scheme.
        :param handler: The ``IAuthenticationHandler`` that handles this scheme.
        :param display_name: The display name for the authentication scheme.
        """
        if not name:
            raise ArgumentNoneException("name")
        if not handler:
            raise ArgumentNoneException("handler")

        if not issubclass(type(handler), IAuthenticationHandler):
            raise ValueError("'handler' must implement IAuthenticationHandler.")

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
        """The ``IAuthenticationHandler`` that handles this scheme."""
        return self._handler


class AuthenticationSchemeBuilder:
    __slots__ = ("_name", "handler", "display_name",)

    def __init__(
            self,
            name: str,
            handler: IAuthenticationHandler | None = None,
            display_name: str | None = None
    ) -> None:
        self._name = name
        self.handler = handler
        """Gets or sets the ``IAuthenticationHandler`` type responsible for this scheme."""
        self.display_name = display_name
        """Gets or sets the display name for the scheme being built."""

    @property
    def name(self) -> str:
        """Gets the name of the scheme being built."""
        return self._name

    def build(self) -> AuthenticationScheme:
        """Builds the ``AuthenticationScheme`` instance."""
        if not self.handler:
            raise InvalidOperationException("'handler' must be configured to build an AuthenticationScheme.")
        return AuthenticationScheme(self.name, self.handler, self.display_name)


class AuthenticationOptions:
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
        """Used as the default scheme by ``authenticate(HttpContext, str)``."""
        self.default_sign_in_scheme: str = ""
        """Used as the default scheme sign_in(HttpContext, str, ClaimsPrincipal, dict[str, ...])."""
        self.default_sign_out_scheme: str = ""
        """Used as the default scheme by sign_out(HttpContext, str, dict[str, ...])."""
        self.required_authenticated_signin: bool = True
        """
        If true, sign_in should throw if attempted with a user is not authenticated.
        A user is considered authenticated if ``ClaimsIdentity.is_authenticated`` returns ``True`` 
        for the ``ClaimsPrincipal`` associated with the HTTP request.
        """

    @property
    def scheme_map(self) -> dict[str, AuthenticationScheme]:
        """Maps schemes by name."""
        return self.__scheme_map

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> None:
        """
        Adds an ``AuthenticationScheme``.

        :param name: The name of the scheme being added.
        :param scheme:
        :return:
        """

    @overload
    def add_scheme(self, name: str, configure_scheme: Callable[[AuthenticationSchemeBuilder], None]) -> None:
        """
        Add a scheme that is built from a delegate with the provided name.

        :param name: The name of the scheme being added.
        :param configure_scheme: Configures the scheme.
        :return:
        """

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None]
    ) -> None:
        if not name:
            raise ArgumentNoneException("name")
        if not scheme_or_builder:
            raise ArgumentNoneException("scheme_or_builder")
        if name in self.__scheme_map:
            raise InvalidOperationException(f"Scheme already exists: {name}.")

        if isinstance(scheme_or_builder, AuthenticationScheme):
            self.__scheme_map[name] = scheme_or_builder

        elif isfunction(scheme_or_builder):
            builder = AuthenticationSchemeBuilder(name)
            scheme_or_builder(builder)
            self.__scheme_map[name] = builder.build()

        else:
            raise NotImplementedError


class AuthenticationSchemeProvider(IAuthenticationSchemeProvider):
    """Implements ``IAuthenticationSchemeProvider``."""

    __slots__ = ("__options", "_auto_default_scheme",)

    def __init__(self, options: IAuthenticationOptionsAccessor) -> None:
        self.__options = options.value
        self._auto_default_scheme = None

        for scheme in self.__options.scheme_map.values():
            self._auto_default_scheme = scheme
            break

    async def get_all_schemes(self) -> Iterable[AuthenticationScheme]:
        return self.__options.scheme_map.values()

    async def get_scheme(self, name: str) -> AuthenticationScheme | None:
        if not name:
            raise ArgumentNoneException("name")
        return self.__options.scheme_map.get(name)

    async def get_default_authentication_scheme(self) -> AuthenticationScheme | None:
        if name := self.__options.default_authentication_scheme:
            return await self.get_scheme(name)
        return await self.get_default_scheme()

    async def get_default_sign_in_scheme(self) -> AuthenticationScheme | None:
        if name := self.__options.default_sign_in_scheme:
            return await self.get_scheme(name)
        return await self.get_default_scheme()

    async def get_default_sign_out_scheme(self) -> AuthenticationScheme | None:
        if name := self.__options.default_sign_out_scheme:
            return await self.get_scheme(name)
        return await self.get_default_sign_in_scheme()

    async def get_default_scheme(self) -> AuthenticationScheme | None:
        if name := self.__options.default_scheme:
            return await self.get_scheme(name)
        return self._auto_default_scheme


class DefaultAuthenticationDataProtector(IAuthenticationDataProtector):
    __slots__ = ("__fernet",)

    def __init__(self, key: bytes | str = None, salt: bytes | str = None):
        key = key or platform.node()
        salt = salt or self.__class__.__name__

        if isinstance(key, str):
            key = key.encode()

        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 480000)
        key = base64.urlsafe_b64encode(kdf.derive(key))
        self.__fernet = Fernet(key)

    def protect(self, plain_text: str | bytes) -> str | None:
        if plain_text is None:
            return plain_text

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        return self.__fernet.encrypt(plain_text).decode()

    def unprotect(self, protected_data: str | bytes) -> str | None:
        if protected_data is None:
            return protected_data

        return self.__fernet.decrypt(protected_data).decode()
