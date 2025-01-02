from functools import lru_cache
from typing import Any

from pydentity.authentication import AuthenticationResult
from pydentity.authentication.interfaces import (
    IAuthenticationHandler,
    IAuthenticationSchemeProvider,
)
from pydentity.exc import InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal


class HttpContext:
    __slots__ = (
        "_request",
        "_response",
        "_schemes",
    )

    def __init__(self, request: Any, response: Any, schemes: IAuthenticationSchemeProvider) -> None:
        self._schemes = schemes
        self._request = request
        self._response = response

    @property
    def request(self) -> Any:
        """Gets the Request object for this request."""
        return self._request

    @property
    def response(self) -> Any:
        """Gets the Response object for this request."""
        return self._response

    @property
    def user(self) -> ClaimsPrincipal | None:
        """Gets the user for this request."""
        return self.request.user  # type:ignore[no-any-return]

    @user.setter
    def user(self, value: ClaimsPrincipal | None) -> None:
        """Sets the user for this request."""
        self.request.scope["user"] = value

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        return await self.get_authentication_handler(scheme).authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        await self.get_authentication_handler(scheme).sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        await self.get_authentication_handler(scheme).sign_out(self, scheme)

    @lru_cache
    def get_authentication_handler(self, name: str) -> IAuthenticationHandler:
        if scheme := self._schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException(f"Scheme '{name}' not registered.")


class HttpContextAccessor:
    response_class: Any

    __slots__ = ("_http_context",)

    def __init__(self, request: Any, schemes: IAuthenticationSchemeProvider) -> None:
        self._http_context = HttpContext(request, self.response_class(None, status_code=204), schemes)

    @property
    def http_context(self) -> HttpContext:
        """Gets or sets the current *HttpContext*. Returns None if there is no active *HttpContext*."""
        return self._http_context
