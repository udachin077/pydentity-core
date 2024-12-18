from abc import abstractmethod, ABC
from functools import lru_cache
from typing import Any, Generic

from pydentity.authentication import AuthenticationResult
from pydentity.authentication.interfaces import (
    IAuthenticationHandler,
    IAuthenticationSchemeProvider,
)
from pydentity.exc import InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal
from pydentity.types import TRequest, TResponse


class HttpContext(Generic[TRequest, TResponse]):
    __slots__ = (
        "_request",
        "_response",
        "_schemes",
    )

    def __init__(self, request: TRequest, response: TResponse, schemes: IAuthenticationSchemeProvider) -> None:
        self._schemes = schemes
        self._request = request
        self._response = response

    @property
    def request(self) -> TRequest:
        """Gets the Request object for this request."""
        return self._request

    @property
    def response(self) -> TResponse:
        """Gets the Response object for this request."""
        return self._response

    @property
    def user(self) -> ClaimsPrincipal | None:
        """Gets the user for this request."""
        return self._user_getter()

    @user.setter
    def user(self, value: ClaimsPrincipal | None) -> None:
        """Sets the user for this request."""
        self._user_setter(value)

    @abstractmethod
    def _user_getter(self) -> ClaimsPrincipal | None:
        pass

    @abstractmethod
    def _user_setter(self, value: ClaimsPrincipal | None) -> None:
        pass

    async def authenticate(self, scheme: str) -> AuthenticationResult:
        handler = await self.get_authentication_handler(scheme)
        return await handler.authenticate(self, scheme)

    async def sign_in(self, scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        handler = await self.get_authentication_handler(scheme)
        await handler.sign_in(self, scheme, principal, **properties)

    async def sign_out(self, scheme: str) -> None:
        handler = await self.get_authentication_handler(scheme)
        await handler.sign_out(self, scheme)

    @lru_cache
    async def get_authentication_handler(self, name: str) -> IAuthenticationHandler:
        if scheme := await self._schemes.get_scheme(name):
            return scheme.handler
        raise InvalidOperationException(f"Scheme '{name}' not registered.")


class IHttpContextAccessor(Generic[TRequest, TResponse], ABC):
    response_class: TResponse
    context_class: type[HttpContext[TRequest, TResponse]]

    __slots__ = ("_http_context",)

    def __init__(self, request: TRequest, schemes: IAuthenticationSchemeProvider) -> None:
        self._http_context = self.context_class(request, self.response_class(None, status_code=204), schemes)  # type: ignore

    @property
    def http_context(self) -> HttpContext:
        """Gets or sets the current ``HttpContext``. Returns None if there is no active ``HttpContext``."""
        return self._http_context
