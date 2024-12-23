import json
from datetime import timedelta
from functools import lru_cache
from typing import Literal, Any

from pydentity.authentication import DefaultAuthenticationDataProtector, AuthenticationResult
from pydentity.authentication.interfaces import IAuthenticationHandler, IAuthenticationDataProtector
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal
from pydentity.security.claims.serializer import principal_dumps, principal_loads
from pydentity.utils import datetime

__all__ = (
    "CookieAuthenticationOptions",
    "CookieAuthenticationHandler",
)


def _create_expires(seconds: float | None) -> int | None:
    return int(datetime.utcnow().add_seconds(seconds).timestamp()) if seconds is not None else None


@lru_cache
def _get_auth_cookie_name(scheme: str, name: str | None = None) -> str:
    return name or scheme


def _split_auth_cookie_value(key: str, value: str, chunk_size: int = 2048) -> dict[str, str]:
    if len(value) <= chunk_size:
        return {key: value}

    chunks = [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)]
    cookies = {key: f"chunks-{len(chunks)}"}
    cookies.update({f"{key}C{i}": chunk for i, chunk in enumerate(chunks, 1)})
    return cookies


def _join_auth_cookie_value(cookies: dict[str, str], key: str) -> str:
    chunks_count = int(cookies[key].removeprefix("chunks-"))
    return "".join(cookies[f"{key}C{i}"] for i in range(1, chunks_count + 1, 1))


class CookieAuthenticationOptions:
    __slots__ = (
        "name",
        "max_age_timedelta",
        "expires_timedelta",
        "path",
        "domain",
        "httponly",
        "secure",
        "samesite",
    )

    def __init__(
        self,
        name: str | None = None,
        max_age_timedelta: timedelta | int | None = None,
        expires_timedelta: timedelta | int | None = None,
        path: str = "/",
        domain: str | None = None,
        httponly: bool = True,
        secure: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        """
        Cookie parameters that will be used by the ``CookieAuthenticationHandler`` to receive and set cookies.

        :param name: A string that will be the cookie's key.
        :param max_age_timedelta: An integer that defines the lifetime of the cookie in seconds. A negative integer or a value of 0 will discard the cookie immediately.
            The time interval that will be set when logging in using ``SignInManager`` if the `is_persistent` parameter is set to `True`. Defaults to 7 days.
        :param expires_timedelta: Timedelta, which defines the interval until the cookie expires.
        :param path: A string that specifies the subset of routes to which the cookie will apply.
        :param domain: A string that specifies the domain for which the cookie is valid.
        :param httponly: A bool indicating that the cookie cannot be accessed via JavaScript through ``Document.cookie`` property, the ``XMLHttpRequest`` or Request APIs.
        :param secure: A bool indicating that the cookie will only be sent to the server if request is made using SSL and the HTTPS protocol.
        :param samesite: A string that specifies the samesite strategy for the cookie. Valid values are 'lax', 'strict' and 'none'. Defaults to 'lax'.
        """
        if max_age_timedelta is None:
            self.max_age_timedelta = timedelta(days=7).total_seconds()
        elif isinstance(max_age_timedelta, timedelta):
            self.max_age_timedelta = max_age_timedelta.total_seconds()
        else:
            self.max_age_timedelta = max_age_timedelta

        if isinstance(expires_timedelta, timedelta):
            self.expires_timedelta = expires_timedelta.total_seconds()
        else:
            self.expires_timedelta = expires_timedelta

        self.name = name
        self.path = path
        self.domain = domain
        self.httponly = httponly
        self.secure = secure
        self.samesite = samesite

    def expires(self, use_max_age: bool = False) -> int | None:
        return _create_expires(self.max_age_timedelta if use_max_age else self.expires_timedelta)


class CookieAuthenticationHandler(IAuthenticationHandler):
    __slots__ = (
        "options",
        "protector",
    )

    def __init__(
        self, options: CookieAuthenticationOptions | None = None, protector: IAuthenticationDataProtector | None = None
    ) -> None:
        self.options = options or CookieAuthenticationOptions()
        self.protector = protector or DefaultAuthenticationDataProtector()

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        return self._decode_authentication_cookie(scheme, context.request.cookies)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        context.response.headers["Cache-Control"] = "no-cache,no-store"
        context.response.headers["Pragma"] = "no-cache"
        cookies = self._encode_authentication_cookie(scheme, principal, **properties)

        for key, value in cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=self.options.expires(use_max_age=properties.get("is_persistent", False)),
                path=self.options.path,
                domain=self.options.domain,
                secure=self.options.secure,
                httponly=self.options.httponly,
                samesite=self.options.samesite,
            )

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        for key in context.request.cookies:
            if key.startswith(_get_auth_cookie_name(scheme, self.options.name)):
                context.response.delete_cookie(key)

    def _encode_authentication_cookie(
        self, scheme: str, principal: ClaimsPrincipal, **properties: Any
    ) -> dict[str, str]:
        data = {"principal": principal_dumps(principal)}

        if properties:
            data.update({"properties": properties})

        protected_data = self.protector.protect(json.dumps(data, separators=(",", ":")))
        key = _get_auth_cookie_name(scheme, self.options.name)
        return _split_auth_cookie_value(key, protected_data)

    def _decode_authentication_cookie(self, scheme: str, cookies: dict[str, str]) -> AuthenticationResult:
        key = _get_auth_cookie_name(scheme, self.options.name)

        if value := cookies.get(key):
            if value.startswith("chunks-"):
                value = _join_auth_cookie_value(cookies, key)

            unprotected_data = json.loads(self.protector.unprotect(value))
            properties = unprotected_data.pop("properties", {})

            if p := unprotected_data.pop("principal"):
                principal = principal_loads(p)
            else:
                principal = ClaimsPrincipal()

            return AuthenticationResult(principal, properties)

        return AuthenticationResult(ClaimsPrincipal(), {})
