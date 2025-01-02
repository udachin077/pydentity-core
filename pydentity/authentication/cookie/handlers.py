from functools import cache
from typing import Any

from itsdangerous import URLSafeSerializer

from pydentity.authentication.cookie.param import CookieAuthenticationOptions
from pydentity.authentication.interfaces import IAuthenticationHandler, IAuthenticationDataProtector
from pydentity.authentication.result import AuthenticationResult
from pydentity.dataprotector import BaseDataProtector, AesBackend
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal

__all__ = ("CookieAuthenticationHandler",)


@cache
def get_authentication_cookie_name(scheme: str, name: str | None = None) -> str:
    return name or scheme


def get_authentication_cookie_chunks(key: str, value: str, chunk_size: int = 2048) -> dict[str, str]:
    if len(value) <= chunk_size:
        return {key: value}

    chunks = [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)]
    cookies = {key: f"chunks-{len(chunks)}"}
    cookies.update({f"{key}C{i}": chunk for i, chunk in enumerate(chunks, 1)})
    return cookies


def get_authentication_token_from_cookies(key: str, cookies: dict[str, str]) -> str | None:
    token_value = cookies.get(key)

    if token_value is None or not token_value.startswith("chunks-"):
        return token_value

    chunks_count = int(token_value.removeprefix("chunks-"))
    return "".join(cookies[f"{key}C{i}"] for i in range(1, chunks_count + 1, 1))


class CookieAuthenticationHandler(IAuthenticationHandler):
    __slots__ = (
        "options",
        "protector",
        "serializer",
    )

    def __init__(
        self,
        options: CookieAuthenticationOptions | None = None,
        protector: IAuthenticationDataProtector | None = None,
        serializer: Any | None = None,
    ) -> None:
        self.options = options or CookieAuthenticationOptions()
        self.protector = protector or BaseDataProtector(AesBackend())
        self.serializer = serializer or URLSafeSerializer("cookie.serializer")

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        token_key = get_authentication_cookie_name(scheme, self.options.name)
        token_value = get_authentication_token_from_cookies(token_key, context.request.cookies)

        if token_value is None:
            return AuthenticationResult(ClaimsPrincipal(), {})

        unprotected = self.protector.unprotect(token_value)
        principal, properties = self._deserialize(unprotected)
        return AuthenticationResult(principal, properties)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        context.response.headers["Cache-Control"] = "no-cache,no-store"
        context.response.headers["Pragma"] = "no-cache"

        self.options.use_max_age = properties.get("is_persistent", False)

        token_key = get_authentication_cookie_name(scheme, self.options.name)
        serialized = self._serialize(principal, **properties)
        token_value = self.protector.protect(serialized)
        authentication_cookies = get_authentication_cookie_chunks(token_key, token_value)

        for key, value in authentication_cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=self.options.expires,
                path=self.options.path,
                domain=self.options.domain,
                secure=self.options.secure,
                httponly=self.options.httponly,
                samesite=self.options.samesite,
            )

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        for key in context.request.cookies:
            token_key = get_authentication_cookie_name(scheme, self.options.name)

            if key.startswith(token_key):
                context.response.delete_cookie(key)

    def _serialize(self, principal: ClaimsPrincipal, **properties: Any) -> str:
        payload = {"principal": principal.dump()}
        payload.update({"props": properties})
        return self.serializer.dumps(payload)

    def _deserialize(self, plaintext: str) -> tuple[ClaimsPrincipal, dict[str, Any]]:
        deserialized = self.serializer.loads(plaintext)
        properties = deserialized.pop("props", {})

        if principal := deserialized.pop("principal", None):
            return ClaimsPrincipal.load(principal), properties

        return ClaimsPrincipal(), properties
