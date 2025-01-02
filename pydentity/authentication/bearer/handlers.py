from typing import Any

from jwt import PyJWTError

from pydentity.authentication.result import AuthenticationResult
from pydentity.authentication.bearer.param import TokenValidationParameters, JWTSecurityToken
from pydentity.authentication.interfaces import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity

__all__ = ("JWTBearerAuthenticationHandler",)


def get_authorization_scheme_param(authorization_header_value: str | None) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, token = authorization_header_value.partition(" ")
    return scheme, token


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("_validation_parameters",)

    def __init__(self, validation_parameters: TokenValidationParameters) -> None:
        self._validation_parameters = validation_parameters

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            return AuthenticationResult(ClaimsPrincipal(), {})

        try:
            jwt_token = JWTSecurityToken.decode(
                token,
                signing_key=self._validation_parameters.issuer_signing_key,
                algorithms=self._validation_parameters.valid_algorithms,
                audience=self._validation_parameters.valid_audiences,
                issuer=self._validation_parameters.valid_issuers,
                options=self._validation_parameters.options,
                leeway=self._validation_parameters.leeway,
            )
        except PyJWTError:
            return AuthenticationResult(ClaimsPrincipal(), {})

        identity = ClaimsIdentity("AuthenticationTypes.Federation", *jwt_token.claims)
        return AuthenticationResult(ClaimsPrincipal(identity), {})

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties: Any) -> None:
        pass

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass
