from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable, Generator, Sequence
from datetime import timedelta, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.exceptions import InvalidKeyError, ExpiredSignatureError, PyJWTError

from pydentity.authentication import AuthenticationResult
from pydentity.authentication.interfaces import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import Claim, ClaimsPrincipal, ClaimsIdentity
from pydentity.types import TRequest, TResponse

__all__ = (
    "JWTSecurityToken",
    "JWTBearerAuthenticationHandler",
    "TokenValidationParameters",
    "ITokenClaimsSerializer",
)

KeyType = RSAPrivateKey | EllipticCurvePrivateKey | Ed25519PrivateKey | Ed448PrivateKey | str | bytes

STANDARD_CLAIM = ("aud", "exp", "iat", "iss", "jti", "nbf", "sub")


class ITokenClaimsSerializer(ABC):
    @abstractmethod
    def dumps(self, claims: list[Claim]) -> dict[str, Any]:
        pass

    @abstractmethod
    def loads(self, payload: dict[str, Any]) -> Generator[Claim]:
        pass


class DefaultTokenClaimSerializer(ITokenClaimsSerializer):
    def dumps(self, claims: list[Claim]) -> dict[str, Any]:
        _claims = defaultdict(list)
        for claim in claims:
            _claims[claim.type].append(claim.value)
        return _claims

    def loads(self, payload: dict[str, Any], exclude_claims: Sequence[str] = STANDARD_CLAIM) -> Generator[Claim]:
        for key, value in payload.copy().items():
            if key in exclude_claims:
                continue
            yield from (Claim(key, v) for v in value)
            payload.pop(key)


class JWTSecurityToken(dict[str, Any]):
    claims_serializer: ITokenClaimsSerializer = DefaultTokenClaimSerializer()

    def __init__(
            self,
            signin_key: KeyType,
            algorithm: str = "HS256",
            audience: str | None = None,
            claims: Iterable[Claim] | None = None,
            expires: datetime | int | None = None,
            headers: dict[str, Any] | None = None,
            issuer: str | None = None,
            issuer_at: datetime | int | None = None,
            not_before: datetime | int | None = None,
            subject: str | None = None,
            **kwargs: Any,
    ) -> None:
        super().__init__(kwargs)
        self._signing_key = signin_key
        self.algorithm = algorithm
        self.headers = headers
        self.claims = claims or []
        self.expires = expires
        self.not_before = not_before
        self.audience = audience
        self.issuer = issuer
        self.issuer_at = issuer_at
        self.subject = subject

    @property
    def audience(self) -> str | None:
        return self.get("aud")

    @audience.setter
    def audience(self, value: str | None) -> None:
        self._set_or_remove("aud", value)

    @property
    def expires(self) -> datetime | int | None:
        return self.get("exp")

    @expires.setter
    def expires(self, value: datetime | int | None) -> None:
        self._set_or_remove("exp", value)

    @property
    def issuer(self) -> str | None:
        return self.get("iss")

    @issuer.setter
    def issuer(self, value: str | None) -> None:
        self._set_or_remove("iss", value)

    @property
    def issuer_at(self) -> datetime | int | None:
        return self.get("iat")

    @issuer_at.setter
    def issuer_at(self, value: datetime | int | None) -> None:
        self._set_or_remove("iat", value)

    @property
    def not_before(self) -> datetime | int | None:
        return self.get("nbf")

    @not_before.setter
    def not_before(self, value: datetime | int | None) -> None:
        self._set_or_remove("nbf", value)

    @property
    def subject(self) -> str | None:
        return self.get("sub")

    @subject.setter
    def subject(self, value: str | None) -> None:
        self._set_or_remove("sub", value)

    def _set_or_remove(self, key: str, value: Any) -> None:
        if value is not None:
            self[key] = value
        elif key in self:
            del self[key]

    def encode(self) -> str:
        if self.expires and self.not_before and self.not_before >= self.expires:
            raise ExpiredSignatureError(f"Expires: '{self.expires}' must be after not_before: '{self.not_before}'.")

        if not self._signing_key:
            raise InvalidKeyError()

        self.update(self.claims_serializer.dumps(self.claims))
        return jwt.encode(self, self._signing_key, self.algorithm, self.headers)

    @classmethod
    def decode(
            cls,
            token: str | bytes,
            key: KeyType,
            algorithms: list[str] | None = None,
            options: dict[str, Any] | None = None,
            audience: str | Iterable[str] | None = None,
            issuer: str | list[str] | None = None,
            leeway: float | timedelta = 0,
    ) -> "JWTSecurityToken":
        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms or ["HS256"],
            audience=audience,
            issuer=issuer,
            options=options,
            leeway=leeway,
        )
        return JWTSecurityToken(
            signin_key=key, claims=[*cls.claims_serializer.loads(payload)] or None, **payload
        )


class TokenValidationParameters:
    """Contains a set of parameters that are used by a JWTBearerAuthenticationHandler when validating a security token."""

    __slots__ = (
        "issuer_signing_key",
        "leeway",
        "options",
        "valid_algorithms",
        "valid_audiences",
        "valid_issuers",
    )

    def __init__(
            self,
            issuer_signing_key: KeyType,
            valid_algorithms: list[str] | None = None,
            valid_audiences: str | Iterable[str] | None = None,
            valid_issuers: str | list[str] | None = None,
            options: dict[str, Any] | None = None,
            leeway: float | timedelta = 0,
    ) -> None:
        self.issuer_signing_key = issuer_signing_key
        self.valid_algorithms = valid_algorithms or ["HS256"]
        self.valid_audiences = valid_audiences
        self.valid_issuers = valid_issuers
        self.options = options
        self.leeway = leeway


def _get_authorization_scheme_param(authorization_header_value: str | None) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def _create_principal_from_jwt_security_token(token: JWTSecurityToken) -> ClaimsPrincipal:
    identity = ClaimsIdentity("AuthenticationTypes.Federation")
    if token.claims:
        identity.add_claims(*token.claims)
    return ClaimsPrincipal(identity)


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("_validation_parameters",)

    def __init__(self, validation_parameters: TokenValidationParameters) -> None:
        self._validation_parameters = validation_parameters

    async def authenticate(self, context: HttpContext[TRequest, TResponse], scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = _get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            return AuthenticationResult(ClaimsPrincipal(), {})

        try:
            jwt_token = JWTSecurityToken.decode(
                token,
                key=self._validation_parameters.issuer_signing_key,
                algorithms=self._validation_parameters.valid_algorithms,
                audience=self._validation_parameters.valid_audiences,
                issuer=self._validation_parameters.valid_issuers,
                options=self._validation_parameters.options,
                leeway=self._validation_parameters.leeway,
            )
            return AuthenticationResult(_create_principal_from_jwt_security_token(jwt_token), {})
        except PyJWTError:
            return AuthenticationResult(ClaimsPrincipal(), {})

    async def sign_in(
            self, context: HttpContext[TRequest, TResponse], scheme: str, principal: ClaimsPrincipal, **properties: Any
    ) -> None:
        pass

    async def sign_out(self, context: HttpContext[TRequest, TResponse], scheme: str) -> None:
        pass
