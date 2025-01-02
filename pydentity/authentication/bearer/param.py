from collections import defaultdict
from datetime import timedelta, datetime
from typing import Any, Iterable, Sequence, Generator, Self

import jwt
from jwt import ExpiredSignatureError, InvalidKeyError

from pydentity.security.claims import Claim

__all__ = (
    "TokenValidationParameters",
    "JWTSecurityToken",
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
        issuer_signing_key: Any,
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


STANDARD_CLAIMS: Sequence[str] = ("aud", "exp", "iat", "iss", "jti", "nbf", "sub")


def _claims_dump(claims: Iterable[Claim]) -> dict[str, Any]:
    _claims = defaultdict(list)
    for claim in claims:
        _claims[claim.type].append(claim.value)
    return _claims


def _claims_load(payload: dict[str, Any]) -> Generator[Claim]:
    for key, value in payload.copy().items():
        if key in STANDARD_CLAIMS:
            continue
        yield from (Claim(key, v) for v in value)
        payload.pop(key)


class JWTSecurityToken(dict[str, Any]):
    def __init__(
        self,
        signing_key: Any,
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
        self._signing_key = signing_key
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
        self._update_or_remove("aud", value)

    @property
    def expires(self) -> datetime | int | None:
        return self.get("exp")

    @expires.setter
    def expires(self, value: datetime | int | None) -> None:
        self._update_or_remove("exp", value)

    @property
    def issuer(self) -> str | None:
        return self.get("iss")

    @issuer.setter
    def issuer(self, value: str | None) -> None:
        self._update_or_remove("iss", value)

    @property
    def issuer_at(self) -> datetime | int | None:
        return self.get("iat")

    @issuer_at.setter
    def issuer_at(self, value: datetime | int | None) -> None:
        self._update_or_remove("iat", value)

    @property
    def not_before(self) -> datetime | int | None:
        return self.get("nbf")

    @not_before.setter
    def not_before(self, value: datetime | int | None) -> None:
        self._update_or_remove("nbf", value)

    @property
    def subject(self) -> str | None:
        return self.get("sub")

    @subject.setter
    def subject(self, value: str | None) -> None:
        self._update_or_remove("sub", value)

    def _update_or_remove(self, key: str, value: Any) -> None:
        if value is None:
            self.pop(key, None)
        else:
            self[key] = value

    def encode(self) -> str:
        not_before = self.not_before
        expires = self.expires

        if expires and not_before:
            nb = not_before.timestamp() if isinstance(not_before, datetime) else not_before
            exp = expires.timestamp() if isinstance(expires, datetime) else expires

            if nb >= exp:
                raise ExpiredSignatureError(f"Expires: '{self.expires}' must be after not_before: '{self.not_before}'.")

        if not self._signing_key:
            raise InvalidKeyError()

        self.update(_claims_dump(self.claims))
        return jwt.encode(self, self._signing_key, self.algorithm, self.headers)

    @classmethod
    def decode(
        cls,
        token: str | bytes,
        signing_key: Any,
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Sequence[str] | None = None,
        leeway: float | timedelta = 0,
    ) -> Self:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=algorithms or ["HS256"],
            audience=audience,
            issuer=issuer,
            options=options,
            leeway=leeway,
        )
        return cls(
            signing_key="",
            claims=tuple(_claims_load(payload)),
            **payload,
        )
