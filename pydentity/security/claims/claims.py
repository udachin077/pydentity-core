import inspect
from collections import defaultdict
from collections.abc import Iterable, Generator
from typing import Any, Final, Literal, overload, Self, Callable

from pydentity.exc import ArgumentNullException
from pydentity.security.claims.claim_types import ClaimTypes
from pydentity.utils import is_null_or_whitespace

__all__ = (
    "Claim",
    "ClaimsIdentity",
    "ClaimsPrincipal",
)

DEFAULT_ISSUER = "LOCAL AUTHORITY"


class Claim:
    """
    A Claim is a statement about an entity by an Issuer.
    A Claim consists of a Type, Value, a Subject and an Issuer.
    """

    __slots__ = ("_type", "_value", "_subject", "_issuer", "_original_issuer")

    def __init__(
        self,
        claim_type: str,
        claim_value: Any,
        issuer: str = DEFAULT_ISSUER,
        original_issuer: str | None = None,
        identity: "ClaimsIdentity | None" = None,
    ) -> None:
        """

        :param claim_type: The claim type.
        :param claim_value: The claim value.
        :param issuer: The claim issuer.
        :param identity:
        """
        if is_null_or_whitespace(claim_value):
            raise ArgumentNullException("claim_type")

        if claim_value is None:
            raise ArgumentNullException("claim_value")

        self._type = claim_type
        self._value = claim_value
        self._subject = identity
        self._issuer = issuer
        self._original_issuer = original_issuer or issuer

    @property
    def type(self) -> str:
        """Gets the claim type of the *Claim*."""
        return self._type

    @property
    def value(self) -> Any:
        """Gets the claim value of the *Claim*."""
        return self._value

    @property
    def subject(self) -> "ClaimsIdentity | None":
        """Gets the subject of the *Claim*."""
        return self._subject

    @property
    def issuer(self) -> str:
        """Gets the issuer of the *Claim*."""
        return self._issuer

    @property
    def original_issuer(self) -> str:
        """Gets the original issuer of the *Claim*."""
        return self._original_issuer

    def clone(self, identity: "ClaimsIdentity") -> Self:
        """
        Creates a new instance *Claim* with values copied from this object.

        :param identity: The value for *Claim.subject*, which is the *ClaimsIdentity* that has these claims.
        :return:
        """
        return self.__class__(self.type, self.value, self.issuer, self.original_issuer, identity)

    def dump(self, exclude_default: bool = True) -> dict[str, Any]:
        if not exclude_default:
            return {
                "claim_type": self.type,
                "claim_value": self.value,
                "issuer": self.issuer,
                "original_issuer": self.original_issuer,
            }

        result = {"claim_type": self.type, "claim_value": self.value}

        if self.issuer != DEFAULT_ISSUER:
            result.update({"issuer": self.issuer})

        if self.original_issuer != DEFAULT_ISSUER:
            result.update({"original_issuer": self.original_issuer})

        return result

    @classmethod
    def load(cls, payload: dict[str, Any]) -> Self:
        return cls(**payload)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.type}:{self.value} object at {hex(id(self))}>"


class ClaimsIdentity:
    __slots__ = (
        "_authentication_type",
        "_claims",
        "_name_claim_type",
        "_role_claim_type",
    )

    DEFAULT_NAME_CLAIM_TYPE: Final[str] = ClaimTypes.Name
    DEFAULT_ROLE_CLAIM_TYPE: Final[str] = ClaimTypes.Role

    def __init__(
        self,
        authentication_type: str | None = None,
        *claims: Claim,
        name_claim_type: str | None = None,
        role_claim_type: str | None = None,
    ) -> None:
        self._authentication_type = authentication_type
        self._name_claim_type: str = name_claim_type or self.DEFAULT_NAME_CLAIM_TYPE
        self._role_claim_type: str = role_claim_type or self.DEFAULT_ROLE_CLAIM_TYPE
        self._claims: set[Claim] = set()
        self.add_claims(*claims)

    @property
    def name(self) -> str | None:
        return self.find_first_value(self._name_claim_type)

    @property
    def is_authenticated(self) -> bool:
        return bool(self._authentication_type)

    @property
    def authentication_type(self) -> str | None:
        return self._authentication_type

    @property
    def name_claim_type(self) -> str:
        return self._name_claim_type

    @property
    def role_claim_type(self) -> str:
        return self._role_claim_type

    @property
    def claims(self) -> Generator[Claim]:
        for claim in self._claims:
            yield claim

    def add_claims(self, *claims: Claim) -> None:
        if not claims:
            return

        for claim in claims:
            if claim.subject is self:
                self._claims.add(claim)
            else:
                self._claims.add(claim.clone(self))

    def remove_claim(self, claim: Claim) -> None:
        if claim is None:
            raise ArgumentNullException("claim")

        self._claims.remove(claim)

    @overload
    def find_all(self, predicate: Callable[[Claim], bool], /) -> Generator[Claim]:
        """
        Retrieves a *Claim*'s where match matches each claim.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a *Claim*'s where each *claim_type* equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_all(self, _object: str | Callable[[Claim], bool]) -> Generator[Claim]:
        if inspect.isfunction(_object):
            yield from filter(_object, self._claims)

        if isinstance(_object, str):
            yield from filter(lambda c: c.type == _object, self._claims)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first(self, predicate: Callable[[Claim], bool], /) -> Claim | None:
        """
        Retrieves the first *Claim*'s that match matches.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None:
        """
        Retrieves the first *Claim*'s where the *Claim.type* equals *claim_type*.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first(self, _object: str | Callable[[Claim], bool]) -> Claim | None:
        if inspect.isfunction(_object):
            return _find_first(self._claims, _object)

        if isinstance(_object, str):
            return _find_first(self._claims, lambda c: c.type == _object)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first_value(self, predicate: Callable[[Claim], bool], /) -> Any | None:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Any | None:
        """
        Return the claim value for the first claim with the specified *claim_type* if it exists, null otherwise.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first_value(self, _object: str | Callable[[Claim], bool]) -> Any | None:
        if inspect.isfunction(_object):
            return _find_first_value(self._claims, _object)

        if isinstance(_object, str):
            return _find_first_value(self._claims, lambda c: c.type == _object)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def has_claim(self, predicate: Callable[[Claim], bool], /) -> bool:
        """
        Determines if a claim is contained within all the *ClaimsIdentities* in this *ClaimPrincipal*.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of *claim_type* AND *claim_value* exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, *args: str | Callable[[Claim], bool]) -> bool:
        result = _has_claim(self._claims, *args)

        if result is not None:
            return result

        raise ValueError("The number of arguments can be 1 ('Callable[[Claim], bool]') or 2 ('str' and 'Any')")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} auth:{self.authentication_type} object at {hex(id(self))}>"


class ClaimsPrincipal:
    __slots__ = ("_identities",)

    def __init__(self, *identities: ClaimsIdentity) -> None:
        self._identities: list[ClaimsIdentity] = list(identities) if identities else []

    @property
    def identities(self) -> tuple[ClaimsIdentity, ...]:
        return tuple(self._identities)

    @property
    def identity(self) -> ClaimsIdentity | None:
        try:
            return self._identities[0]
        except IndexError:
            return None

    @property
    def claims(self) -> Generator[Claim]:
        for identity in self._identities:
            yield from identity.claims

    @overload
    def find_all(self, predicate: Callable[[Claim], bool], /) -> Generator[Claim]:
        """
        Retrieves a *Claim*'s where match matches each claim.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]:
        """
        Retrieves a *Claim*'s where each *Claim.type* equals claim_type.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_all(self, _object: str | Callable[[Claim], bool]) -> Generator[Claim]:
        if inspect.isfunction(_object):
            yield from filter(_object, self.claims)

        if isinstance(_object, str):
            yield from filter(lambda c: c.type == _object, self.claims)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first(self, predicate: Callable[[Claim], bool], /) -> Claim | None:
        """
        Retrieves the first *Claim*'s that match matches.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None:
        """
        Retrieves the first *Claim*'s where the *Claim.type* equals *claim_type*.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first(self, _object: str | Callable[[Claim], bool]) -> Claim | None:
        if inspect.isfunction(_object):
            return _find_first(self.claims, _object)

        if isinstance(_object, str):
            return _find_first(self.claims, lambda c: c.type == _object)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first_value(self, predicate: Callable[[Claim], bool], /) -> Any | None:
        """
        Return the claim value for the first claim with the specified match if it exists, null otherwise.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Any | None:
        """
        Return the claim value for the first claim with the specified *claim_type* if it exists, null otherwise.

        :param claim_type: The type of the claim to match.
        :return:
        """
        ...

    def find_first_value(self, _object: str | Callable[[Claim], bool]) -> Any | None:
        if inspect.isfunction(_object):
            return _find_first_value(self.claims, _object)

        if isinstance(_object, str):
            return _find_first_value(self.claims, lambda c: c.type == _object)

        raise ValueError("'_object' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def has_claim(self, predicate: Callable[[Claim], bool], /) -> bool:
        """
        Determines if a claim is contained within all the *ClaimsIdentities* in this *ClaimPrincipal*.

        :param predicate: The predicate that performs the matching logic.
        :return:
        """
        ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool:
        """
        Determines if a claim of *claim_type* AND *claim_value* exists in any of the identities.

        :param claim_type: The type of the claim to match.
        :param claim_value:  The value of the claim to match.
        :return:
        """
        ...

    def has_claim(self, *args: str | Callable[[Claim], bool]) -> bool:
        result = _has_claim(self.claims, *args)

        if result is not None:
            return result

        raise ValueError("The number of arguments can be 1 ('Callable[[Claim], bool]') or 2 ('str' and 'Any')")

    def add_identities(self, *identities: ClaimsIdentity) -> None:
        """
        Adds *ClaimsIdentity* to the internal list.

        :param identities:
        :return:
        """
        if not identities:
            raise ArgumentNullException("identities")

        self._identities.extend(identities)

    def is_in_role(self, role: str) -> bool:
        """
        *is_in_role* answers the question: does an builders this principal possesses
        contains a claim of type *role_claim_type* where the value is "==" to the role.

        :param role: The role to check for.
        :return:
        """
        for _identity in self._identities:
            if _identity.has_claim(_identity.role_claim_type, role):
                return True

        return False

    def is_in_roles(self, *roles: str, mode: Literal["all", "any"] = "all") -> bool:
        """
        *is_in_role* answers the question: does an builders this principal possesses
        contains a claim of type *role_claim_type* where the value is "==" to the roles.

        :param roles: The roles to check for.
        :param mode: Verification mode.
        :return:
        """
        if not roles:
            raise ArgumentNullException("roles")

        if mode == "all":
            return all(False for role in roles if not self.is_in_role(role))

        if mode == "any":
            return any(True for role in roles if self.is_in_role(role))

        raise ValueError("The 'mode' must be 'all' or 'any'")

    def dump(self, exclude_default: bool = True, sep: str = "$") -> dict[str, Any]:
        result: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for identity in self.identities:
            key = f"%s{sep}%s{sep}%s" % (
                identity.authentication_type,
                identity.name_claim_type,
                identity.role_claim_type,
            )

            for claim in identity.claims:
                result[key].append(claim.dump(exclude_default=exclude_default))

        return result

    @classmethod
    def load(cls, payload: dict[str, list[dict[str, Any]]], sep: str = "$") -> Self:
        identities: list[ClaimsIdentity] = []

        for name, claims in payload.items():
            authentication_type, name_claim_type, role_claim_type = name.rsplit(sep, maxsplit=2)
            identities.append(
                ClaimsIdentity(
                    authentication_type,
                    *(Claim.load(claim) for claim in claims),
                    name_claim_type=name_claim_type,
                    role_claim_type=role_claim_type,
                )
            )

        return cls(*identities)


def _find_first(claims: Iterable[Claim], predicate: Callable[[Claim], bool]) -> Claim | None:
    for claim in claims:
        if predicate(claim):
            return claim
    return None


def _find_first_value(claims: Iterable[Claim], predicate: Callable[[Claim], bool]) -> Any | None:
    claim = _find_first(claims, predicate)
    return claim.value if claim is not None else None


def _has_claim(claims: Iterable[Claim], *args: str | Callable[[Claim], bool]) -> bool | None:
    len_args = len(args)

    if len_args == 1 and inspect.isfunction(args[0]):
        return bool(_find_first(claims, args[0]))

    if len_args == 2 and isinstance(args[0], str):
        return bool(_find_first(claims, lambda c: c.type == args[0] and c.value == args[1]))

    return None
