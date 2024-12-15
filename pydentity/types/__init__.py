from collections.abc import Callable
from datetime import datetime
from typing import TypeVar, Protocol, Optional, Union
from uuid import UUID

__all__ = (
    "Predicate",
    "Action",
    "GUID",
    "TKey",
    "UserProtokol",
    "UserRoleProtokol",
    "UserClaimProtokol",
    "UserTokenProtokol",
    "UserLoginProtokol",
    "RoleProtokol",
    "RoleClaimProtokol",
    "TUser",
    "TRole",
    "TUserRole",
    "TUserClaim",
    "TUserLogin",
    "TUserToken",
    "TRoleClaim",
    "TRequest",
    "TResponse",
)

TRequest = TypeVar("TRequest")
TResponse = TypeVar("TResponse")

_T = TypeVar("_T")
TKey = TypeVar(
    "TKey",
    int,
    str,
    UUID,
)

Predicate = Callable[[_T], bool]
Action = Callable[[_T], None]

GUID = Union[UUID, str]


class UserProtokol(Protocol[TKey]):
    access_failed_count: int
    concurrency_stamp: Optional[GUID]
    email: Optional[str]
    email_confirmed: bool
    id: TKey
    lockout_enabled: bool
    lockout_end: Optional[datetime]
    normalized_email: Optional[str]
    normalized_username: Optional[str]
    password_hash: Optional[str]
    phone_number: Optional[str]
    phone_number_confirmed: bool
    security_stamp: Optional[GUID]
    two_factor_enabled: bool
    username: Optional[str]


class RoleProtokol(Protocol[TKey]):
    concurrency_stamp: Optional[GUID]
    id: TKey
    name: Optional[str]
    normalized_name: Optional[str]


class UserRoleProtokol(Protocol[TKey]):
    user_id: TKey
    role_id: TKey


class UserClaimProtokol(Protocol[TKey]):
    claim_type: Optional[str]
    claim_value: Optional[str]
    user_id: TKey


class UserLoginProtokol(Protocol[TKey]):
    login_provider: str
    provider_key: str
    provider_display_name: Optional[str]
    user_id: TKey


class UserTokenProtokol(Protocol[TKey]):
    login_provider: str
    name: str
    value: Optional[str]
    user_id: TKey


class RoleClaimProtokol(Protocol[TKey]):
    claim_type: Optional[str]
    claim_value: Optional[str]
    role_id: TKey


TUser = TypeVar("TUser", bound=UserProtokol)  # type: ignore
TRole = TypeVar("TRole", bound=RoleProtokol)  # type: ignore
TUserRole = TypeVar("TUserRole", bound=UserRoleProtokol)  # type: ignore
TUserClaim = TypeVar("TUserClaim", bound=UserClaimProtokol)  # type: ignore
TUserLogin = TypeVar("TUserLogin", bound=UserLoginProtokol)  # type: ignore
TUserToken = TypeVar("TUserToken", bound=UserTokenProtokol)  # type: ignore
TRoleClaim = TypeVar("TRoleClaim", bound=RoleClaimProtokol)  # type: ignore
