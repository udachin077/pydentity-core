from datetime import datetime
from typing import TypeVar, Protocol
from uuid import UUID

__all__ = (
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
)

TKey = TypeVar("TKey")


class UserProtokol(Protocol[TKey]):
    access_failed_count: int
    concurrency_stamp: str | UUID | None
    email: str | None
    email_confirmed: bool
    id: TKey
    lockout_enabled: bool
    lockout_end: datetime | None
    normalized_email: str | None
    normalized_username: str | None
    password_hash: str | None
    phone_number: str | None
    phone_number_confirmed: bool
    security_stamp: str | UUID | None
    two_factor_enabled: bool
    username: str | None


class RoleProtokol(Protocol[TKey]):
    concurrency_stamp: str | UUID | None
    id: TKey
    name: str | None
    normalized_name: str | None


class UserRoleProtokol(Protocol[TKey]):
    user_id: TKey
    role_id: TKey


class UserClaimProtokol(Protocol[TKey]):
    claim_type: str | None
    claim_value: str | None
    user_id: TKey


class UserLoginProtokol(Protocol[TKey]):
    login_provider: str
    provider_key: str
    provider_display_name: str | None
    user_id: TKey


class UserTokenProtokol(Protocol[TKey]):
    login_provider: str
    name: str
    value: str | None
    user_id: TKey


class RoleClaimProtokol(Protocol[TKey]):
    claim_type: str | None
    claim_value: str | None
    role_id: TKey


TUser = TypeVar("TUser", bound=UserProtokol)
TRole = TypeVar("TRole", bound=RoleProtokol)
TUserRole = TypeVar("TUserRole", bound=UserRoleProtokol)
TUserClaim = TypeVar("TUserClaim", bound=UserClaimProtokol)
TUserLogin = TypeVar("TUserLogin", bound=UserLoginProtokol)
TUserToken = TypeVar("TUserToken", bound=UserTokenProtokol)
TRoleClaim = TypeVar("TRoleClaim", bound=RoleClaimProtokol)
