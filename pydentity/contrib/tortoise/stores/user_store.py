from datetime import datetime
from typing import Type, Generic, Final, Any
from uuid import uuid4

from tortoise import BaseDBAsyncClient

import pydentity.resources as res
from pydentity.exc import InvalidOperationException, PersonalDataError
from pydentity.identity_result import IdentityResult
from pydentity.interfaces.stores import (
    IUserAuthenticationTokenStore,
    IUserAuthenticatorKeyStore,
    IUserClaimStore,
    IUserEmailStore,
    IUserLockoutStore,
    IUserLoginStore,
    IUserPasswordStore,
    IUserPersonalDataStore,
    IUserPhoneNumberStore,
    IUserRoleStore,
    IUserSecurityStampStore,
    IUserStore,
    IUserTwoFactorRecoveryCodeStore,
    IUserTwoFactorStore,
)
from pydentity.security.claims import Claim
from pydentity.types import TUser, TRole, TUserRole, TUserLogin, TUserClaim, TUserToken

__all__ = ("UserStore",)

from pydentity.user_login_info import UserLoginInfo


class UserStore(
    IUserAuthenticationTokenStore[TUser],
    IUserAuthenticatorKeyStore[TUser],
    IUserClaimStore[TUser],
    IUserEmailStore[TUser],
    IUserLockoutStore[TUser],
    IUserLoginStore[TUser],
    IUserPasswordStore[TUser],
    IUserPersonalDataStore[TUser],
    IUserPhoneNumberStore[TUser],
    IUserRoleStore[TUser],
    IUserSecurityStampStore[TUser],
    IUserTwoFactorRecoveryCodeStore[TUser],
    IUserTwoFactorStore[TUser],
    IUserStore[TUser],
    Generic[TUser],
):
    user_model: Type[TUser]
    role_model: Type[TRole]
    user_role_model: Type[TUserRole]
    user_claim_model: Type[TUserClaim]
    user_login_model: Type[TUserLogin]
    user_token_model: Type[TUserToken]

    INTERNAL_LOGIN_PROVIDER: Final[str] = "[Pydentity:UserStore]"
    AUTHENTICATOR_KEY_TOKEN_NAME: Final[str] = "[Pydentity:AuthenticatorKey]"
    RECOVERY_CODE_TOKEN_NAME: Final[str] = "[Pydentity:RecoveryCodes]"

    def __init__(self, transaction: BaseDBAsyncClient = None):
        self.transaction = transaction

    def create_model_from_dict(self, **kwargs) -> TUser:
        return self.user_model(**kwargs)

    async def refresh(self, user: TUser):
        await user.refresh_from_db(using_db=self.transaction)

    async def all(self) -> list[TUser]:
        return await self.user_model.all(using_db=self.transaction)

    async def create(self, user: TUser) -> IdentityResult:
        await user.save(using_db=self.transaction)
        await self.refresh(user)
        return IdentityResult.success()

    async def update(self, user: TUser) -> IdentityResult:
        user.concurrency_stamp = str(uuid4())
        await user.save(using_db=self.transaction)
        await self.refresh(user)
        return IdentityResult.success()

    async def delete(self, user: TUser) -> IdentityResult:
        await user.delete(using_db=self.transaction)
        return IdentityResult.success()

    async def find_by_id(self, user_id: Any) -> TUser | None:
        return await self.user_model.get_or_none(id=user_id, using_db=self.transaction)

    async def find_by_name(self, normalized_username: str) -> TUser | None:
        return await self.user_model.get_or_none(normalized_username=normalized_username, using_db=self.transaction)

    async def get_user_id(self, user: TUser) -> Any:
        return user.id

    async def get_username(self, user: TUser) -> str | None:
        return user.username

    async def set_username(self, user: TUser, username: str | None) -> None:
        user.username = username

    async def get_normalized_username(self, user: TUser) -> str | None:
        return user.normalized_username

    async def set_normalized_username(self, user: TUser, normalized_name: str | None) -> None:
        user.normalized_username = normalized_name

    async def find_by_email(self, normalized_email: str) -> TUser | None:
        return await self.user_model.get_or_none(normalized_email=normalized_email, using_db=self.transaction)

    async def get_email(self, user: TUser) -> str | None:
        return user.email

    async def set_email(self, user: TUser, email: str | None) -> None:
        user.email = email

    async def get_email_confirmed(self, user: TUser) -> bool:
        return user.email and user.email_confirmed

    async def get_normalized_email(self, user: TUser) -> str | None:
        return user.normalized_email

    async def set_normalized_email(self, user: TUser, normalized_email: str | None) -> None:
        user.normalized_email = normalized_email

    async def set_email_confirmed(self, user: TUser, confirmed: bool) -> None:
        user.email_confirmed = confirmed

    async def get_password_hash(self, user: TUser) -> str | None:
        return user.password_hash

    async def has_password(self, user: TUser) -> bool:
        return bool(user.password_hash)

    async def set_password_hash(self, user: TUser, password_hash: str) -> None:
        user.password_hash = password_hash

    async def get_phone_number(self, user: TUser) -> str | None:
        return user.phone_number

    async def set_phone_number(self, user: TUser, phone_number: str | None) -> None:
        user.phone_number = phone_number

    async def get_phone_number_confirmed(self, user: TUser) -> bool:
        return user.phone_number and user.phone_number_confirmed

    async def set_phone_number_confirmed(self, user: TUser, confirmed: bool) -> None:
        user.phone_number_confirmed = confirmed

    async def get_access_failed_count(self, user: TUser) -> int:
        return user.access_failed_count

    async def get_lockout_enabled(self, user: TUser) -> bool:
        return user.lockout_enabled

    async def get_lockout_end_date(self, user: TUser) -> datetime | None:
        lockout_end = user.lockout_end
        return lockout_end.astimezone() if lockout_end else None

    async def increment_access_failed_count(self, user: TUser) -> int:
        user.access_failed_count += 1
        return user.access_failed_count + 1

    async def reset_access_failed_count(self, user: TUser) -> None:
        user.access_failed_count = 0

    async def set_lockout_enabled(self, user: TUser, enabled: bool) -> None:
        user.lockout_enabled = enabled

    async def set_lockout_end_date(self, user: TUser, lockout_end: datetime | None) -> None:
        user.lockout_end = lockout_end

    async def get_security_stamp(self, user: TUser) -> str | None:
        return str(user.security_stamp) if user.security_stamp else None

    async def set_security_stamp(self, user: TUser, stamp: str) -> None:
        user.security_stamp = stamp

    async def add_to_role(self, user: TUser, normalized_role_name: str) -> None:
        if role := await self._find_role(normalized_role_name):
            await self.user_role_model(user_id=user.id, role_id=role.id).save(using_db=self.transaction)
            return

        raise InvalidOperationException(res.RoleNotFound.format(normalized_role_name))

    async def get_roles(self, user: TUser) -> list[str]:
        return await self.role_model.filter(users__id=user.id).using_db(self.transaction).values_list("name", flat=True)

    async def get_users_in_role(self, normalized_role_name: str) -> list[TUser]:
        if role := await self.role_model.get_or_none(normalized_name=normalized_role_name, using_db=self.transaction):
            return await role.users.all().using_db(self.transaction)

        raise InvalidOperationException(res.RoleNotFound.format(normalized_role_name))

    async def is_in_role(self, user: TUser, normalized_role_name: str) -> bool:
        return await self.user_role_model.exists(
            user_id=user.id, role__normalized_name=normalized_role_name, using_db=self.transaction
        )

    async def remove_from_role(self, user: TUser, normalized_role_name: str) -> None:
        if role := await self.role_model.get_or_none(normalized_name=normalized_role_name, using_db=self.transaction):
            await self.user_role_model.filter(user_id=user.id, role_id=role.id).using_db(self.transaction).delete()

    async def add_login(self, user: TUser, login: UserLoginInfo) -> None:
        await self._create_user_login(user, login).save(using_db=self.transaction)

    async def find_by_login(self, login_provider: str, provider_key: str) -> TUser | None:
        return await self.user_model.get_or_none(
            logins__login_provider=login_provider, logins__provider_key=provider_key, using_db=self.transaction
        )

    async def get_logins(self, user: TUser) -> list[UserLoginInfo]:
        logins = await self.user_login_model.filter(user_id=user.id).using_db(self.transaction)
        return [self._create_user_login_info(login) for login in logins]

    async def remove_login(self, user: TUser, login_provider: str, provider_key: str) -> None:
        await (
            self.user_login_model.filter(user_id=user.id, login_provider=login_provider, provider_key=provider_key)
            .using_db(self.transaction)
            .delete()
        )

    async def get_token(self, user: TUser, login_provider: str, name: str) -> str | None:
        if token := await self._find_token(user, login_provider, name):
            return token.value

    async def remove_token(self, user: TUser, login_provider: str, name: str) -> None:
        await (
            self.user_token_model.filter(user_id=user.id, login_provider=login_provider, name=name)
            .using_db(self.transaction)
            .delete()
        )

    async def set_token(self, user: TUser, login_provider: str, name: str, value: str | None) -> None:
        defaults = {"user_id": user.id, "login_provider": login_provider, "name": name, "value": value}
        await self.user_token_model.update_or_create(
            defaults=defaults, using_db=self.transaction, user_id=user.id, login_provider=login_provider, name=name
        )

    async def get_two_factor_enabled(self, user: TUser) -> bool:
        return user.two_factor_enabled

    async def set_two_factor_enabled(self, user: TUser, enabled: bool) -> None:
        user.two_factor_enabled = enabled

    async def get_authenticator_key(self, user: TUser) -> str | None:
        return await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.AUTHENTICATOR_KEY_TOKEN_NAME)

    async def set_authenticator_key(self, user: TUser, key: str) -> None:
        return await self.set_token(user, self.INTERNAL_LOGIN_PROVIDER, self.AUTHENTICATOR_KEY_TOKEN_NAME, key)

    async def count_codes(self, user: TUser) -> int:
        merged_codes = (await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.RECOVERY_CODE_TOKEN_NAME)) or ""
        if merged_codes:
            return merged_codes.count(";") + 1
        return 0

    async def redeem_code(self, user: TUser, code: str) -> bool:
        merged_codes = (await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.RECOVERY_CODE_TOKEN_NAME)) or ""
        split_codes = merged_codes.split(";")

        if code in split_codes:
            split_codes.remove(code)
            await self.replace_codes(user, *split_codes)
            return True

        return False

    async def replace_codes(self, user: TUser, *recovery_codes: str) -> None:
        merged_codes = ";".join(recovery_codes)
        return await self.set_token(user, self.INTERNAL_LOGIN_PROVIDER, self.RECOVERY_CODE_TOKEN_NAME, merged_codes)

    async def add_claims(self, user: TUser, *claims: Claim) -> None:
        await self.user_claim_model.bulk_create(
            [self._create_user_claim(user, claim) for claim in claims], using_db=self.transaction
        )

    async def get_claims(self, user: TUser) -> list[Claim]:
        claims = await self.user_claim_model.filter(user_id=user.id).using_db(self.transaction)
        return [self._create_claim(claim) for claim in claims]

    async def get_users_for_claim(self, claim: Claim) -> list[TUser]:
        return await self.user_model.filter(claims__claim_type=claim.type, claims__claim_value=claim.value).using_db(
            self.transaction
        )

    async def remove_claims(self, user: TUser, *claims: Claim) -> None:
        for claim in claims:
            await (
                self.user_claim_model.filter(user_id=user.id, claim_type=claim.type, claim_value=claim.value)
                .using_db(self.transaction)
                .delete()
            )

    async def replace_claim(self, user: TUser, claim: Claim, new_claim: Claim) -> None:
        defaults = {"user_id": user.id, "claim_type": new_claim.type, "claim_value": new_claim.value}
        await self.user_claim_model.update_or_create(
            defaults=defaults,
            using_db=self.transaction,
            user_id=user.id,
            claim_type=claim.type,
            claim_value=claim.value,
        )

    async def get_personal_data(self, user: TUser) -> dict[str, Any] | None:
        if hasattr(user.Meta, "personal_data"):
            return {p: getattr(user, p) for p in getattr(user.Meta, "personal_data")}

        raise PersonalDataError(
            f"The model '{user.__class__}' does not support receiving personal data.\n"
            f"The 'Meta' must have the 'personal_data' attribute, which lists the fields related to personal data."
        )

    def _create_claim(self, model: TUserClaim) -> Claim:  # noqa
        return Claim(claim_type=model.claim_type, claim_value=model.claim_value)

    def _create_user_claim(self, user: TUser, claim: Claim) -> TUserClaim:
        return self.user_claim_model(user_id=user.id, claim_type=claim.type, claim_value=claim.value)

    def _create_user_token(self, user: TUser, login_provider: str, name: str, value: str | None) -> TUserToken:
        return self.user_token_model(user_id=user.id, login_provider=login_provider, name=name, value=value)

    def _create_user_login_info(self, model: TUserLogin) -> UserLoginInfo:  # noqa
        return UserLoginInfo(
            login_provider=model.login_provider,
            provider_key=model.provider_key,
            display_name=model.provider_display_name,
        )

    def _create_user_login(self, user: TUser, login: UserLoginInfo) -> TUserLogin:
        return self.user_login_model(
            user_id=user.id,
            login_provider=login.login_provider,
            provider_display_name=login.provider_display_name,
            provider_key=login.provider_key,
        )

    async def _find_token(self, user: TUser, login_provider: str, name: str) -> TUserToken | None:
        return await self.user_token_model.get_or_none(
            user_id=user.id, login_provider=login_provider, name=name, using_db=self.transaction
        )

    async def _find_role(self, name: str) -> TRole | None:
        return await self.role_model.get_or_none(normalized_name=name, using_db=self.transaction)
