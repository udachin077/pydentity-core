import logging
from collections.abc import Iterable
from typing import Generic, Any

from pydentity.authentication.interfaces import IAuthenticationSchemeProvider
from pydentity.exc import ArgumentNullException
from pydentity.http.context import HttpContext, HttpContextAccessor
from pydentity.identity_constants import IdentityConstants
from pydentity.identity_error import IdentityError
from pydentity.identity_options import IdentityOptions
from pydentity.identity_result import IdentityResult
from pydentity.interfaces.logger import ILogger
from pydentity.interfaces.user_claims_principal_factory import IUserClaimsPrincipalFactory
from pydentity.interfaces.user_confirmation import IUserConfirmation
from pydentity.loggers import sign_in_manager_logger
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim, ClaimTypes
from pydentity.signin_result import SignInResult
from pydentity.types import TUser
from pydentity.user_confirmation import DefaultUserConfirmation
from pydentity.user_manager import UserManager

__all__ = ("SignInManager",)


class TwoFactorAuthenticationInfo:
    __slots__ = (
        "user",
        "login_provider",
    )

    def __init__(self, user: TUser, login_provider: str | None):
        self.user = user
        self.login_provider = login_provider


class SignInManager(Generic[TUser]):
    """Provides the APIs for user sign in."""

    __slots__ = (
        "_two_factor_info",
        "_confirmation",
        "_context_accessor",
        "_schemes",
        "authentication_scheme",
        "claims_factory",
        "logger",
        "options",
        "user_manager",
    )

    def __init__(
        self,
        user_manager: UserManager[TUser],
        context_accessor: HttpContextAccessor,
        schemes: IAuthenticationSchemeProvider,
        user_claims_factory: IUserClaimsPrincipalFactory[TUser],
        confirmation: IUserConfirmation[TUser] | None = None,
        options: IdentityOptions | None = None,
        logger: ILogger["SignInManager[TUser]"] | None = None,
    ):
        if not user_manager:
            raise ArgumentNullException("user_manager")
        if not user_claims_factory:
            raise ArgumentNullException("user_claims_factory")

        self._confirmation = confirmation or DefaultUserConfirmation()
        self._context_accessor = context_accessor
        self._schemes = schemes
        self._two_factor_info: TwoFactorAuthenticationInfo | None = None
        self.user_manager = user_manager
        self.claims_factory = user_claims_factory
        self.options = options or IdentityOptions()
        self.logger: ILogger["SignInManager[TUser]"] | logging.Logger = logger or sign_in_manager_logger
        self.authentication_scheme = IdentityConstants.ApplicationScheme

    @property
    def context(self) -> HttpContext:
        return self._context_accessor.http_context

    async def is_signed_in(self, principal: ClaimsPrincipal) -> bool:
        """
        Returns true if the principal has an builders with the application cookie builders.

        :param principal: The *ClaimsPrincipal* instance.
        :return:
        """
        if not principal:
            raise ArgumentNullException("principal")

        return any([True for i in principal.identities if i.authentication_type == self.authentication_scheme])

    async def can_sign_in(self, user: TUser) -> bool:
        """
        Returns a flag indicating whether the specified user can sign in.

        :param user: The user whose sign-in status should be returned.
        :return:
        """
        if self.options.signin.required_confirmed_email and not await self.user_manager.is_email_confirmed(user):
            self.logger.debug("User cannot sign in without a confirmed email.")
            return False

        if (
            self.options.signin.required_confirmed_phone_number
            and not await self.user_manager.is_phone_number_confirmed(user)
        ):
            self.logger.debug("User cannot sign in without a confirmed phone number.")
            return False

        if self.options.signin.required_confirmed_account and not await self._confirmation.is_confirmed(
            self.user_manager, user
        ):
            self.logger.debug("User cannot sign in without a confirmed account.")
            return False

        return True

    async def refresh_sign_in(self, user: TUser) -> None:
        """


        :param user: The user to sign-in.
        :return:
        """
        auth = await self.context.authenticate(self.authentication_scheme)

        claims = []
        if auth and auth.principal:
            authentication_method = auth.principal.find_first(ClaimTypes.AuthenticationMethod)
            amr = auth.principal.find_first("amr")

            if authentication_method:
                claims.append(authentication_method)
            if amr:
                claims.append(amr)

        await self.sign_in_with_claims(user, auth.properties["is_persistent"], claims)

    async def sign_in(self, user: TUser, is_persistent: bool, authentication_method: str | None = None) -> None:
        additional_claims = []
        if authentication_method:
            additional_claims.append(Claim(ClaimTypes.AuthenticationMethod, authentication_method))

        return await self.sign_in_with_claims(user, is_persistent, additional_claims)

    async def sign_in_with_claims(self, user: TUser, is_persistent: bool, additional_claims: Iterable[Claim]) -> None:
        """
        Signs in the specified user.

        :param user:
        :param is_persistent:
        :param additional_claims:
        :return:
        """
        user_principal = await self.create_user_principal(user)
        user_principal.identity.add_claims(*additional_claims)  # type:ignore
        await self.context.sign_in(self.authentication_scheme, user_principal, is_persistent=is_persistent)
        self.context.user = user_principal

    async def sign_out(self) -> None:
        """
        Signs the current user out of the application.

        :return:
        """
        await self.context.sign_out(self.authentication_scheme)

        if self._schemes.get_scheme(IdentityConstants.ExternalScheme):
            await self.context.sign_out(IdentityConstants.ExternalScheme)

        if self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
            await self.context.sign_out(IdentityConstants.TwoFactorUserIdScheme)

    async def validate_security_stamp(self, principal: ClaimsPrincipal) -> TUser | None:
        """
        Validates the security stamp for the specified principal against the persisted stamp for the current user.

        :param principal:
        :return:
        """
        user = await self.user_manager.get_user(principal)
        if await self.is_valid_security_stamp(
            user, principal.find_first_value(self.options.claims_identity.security_stamp_claim_type)
        ):
            return user

        self.logger.debug("Failed to validate a security stamp.")
        return None

    async def is_valid_security_stamp(self, user: TUser | None, security_stamp: str | None) -> bool:
        """
        Validates the security stamp for the specified user.
        If no user is specified, or if the stores does not support security stamps, validation is considered successful.

        :param user: The user whose stamp should be validated.
        :param security_stamp: The expected security stamp value.
        :return: The result of the validation.
        """
        return bool(
            user is not None
            and
            # Only validate the security stamp if the store supports it
            (
                not self.user_manager.supports_user_security_stamp
                or (security_stamp and security_stamp == await self.user_manager.get_security_stamp(user))
            )
        )

    async def validate_two_factory_security_stamp(self, principal: ClaimsPrincipal | None) -> TUser | None:
        """
        Validates the security stamp for the specified principal from one of
        the two-factor principals (remember client or user id) against
        the persisted stamp for the current user.

        :param principal:
        :return:
        """
        if not principal or not principal.identity or not principal.identity.name:
            return None

        user = await self.user_manager.find_by_id(principal.identity.name)

        if await self.is_valid_security_stamp(
            user, principal.find_first_value(self.options.claims_identity.security_stamp_claim_type)
        ):
            return user

        self.logger.debug("Failed to validate a security stamp.")
        return None

    async def password_sign_in(
        self,
        username: str,
        password: str,
        is_persistent: bool = False,
        lockout_on_failure: bool = True,
    ) -> SignInResult:
        """
        Attempts to sign in the specified username and password combination.

        :param username: The username to sign in.
        :param password: The password to attempt to sign in with.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param lockout_on_failure: Flag indicating if the user account should be locked if the sign in fails.
        :return:
        """
        user = await self.user_manager.find_by_name(username)

        if user is None:
            # Run the hasher to mitigate timing attack
            self.user_manager.password_hasher.hash_password(user, password)  # type: ignore[arg-type]
            return SignInResult.failed()

        attempt = await self.check_password_sign_in(user, password, lockout_on_failure)

        if attempt.succeeded:
            return await self._sign_in_or_two_factor(user, is_persistent)

        return attempt

    async def check_password_sign_in(self, user: TUser, password: str, lockout_on_failure: bool) -> SignInResult:
        """
        Attempts a password sign-in for a user.

        :param user: The user to sign in.
        :param password: The password to attempt to sign in with.
        :param lockout_on_failure: Flag indicating if the user account should be locked if the sign in fails.
        :return:
        """
        if not user:
            raise ArgumentNullException("user")

        if error := await self._pre_sign_in_check(user):
            return error

        if await self.user_manager.check_password(user, password):
            if not await self._is_two_factor_enabled(user) or await self.is_two_factor_client_remembered(user):
                reset_lockout_result = await self._reset_lockout_with_result(user)

                if not reset_lockout_result.succeeded:
                    # `reset_lockout` got an unsuccessful result that could be caused by concurrency failures
                    # indicating an attacker could be trying to bypass the `max_failed_access_attempts` limit.
                    # Return the same failure we do when failing to increment the lockout to avoid giving an attacker
                    # extra guesses at the password.
                    return SignInResult.failed()

            return SignInResult.success(self.context.response)

        self.logger.warning("User failed to provide the correct password.")

        if self.user_manager.supports_user_lockout and lockout_on_failure:
            # If lockout is requested, increment access failed count which might lock out the user.
            increment_lockout_result = await self.user_manager.access_failed(user)

            if not increment_lockout_result.succeeded:
                # Return the same failure we do when resetting the lockout fails after a correct password.
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out()

        return SignInResult.failed()

    async def is_two_factor_client_remembered(self, user: TUser) -> bool:
        """
        Returns a flag indicating if the current client browser has been remembered by two-factor authentication
        for the user attempting to login.

        :param user: The user attempting to login.
        :return:
        """
        if self._schemes.get_scheme(IdentityConstants.TwoFactorRememberMeScheme) is None:
            return False

        user_id = await self.user_manager.get_user_id(user)
        result = await self.context.authenticate(IdentityConstants.TwoFactorRememberMeScheme)
        return bool(result.principal and result.principal.find_first_value(ClaimTypes.Name) == user_id)

    async def remember_two_factor_client(self, user: TUser) -> None:
        await self.context.sign_in(
            IdentityConstants.TwoFactorRememberMeScheme,
            await self._store_remember_client(user),
            is_persistent=True,
        )

    async def forget_two_factor_client(self) -> None:
        return await self.context.sign_out(IdentityConstants.TwoFactorRememberMeScheme)

    async def two_factor_recovery_code_sign_in(self, recovery_code: str) -> SignInResult:
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        result = await self.user_manager.redeem_two_factor_recovery_code(two_factor_info.user, recovery_code)
        if result.succeeded:
            return await self._do_two_factor_sign_in(
                two_factor_info.user, two_factor_info, is_persistent=False, remember_client=False
            )

        return SignInResult.failed()

    async def _do_two_factor_sign_in(
        self,
        user: TUser,
        two_factor_info: TwoFactorAuthenticationInfo,
        is_persistent: bool,
        remember_client: bool,
    ) -> SignInResult:
        reset_lockout_result = await self._reset_lockout_with_result(user)
        if not reset_lockout_result.succeeded:
            # ResetLockout got an unsuccessful result that could be caused by concurrency failures indicating an
            # attacker could be trying to bypass the `max_failed_access_attempts` limit. Return the same failure we do
            # when failing to increment the lockout to avoid giving an attacker extra guesses at the two-factor code.
            return SignInResult.failed()

        claims = [Claim("amr", "mfa")]

        if two_factor_info.login_provider:
            claims.append(Claim(ClaimTypes.AuthenticationMethod, two_factor_info.login_provider))

        if self._schemes.get_scheme(IdentityConstants.ExternalScheme):
            await self.context.sign_out(IdentityConstants.ExternalScheme)

        if self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
            await self.context.sign_out(IdentityConstants.TwoFactorUserIdScheme)
            if remember_client:
                await self.remember_two_factor_client(user)

        await self.sign_in_with_claims(user, is_persistent, claims)
        return SignInResult.success(self.context.response)

    async def two_factor_authenticator_sign_in(
        self, code: str, is_persistent: bool, remember_client: bool
    ) -> SignInResult:
        """
        Validates the sign in code from an authenticator app and creates and signs in the user.

        :param code: The two-factor authentication code to validate.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param remember_client: Flag indicating whether the current browser should be remembered, suppressing
                                all further two-factor authentication prompts.
        :return:
        """
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        user = two_factor_info.user

        if error := await self._pre_sign_in_check(user):
            return error

        if await self.user_manager.verify_two_factor_token(
            user, self.options.tokens.authenticator_token_provider, code
        ):
            return await self._do_two_factor_sign_in(user, two_factor_info, is_persistent, remember_client)

        if self.user_manager.supports_user_lockout:
            increment_lockout_result = await self.user_manager.access_failed(user)

            if not increment_lockout_result.succeeded:
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out()

        return SignInResult.failed()

    async def two_factor_sign_in(
        self, provider: str, code: str, is_persistent: bool, remember_client: bool
    ) -> SignInResult:
        """
        Validates the two-factor sign in code and creates and signs in the user

        :param provider: The two-factor authentication provider to validate the code against.
        :param code: The two-factor authentication code to validate.
        :param is_persistent: Flag indicating whether the sign-in cookie should persist after the browser is closed.
        :param remember_client: Flag indicating whether the current browser should be remembered,
                                suppressing all further two-factor authentication prompts.
        :return:
        """
        two_factor_info = await self.retrieve_two_factor_info()
        if not two_factor_info:
            return SignInResult.failed()

        user = two_factor_info.user

        if error := await self._pre_sign_in_check(user):
            return error

        if await self.user_manager.verify_two_factor_token(user, provider, code):
            return await self._do_two_factor_sign_in(user, two_factor_info, is_persistent, remember_client)

        if self.user_manager.supports_user_lockout:
            increment_lockout_result = await self.user_manager.access_failed(user)

            if not increment_lockout_result.succeeded:
                return SignInResult.failed()

            if await self.user_manager.is_locked_out(user):
                return await self._locked_out()

        return SignInResult.failed()

    async def get_two_factor_authentication_user(self) -> TUser | None:
        """
        Gets the TUser for the current two-factor authentication login.

        :return:
        """
        info = await self.retrieve_two_factor_info()
        return info.user if info else None

    def _store_two_factor_info(self, user_id: Any, login_provider: str | None) -> ClaimsPrincipal:
        identity = ClaimsIdentity(authentication_type=IdentityConstants.TwoFactorUserIdScheme)
        identity.add_claims(Claim(ClaimTypes.Name, user_id))

        if login_provider:
            identity.add_claims(Claim(ClaimTypes.AuthenticationMethod, login_provider))

        return ClaimsPrincipal(identity)

    async def _store_remember_client(self, user: TUser) -> ClaimsPrincipal:
        user_id = await self.user_manager.get_user_id(user)
        remember_browser_identity = ClaimsIdentity(authentication_type=IdentityConstants.TwoFactorRememberMeScheme)
        remember_browser_identity.add_claims(Claim(ClaimTypes.Name, user_id))

        if self.user_manager.supports_user_security_stamp:
            stamp = await self.user_manager.get_security_stamp(user)
            remember_browser_identity.add_claims(Claim(self.options.claims_identity.security_stamp_claim_type, stamp))

        return ClaimsPrincipal(remember_browser_identity)

    async def _is_two_factor_enabled(self, user: TUser) -> bool:
        return (
            self.user_manager.supports_user_two_factor
            and await self.user_manager.get_two_factor_enabled(user)
            and len(await self.user_manager.get_valid_two_factor_providers(user)) > 0
        )

    async def _sign_in_or_two_factor(
        self,
        user: TUser,
        is_persistent: bool,
        login_provider: str | None = None,
        bypass_two_factor: bool = False,
    ) -> SignInResult:
        if not bypass_two_factor and await self._is_two_factor_enabled(user):
            if not await self.is_two_factor_client_remembered(user):
                self._two_factor_info = TwoFactorAuthenticationInfo(user=user, login_provider=login_provider)
                if self._schemes.get_scheme(IdentityConstants.TwoFactorUserIdScheme):
                    user_id = await self.user_manager.get_user_id(user)
                    await self.context.sign_in(
                        IdentityConstants.TwoFactorUserIdScheme,
                        self._store_two_factor_info(user_id, login_provider),
                    )
                return SignInResult.two_factor_required(self.context.response)

        if login_provider:
            await self.context.sign_out(IdentityConstants.ExternalScheme)
            await self.sign_in(user, is_persistent, login_provider)
        else:
            await self.sign_in_with_claims(user, is_persistent, [Claim("amr", "pwd")])

        return SignInResult.success(self.context.response)

    async def retrieve_two_factor_info(self) -> TwoFactorAuthenticationInfo | None:
        if self._two_factor_info:
            return self._two_factor_info

        result = await self.context.authenticate(IdentityConstants.TwoFactorUserIdScheme)
        if result.principal is None:
            return None

        user_id = result.principal.find_first_value(ClaimTypes.Name)
        if user_id is None:
            return None

        user = await self.user_manager.find_by_id(user_id)
        if user is None:
            return None

        return TwoFactorAuthenticationInfo(user, result.principal.find_first_value(ClaimTypes.AuthenticationMethod))

    async def _is_locked_out(self, user: TUser) -> bool:
        """
        Used to determine if a user is considered locked out.

        :param user: The user.
        :return:
        """
        return self.user_manager.supports_user_lockout and await self.user_manager.is_locked_out(user)

    async def _locked_out(self) -> SignInResult:
        """
        Returns a locked out SignInResult.

        :return:
        """
        self.logger.warning("User is currently locked out.")
        return SignInResult.locked_out()

    async def _pre_sign_in_check(self, user: TUser) -> SignInResult | None:
        """
        Used to ensure that a user is allowed to sign in.

        :param user:
        :return:
        """
        if not await self.can_sign_in(user):
            return SignInResult.not_allowed()

        if await self._is_locked_out(user):
            return await self._locked_out()

        return None

    async def create_user_principal(self, user: TUser) -> ClaimsPrincipal:
        return await self.claims_factory.create(user)

    async def _reset_lockout_with_result(self, user: TUser) -> IdentityResult:
        """
        Used to reset a user`s lockout count.

        :param user: The user.
        :return:
        """
        if not self.user_manager.supports_user_lockout:
            return IdentityResult.success()

        result = await self.user_manager.reset_access_failed_count(user)

        if not result.succeeded:
            return IdentityResult.failed(IdentityError("ResetLockout", "Reset lockout failed."), *result.errors)

        return result
