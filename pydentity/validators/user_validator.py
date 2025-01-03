from typing import TYPE_CHECKING, Generic

from email_validator import validate_email, EmailNotValidError

from pydentity.exc import ArgumentNullException
from pydentity.identity_error import IdentityError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.interfaces.user_validator import IUserValidator
from pydentity.types import TUser
from pydentity.utils import is_null_or_whitespace

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("UserValidator",)


class UserValidator(IUserValidator[TUser], Generic[TUser]):
    """Provides validation builders for user classes."""

    __slots__ = ("_error_describer",)

    def __init__(self, error_describer: IdentityErrorDescriber | None = None) -> None:
        """

        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        self._error_describer = error_describer or IdentityErrorDescriber()

    async def validate(self, manager: "UserManager[TUser]", user: TUser) -> IdentityResult:
        if manager is None:
            raise ArgumentNullException("manager")
        if user is None:
            raise ArgumentNullException("user")

        errors: list[IdentityError] = []
        await self._validate_username(manager, user, errors)

        if manager.options.user.require_unique_email:
            await self._validate_email(manager, user, errors)

        return IdentityResult.failed(*errors) if errors else IdentityResult.success()

    async def _validate_username(self, manager: "UserManager[TUser]", user: TUser, errors: list[IdentityError]) -> None:
        username = await manager.get_username(user)

        if is_null_or_whitespace(username):
            errors.append(self._error_describer.InvalidUserName(username))
            return

        allowed_characters = manager.options.user.allowed_username_characters
        if allowed_characters and any(c not in allowed_characters for c in username):  # type:ignore[union-attr]
            errors.append(self._error_describer.InvalidUserName(username))
            return

        owner = await manager.find_by_name(username)  # type:ignore[arg-type]
        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._error_describer.DuplicateUserName(username))  # type:ignore[arg-type]

    async def _validate_email(self, manager: "UserManager[TUser]", user: TUser, errors: list[IdentityError]) -> None:
        email = await manager.get_email(user)

        if is_null_or_whitespace(email):
            errors.append(self._error_describer.InvalidEmail(email))
            return

        try:
            result = validate_email(email, check_deliverability=False)  # type:ignore[arg-type]
        except EmailNotValidError:
            errors.append(self._error_describer.InvalidEmail(email))
            return

        allowed_email_domains = manager.options.user.allowed_email_domains
        if allowed_email_domains and (result.domain not in allowed_email_domains):
            errors.append(self._error_describer.InvalidDomain(result.domain))
            return

        owner = await manager.find_by_email(email)  # type:ignore[arg-type]
        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._error_describer.DuplicateEmail(email))  # type:ignore[arg-type]
