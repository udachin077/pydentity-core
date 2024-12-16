from typing import Generic, TYPE_CHECKING

from email_validator import validate_email, EmailNotValidError

from pydentity.identity_error import IdentityError
from pydentity.interfaces import IUserValidator
from pydentity.exc import ArgumentNoneException
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.types import TUser
from pydentity.utils import is_none_or_space

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("UserValidator",)


class UserValidator(IUserValidator[TUser], Generic[TUser]):
    """Provides validation builders for user classes."""

    __slots__ = ("_errors",)

    def __init__(self, errors: IdentityErrorDescriber | None = None) -> None:
        """

        :param errors: The ``IdentityErrorDescriber`` used to provider error messages.
        """
        self._errors = errors or IdentityErrorDescriber()

    async def validate(self, manager: "UserManager[TUser]", user: TUser) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneException("manager")
        if user is None:
            raise ArgumentNoneException("user")

        options = manager.options.user
        errors = []  # type: ignore

        await self._validate_username(manager, user, errors)

        if options.require_unique_email:
            await self._validate_email(manager, user, errors)

        if not errors:
            return IdentityResult.success()

        return IdentityResult.failed(*errors)

    async def _validate_username(self, manager: "UserManager[TUser]", user: TUser, errors: list[IdentityError]) -> None:
        username = await manager.get_username(user)

        if is_none_or_space(username):
            errors.append(self._errors.InvalidUserName("None"))
            return

        assert username is not None
        options = manager.options.user

        if not options.allowed_username_characters.isspace() and any(
            c not in options.allowed_username_characters for c in username
        ):
            errors.append(self._errors.InvalidUserName(username))
            return

        owner = await manager.find_by_name(username)

        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._errors.DuplicateUserName(username))

    async def _validate_email(self, manager: "UserManager[TUser]", user: TUser, errors: list[IdentityError]) -> None:
        email = await manager.get_email(user)

        if is_none_or_space(email):
            errors.append(self._errors.InvalidEmail("None"))
            return

        assert email is not None
        try:
            result = validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            errors.append(self._errors.InvalidEmail(email))
            return

        options = manager.options.user

        if options.allowed_email_domains:
            if result.domain not in options.allowed_email_domains:
                errors.append(self._errors.InvalidDomain(result.domain))
                return

        owner = await manager.find_by_email(email)

        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._errors.DuplicateEmail(email))
