from typing import TYPE_CHECKING, Generic

from pydentity.exc import ArgumentNoneException
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.interfaces import IPasswordValidator
from pydentity.types import TUser
from pydentity.utils import is_none_or_space

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("PasswordValidator",)


def _is_lower(c: str) -> bool:
    return "a" <= c <= "z"


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_upper(c: str) -> bool:
    return "A" <= c <= "Z"


def _is_letter_or_digit(c: str) -> bool:
    return _is_lower(c) or _is_upper(c) or _is_digit(c)


class PasswordValidator(IPasswordValidator[TUser], Generic[TUser]):
    """Provides the default password policy for Identity."""

    __slots__ = ("_errors",)

    def __init__(self, errors: IdentityErrorDescriber | None = None) -> None:
        """

        :param errors: The ``IdentityErrorDescriber`` used to provider error messages.
        """
        self._errors = errors or IdentityErrorDescriber()

    async def validate(self, manager: "UserManager[TUser]", password: str) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneException("manager")
        if password is None:
            raise ArgumentNoneException("password")

        options = manager.options.password
        errors = []

        if is_none_or_space(password) or len(password) < options.required_length:
            errors.append(self._errors.PasswordTooShort(options.required_length))

        if options.required_digit and not any(_is_digit(c) for c in password):
            errors.append(self._errors.PasswordRequiresDigit())

        if options.required_lowercase and not any(_is_lower(c) for c in password):
            errors.append(self._errors.PasswordRequiresLower())

        if options.required_uppercase and not any(_is_upper(c) for c in password):
            errors.append(self._errors.PasswordRequiresUpper())

        if options.required_non_alphanumeric and all(_is_letter_or_digit(c) for c in password):
            errors.append(self._errors.PasswordRequiresNonAlphanumeric())

        if options.required_unique_chars >= 1 and len(set(password)) < options.required_unique_chars:
            errors.append(self._errors.PasswordRequiresUniqueChars(options.required_unique_chars))

        if not errors:
            return IdentityResult.success()

        return IdentityResult.failed(*errors)
