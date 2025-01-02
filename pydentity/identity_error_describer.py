import pydentity.resources as res
from pydentity.identity_error import IdentityError

__all__ = ("IdentityErrorDescriber",)


# noinspection PyPep8Naming
class IdentityErrorDescriber:
    """Service to enable localization for application facing builders errors."""

    __slots__ = ()

    @staticmethod
    def DefaultError() -> IdentityError:
        return IdentityError(code="DefaultError", description=res.DefaultError)

    @staticmethod
    def DuplicateEmail(email: str) -> IdentityError:
        return IdentityError(code="DuplicateEmail", description=res.DuplicateEmail.format(email))

    @staticmethod
    def DuplicateRoleName(name: str) -> IdentityError:
        return IdentityError(code="DuplicateRoleName", description=res.DuplicateRoleName.format(name))

    @staticmethod
    def DuplicateUserName(name: str) -> IdentityError:
        return IdentityError(code="DuplicateUserName", description=res.DuplicateUserName.format(name))

    @staticmethod
    def InvalidEmail(email: str | None) -> IdentityError:
        return IdentityError(code="InvalidEmail", description=res.InvalidEmail.format(email))

    @staticmethod
    def InvalidRoleName(name: str | None) -> IdentityError:
        return IdentityError(code="InvalidRoleName", description=res.InvalidRoleName.format(name))

    @staticmethod
    def InvalidDomain(domain: str) -> IdentityError:
        return IdentityError(code="InvalidDomain", description=res.InvalidDomain.format(domain))

    @staticmethod
    def InvalidToken() -> IdentityError:
        return IdentityError(code="InvalidToken", description=res.InvalidToken)

    @staticmethod
    def InvalidUserName(name: str | None) -> IdentityError:
        return IdentityError(code="InvalidUserName", description=res.InvalidUserName.format(name))

    @staticmethod
    def LoginAlreadyAssociated() -> IdentityError:
        return IdentityError(code="InvalidUserName", description=res.LoginAlreadyAssociated)

    @staticmethod
    def NullSecurityStamp() -> IdentityError:
        return IdentityError(code="NullSecurityStamp", description=res.NullSecurityStamp)

    @staticmethod
    def PasswordMismatch() -> IdentityError:
        return IdentityError(code="PasswordMismatch", description=res.PasswordMismatch)

    @staticmethod
    def PasswordRequiresDigit() -> IdentityError:
        return IdentityError(code="PasswordRequiresDigit", description=res.PasswordRequiresDigit)

    @staticmethod
    def PasswordRequiresLower() -> IdentityError:
        return IdentityError(code="PasswordRequiresLower", description=res.PasswordRequiresLower)

    @staticmethod
    def PasswordRequiresNonAlphanumeric() -> IdentityError:
        return IdentityError(
            code="PasswordRequiresNonAlphanumeric",
            description=res.PasswordRequiresNonAlphanumeric,
        )

    @staticmethod
    def PasswordRequiresUpper() -> IdentityError:
        return IdentityError(code="PasswordRequiresUpper", description=res.PasswordRequiresUpper)

    @staticmethod
    def PasswordTooShort(length: int) -> IdentityError:
        return IdentityError(code="PasswordTooShort", description=res.PasswordTooShort.format(length))

    @staticmethod
    def PasswordRequiresUniqueChars(unique_chars: int) -> IdentityError:
        return IdentityError(
            code="PasswordRequiresUniqueChars",
            description=res.PasswordRequiresUniqueChars.format(unique_chars),
        )

    @staticmethod
    def RoleNotFound(name: str) -> IdentityError:
        return IdentityError(code="RoleNotFound", description=res.RoleNotFound.format(name))

    @staticmethod
    def RecoveryCodeRedemptionFailed() -> IdentityError:
        return IdentityError(code="RecoveryCodeRedemptionFailed", description=res.RecoveryCodeRedemptionFailed)

    @staticmethod
    def UserAlreadyHasPassword() -> IdentityError:
        return IdentityError(code="UserAlreadyHasPassword", description=res.UserAlreadyHasPassword)

    @staticmethod
    def UserAlreadyInRole(name: str) -> IdentityError:
        return IdentityError(code="UserAlreadyInRole", description=res.UserAlreadyInRole.format(name))

    @staticmethod
    def UserLockedOut() -> IdentityError:
        return IdentityError(code="UserLockedOut", description=res.UserLockedOut)

    @staticmethod
    def UserLockoutNotEnabled() -> IdentityError:
        return IdentityError(code="UserLockoutNotEnabled", description=res.UserLockoutNotEnabled)

    @staticmethod
    def UserNameNotFound(name: str) -> IdentityError:
        return IdentityError(code="UserNameNotFound", description=res.UserNameNotFound.format(name))

    @staticmethod
    def UserNotInRole(name: str) -> IdentityError:
        return IdentityError(code="UserNotInRole", description=res.UserNotInRole.format(name))
