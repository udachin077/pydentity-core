from typing import TYPE_CHECKING, Generic

from pydentity.exc import ArgumentNullException
from pydentity.identity_error import IdentityError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.interfaces.role_validator import IRoleValidator
from pydentity.types import TRole
from pydentity.utils import is_null_or_whitespace

if TYPE_CHECKING:
    from pydentity.role_manager import RoleManager

__all__ = ("RoleValidator",)


class RoleValidator(IRoleValidator[TRole], Generic[TRole]):
    """Provides the default validation of roles."""

    __slots__ = ("_describer",)

    def __init__(self, errors: IdentityErrorDescriber | None = None) -> None:
        """

        :param errors: The *IdentityErrorDescriber* used to provider error messages.
        """
        self._describer = errors or IdentityErrorDescriber()

    async def validate(self, manager: "RoleManager[TRole]", role: TRole) -> IdentityResult:
        if manager is None:
            raise ArgumentNullException("manager")
        if role is None:
            raise ArgumentNullException("role")

        errors: list[IdentityError] = []
        await self._validate_role_name(manager, role, errors)
        return IdentityResult.failed(*errors) if errors else IdentityResult.success()

    async def _validate_role_name(
        self, manager: "RoleManager[TRole]", role: TRole, errors: list[IdentityError]
    ) -> None:
        role_name = await manager.get_role_name(role)

        if is_null_or_whitespace(role_name):
            errors.append(self._describer.InvalidRoleName(role_name))
            return

        if owner := await manager.find_by_name(role_name):  # type:ignore[arg-type]
            if await manager.get_role_id(owner) != await manager.get_role_id(role):
                errors.append(self._describer.DuplicateRoleName(role_name))  # type:ignore[arg-type]
