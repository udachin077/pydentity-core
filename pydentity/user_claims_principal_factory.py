from typing import Generic

from pydentity.interfaces import IUserClaimsPrincipalFactory
from pydentity.exc import ArgumentNoneException
from pydentity.identity_constants import IdentityConstants
from pydentity.identity_options import IdentityOptions
from pydentity.role_manager import RoleManager
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim, ClaimTypes
from pydentity.types import TUser, TRole
from pydentity.user_manager import UserManager

__all__ = ("UserClaimsPrincipalFactory",)


class UserClaimsPrincipalFactory(IUserClaimsPrincipalFactory[TUser], Generic[TUser]):
    """Provides methods to create a claims principal for a given user."""

    __slots__ = (
        "user_manager",
        "role_manager",
        "options",
    )

    def __init__(
        self,
        user_manager: UserManager[TUser],
        role_manager: RoleManager[TRole],
        options: IdentityOptions,
    ) -> None:
        self.user_manager = user_manager
        self.role_manager = role_manager
        self.options = options

    async def create(self, user: TUser) -> ClaimsPrincipal:
        if not user:
            raise ArgumentNoneException("user")

        user_id = await self.user_manager.get_user_id(user=user)
        username = await self.user_manager.get_username(user=user)

        identity = ClaimsIdentity(
            IdentityConstants.ApplicationScheme,
            Claim(ClaimTypes.NameIdentifier, user_id),
            Claim(ClaimTypes.Name, username),
            name_claim_type=self.options.claims_identity.username_claim_type,
            role_claim_type=self.options.claims_identity.role_claim_type,
        )

        if self.user_manager.supports_user_email:
            if email := await self.user_manager.get_email(user):
                identity.add_claims(Claim(self.options.claims_identity.email_claim_type, email))

        if self.user_manager.supports_user_security_stamp:
            if security := await self.user_manager.get_security_stamp(user):
                identity.add_claims(Claim(self.options.claims_identity.security_stamp_claim_type, security))

        if self.user_manager.supports_user_claim:
            if claims := await self.user_manager.get_claims(user):
                identity.add_claims(*claims)

        if self.user_manager.supports_user_role:
            roles = await self.user_manager.get_roles(user)

            for role_name in roles:
                identity.add_claims(Claim(self.options.claims_identity.role_claim_type, role_name))

                if self.role_manager.supports_role_claims:
                    if role := await self.role_manager.find_by_name(role_name):
                        identity.add_claims(*(await self.role_manager.get_claims(role)))

        return ClaimsPrincipal(identity)
