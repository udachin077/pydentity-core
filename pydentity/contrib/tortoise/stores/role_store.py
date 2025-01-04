from typing import Type, Generic, Any
from uuid import uuid4

from tortoise.backends.base.client import BaseDBAsyncClient

from pydentity.identity_result import IdentityResult
from pydentity.interfaces.stores import IRoleClaimStore, IRoleStore
from pydentity.security.claims import Claim
from pydentity.types import TRole, TRoleClaim

__all__ = ("RoleStore",)


class RoleStore(IRoleClaimStore[TRole], IRoleStore[TRole], Generic[TRole]):
    role_model: Type[TRole]
    role_claim_model: Type[TRoleClaim]

    def __init__(self, transaction: BaseDBAsyncClient = None):
        self.transaction = transaction

    def create_model_from_dict(self, **kwargs):
        return self.role_model(**kwargs)

    async def refresh(self, role: TRole):
        await role.refresh_from_db(using_db=self.transaction)

    async def all(self) -> list[TRole]:
        return await self.role_model.all(using_db=self.transaction)

    async def create(self, role: TRole) -> IdentityResult:
        await role.save(using_db=self.transaction)
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        role.concurrency_stamp = uuid4()
        await role.save(using_db=self.transaction)
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        await role.delete(using_db=self.transaction)
        return IdentityResult.success()

    async def find_by_id(self, role_id: Any) -> TRole | None:
        return await self.role_model.get_or_none(id=role_id, using_db=self.transaction)

    async def find_by_name(self, normalized_name: str) -> TRole | None:
        return await self.role_model.get_or_none(normalized_name=normalized_name, using_db=self.transaction)

    async def get_role_id(self, role: TRole) -> Any:
        return role.id

    async def get_role_name(self, role: TRole) -> str | None:
        return role.name

    async def set_role_name(self, role: TRole, role_name: str | None) -> None:
        role.name = role_name

    async def get_normalized_role_name(self, role: TRole) -> str | None:
        return role.normalized_name

    async def set_normalized_role_name(self, role: TRole, normalized_name: str | None) -> None:
        role.normalized_name = normalized_name

    async def add_claim(self, role: TRole, claim: Claim) -> None:
        await self.role_claim_model(role_id=role.id, claim_type=claim.type, claim_value=claim.value).save(
            self.transaction
        )

    async def remove_claim(self, role: TRole, claim: Claim) -> None:
        await (
            self.role_claim_model.filter(role_id=role.id, claim_type=claim.type, claim_value=claim.value)
            .using_db(self.transaction)
            .delete()
        )

    async def get_claims(self, role: TRole) -> list[Claim]:
        result = await (
            self.role_claim_model.filter(role_id=role.id)
            .using_db(self.transaction)
            .values_list("claim_type", "claim_value")
        )
        return [Claim(*r) for r in result]
