from typing import Type, Generic, Any
from uuid import uuid4

from sqlalchemy import select, and_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from pydentity.identity_result import IdentityResult
from pydentity.interfaces.stores import IRoleClaimStore, IRoleStore
from pydentity.security.claims import Claim
from pydentity.types import TRole, TRoleClaim

__all__ = ("RoleStore",)


class RoleStore(IRoleClaimStore[TRole], IRoleStore[TRole], Generic[TRole]):
    role_model: Type[TRole]
    role_claim_model: Type[TRoleClaim]

    def __init__(self, session: AsyncSession):
        self.session = session

    def create_model_from_dict(self, **kwargs) -> TRole:
        return self.role_model(**kwargs)  # noqa

    async def save_changes(self) -> None:
        await self.session.commit()

    async def refresh(self, role: TRole) -> None:
        await self.session.refresh(role)

    async def all(self) -> list[TRole]:
        return list((await self.session.scalars(select(self.role_model))).all())

    async def create(self, role: TRole) -> IdentityResult:
        self.session.add(role)
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        role.concurrency_stamp = str(uuid4())
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        await self.session.delete(role)
        await self.save_changes()
        return IdentityResult.success()

    async def find_by_id(self, role_id: Any) -> TRole | None:
        statement = select(self.role_model).where(self.role_model.id == role_id)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def find_by_name(self, normalized_name: str) -> TRole | None:
        statement = select(self.role_model).where(self.role_model.normalized_name == normalized_name)  # type: ignore
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

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
        self.session.add(self._create_claim_to_db(role, claim))
        await self.save_changes()

    async def remove_claim(self, role: TRole, claim: Claim) -> None:
        statement = delete(self.role_claim_model).where(
            and_(
                self.role_claim_model.role_id == role.id,
                self.role_claim_model.claim_type == claim.type,
                self.role_claim_model.claim_value == claim.value,
            )
        )
        await self.session.execute(statement)

    async def get_claims(self, role: TRole) -> list[Claim]:
        statement = (
            select(self.role_claim_model).where(self.role_claim_model.role_id == role.id)  # type: ignore
        )
        role_claims = (await self.session.scalars(statement)).all()
        return [self._create_claim_from_db(uc) for uc in role_claims]

    def _create_claim_from_db(self, model: TRoleClaim) -> Claim:
        return Claim(claim_type=model.claim_type, claim_value=model.claim_value)

    def _create_claim_to_db(self, role: TRole, claim: Claim) -> TRoleClaim:
        return self.role_claim_model(role_id=role.id, claim_type=claim.type, claim_value=claim.value)
