from typing import Any

import pytest
from uuid_extensions import uuid7str

from conftest import MockRole
from pydentity import RoleManager, IdentityResult
from pydentity.interfaces.stores import IRoleStore, IRoleClaimStore
from pydentity.security.claims import Claim
from pydentity.types import TRole
from pydentity.validators import RoleValidator

ROLES = [
    MockRole(name="admin", normalized_name="admin"),
    MockRole(name="user", normalized_name="user"),
    MockRole(name="manager", normalized_name="manager"),
    MockRole(name="guest", normalized_name="guest"),
    MockRole(name="empl", normalized_name="empl"),
]


class NotSupportsRoleClaimsRoleStore(IRoleStore):
    def create_model_from_dict(self, **kwargs: Any) -> TRole:
        pass

    async def all(self) -> list[TRole]:
        pass

    async def create(self, role: TRole) -> IdentityResult:
        pass

    async def update(self, role: TRole) -> IdentityResult:
        pass

    async def delete(self, role: TRole) -> IdentityResult:
        pass

    async def find_by_id(self, role_id: str) -> TRole | None:
        pass

    async def find_by_name(self, normalized_name: str) -> TRole | None:
        pass

    async def get_role_id(self, role: TRole) -> str:
        pass

    async def get_role_name(self, role: TRole) -> str | None:
        pass

    async def set_role_name(self, role: TRole, role_name: str | None) -> None:
        pass

    async def get_normalized_role_name(self, role: TRole) -> str | None:
        pass

    async def set_normalized_role_name(self, role: TRole, normalized_name: str | None) -> None:
        pass


class MockRoleStore(IRoleClaimStore, IRoleStore):
    async def get_claims(self, role: TRole) -> list[Claim]:
        pass

    async def add_claim(self, role: TRole, claims: Claim) -> None:
        pass

    async def remove_claim(self, role: TRole, claim: Claim) -> None:
        pass

    def create_model_from_dict(self, **kwargs: Any) -> TRole:
        pass

    async def all(self) -> list[TRole]:
        return ROLES

    async def create(self, role: TRole) -> IdentityResult:
        ROLES.append(role)
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        for r in ROLES:
            if r.id == role.id:
                ROLES.remove(r)
                break
        ROLES.append(role)
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        for r in ROLES:
            if r.id == role.id:
                ROLES.remove(r)
                return IdentityResult.success()
        return IdentityResult.failed()

    async def find_by_id(self, role_id: str) -> TRole | None:
        for r in ROLES:
            if r.id == role_id:
                return r

    async def find_by_name(self, normalized_name: str) -> TRole | None:
        for r in ROLES:
            if r.normalized_name == normalized_name:
                return r

    async def get_role_id(self, role: TRole) -> str:
        return role.id

    async def get_role_name(self, role: TRole) -> str | None:
        return role.name

    async def set_role_name(self, role: TRole, role_name: str | None) -> None:
        role.name = role_name

    async def get_normalized_role_name(self, role: TRole) -> str | None:
        return role.normalized_name

    async def set_normalized_role_name(self, role: TRole, normalized_name: str | None) -> None:
        role.normalized_name = normalized_name


@pytest.fixture(scope="session")
def role_manager():
    return RoleManager(MockRoleStore(), role_validators=(RoleValidator(),))


@pytest.mark.parametrize(
    "manager,result",
    [
        (RoleManager(NotSupportsRoleClaimsRoleStore()), False),
        (RoleManager(MockRoleStore()), True),
    ],
)
def test_supports_role_claims(manager, result):
    assert manager.supports_role_claims is result


@pytest.mark.asyncio
async def test_all(role_manager):
    roles = await role_manager.all()
    assert len(roles) == 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "roles,result",
    [
        ((MockRole("sysadmin"),), True,),
        ((MockRole("admin"), MockRole("user"),), False,),
    ],
)
async def test_create(role_manager, roles, result):
    for role in roles:
        res = await role_manager.create(role)
        assert res.succeeded is result


# @pytest.mark.asyncio
# def test_update():
#     assert False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "roles,result",
    [
        (ROLES[0:1:], True,),
        ((MockRole("sys_admin"),), False,),
    ],
)
async def test_delete(role_manager, roles, result):
    for role in roles:
        res = await role_manager.delete(role)
        assert res.succeeded is result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role_names,result",
    [
        (("role_1", "role_2",), False),
        (("guest", "user",), True),
    ],
)
async def test_role_exists(role_manager, role_names, result):
    for name in role_names:
        assert await role_manager.role_exists(name) is result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role_ids,result",
    [
        ((r.id for r in ROLES), True),
        ((uuid7str(), uuid7str(),), False,),
    ],
)
async def test_find_by_id(role_manager, role_ids, result):
    for _id in role_ids:
        assert bool(await role_manager.find_by_id(_id)) is result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role_names,result",
    [
        (("role_1", "role_2",), False),
        (("guest", "user",), True),
    ],
)
async def test_find_by_name(role_manager, role_names, result):
    for name in role_names:
        assert bool(await role_manager.find_by_name(name)) is result

# def test_get_claims():
#     assert False


# def test_add_claim():
#     assert False


# def test_remove_claim():
#     assert False
