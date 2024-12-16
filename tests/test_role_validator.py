import pytest
from uuid_extensions import uuid7

from pydentity.types import RoleProtokol
from pydentity.validators import RoleValidator


class MockRole(RoleProtokol):
    def __init__(self, id, name):
        self.id = id
        self.name = name


ROLES = [
    MockRole(id=uuid7().hex, name="admin"),
    MockRole(id=uuid7().hex, name="user"),
]


class MockRoleManager:
    async def get_role_name(self, role):
        return role.name

    async def get_role_id(self, role):
        return role.id

    async def find_by_name(self, name):
        for role in ROLES:
            if role.name == name:
                return role
        return None


@pytest.fixture(scope="function")
def validator() -> RoleValidator:
    return RoleValidator()


@pytest.fixture(scope="function")
def manager():
    return MockRoleManager()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(id=uuid7().hex, name="manager"), MockRole(id=uuid7().hex, name="sysadmin")])
async def test_validate(manager, validator, role):
    result = await validator.validate(manager, role)
    assert result.succeeded == True


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(id=uuid7().hex, name="admin"), MockRole(id=uuid7().hex, name="user")])
async def test_validate_fail(manager, validator, role):
    result = await validator.validate(manager, role)
    assert result.succeeded == False
