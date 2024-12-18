import pytest

from conftest import MockRole
from pydentity.validators import RoleValidator

ROLES = [
    MockRole(name="admin", normalized_name="admin"),
    MockRole(name="user", normalized_name="user"),
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
def role_validator():
    return RoleValidator()


@pytest.fixture(scope="function")
def manager():
    return MockRoleManager()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(name="manager"), MockRole(name="sysadmin"), *ROLES])
async def test_validate(manager, role_validator, role):
    result = await role_validator.validate(manager, role)
    assert result.succeeded is True


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(name="admin"), MockRole(name="user")])
async def test_validate_fail(manager, role_validator, role):
    result = await role_validator.validate(manager, role)
    assert result.succeeded is False
