import pytest
from uuid_extensions import uuid7

from pydentity.identity_options import IdentityOptions
from pydentity.types import UserProtokol
from pydentity.validators import UserValidator


class MockUser(UserProtokol):
    def __init__(self, id, email, username):
        self.id = id
        self.email = email
        self.username = username


USERS = [
    MockUser(id=uuid7().hex, email="admin@email.com", username="admin"),
    MockUser(id=uuid7().hex, email="user@email.com", username="user"),
]


class MockUserManager:
    options = IdentityOptions()

    async def get_username(self, user):
        return user.username

    async def get_email(self, user):
        return user.email

    async def get_user_id(self, user):
        return user.id

    async def find_by_name(self, name):
        for user in USERS:
            if user.username == name:
                return user
        return None

    async def find_by_email(self, email):
        for user in USERS:
            if user.email == email:
                return user
        return None


@pytest.fixture(scope="function")
def validator():
    return UserValidator()


@pytest.fixture(scope="function")
def manager():
    return MockUserManager()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(id=uuid7().hex, email="manager@email.com", username="manager"),
        MockUser(id=uuid7().hex, email="sysadmin@email.com", username="sysadmin"),
    ]
)
async def test_validate(manager, validator, user):
    result = await validator.validate(manager, user)
    assert result.succeeded == True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(id=uuid7().hex, email="admin@email.com", username="admin"),
        MockUser(id=uuid7().hex, email="user@email.com", username="user"),
    ]
)
async def test_validate_fail(manager, validator, user):
    result = await validator.validate(manager, user)
    assert result.succeeded == False
