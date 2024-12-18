import pytest

from conftest import MockUser
from pydentity.identity_options import IdentityOptions
from pydentity.validators import UserValidator

USERS = [
    MockUser(
        email="alex@email.com",
        username="alex",
        normalized_email="alex@email.com",
        normalized_username="alex",
    ),
    MockUser(
        email="john@email.com",
        username="john",
        normalized_email="john@email.com",
        normalized_username="john",
    ),
    MockUser(
        email="sam@email.com",
        username="sam",
        normalized_email="sam@email.com",
        normalized_username="sam",
    ),
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
def user_validator():
    return UserValidator()


@pytest.fixture(scope="function")
def manager():
    return MockUserManager()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(
            email="anna@email.com",
            username="anna",
            normalized_email="anna@email.com",
            normalized_username="anna"
        ),
        MockUser(
            email="ella@email.com",
            username="ella",
            normalized_email="ella@email.com",
            normalized_username="ella"
        ),
    ],
)
async def test_validate(manager, user_validator, user):
    result = await user_validator.validate(manager, user)
    assert result.succeeded == True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(
            email="alex@email.com",
            username="alex",
            normalized_email="alex@email.com",
            normalized_username="alex",
        ),
        MockUser(
            email="john@email.com",
            username="john",
            normalized_email="john@email.com",
            normalized_username="john",
        ),
    ],
)
async def test_validate_fail(manager, user_validator, user):
    result = await user_validator.validate(manager, user)
    assert result.succeeded == False
