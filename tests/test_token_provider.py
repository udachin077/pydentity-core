import pytest
from uuid_extensions import uuid7str

from pydentity import IdentityOptions
from pydentity.rfc6238service import generate_code, generate_key
from pydentity.token_providers import (
    TotpSecurityStampBasedTokenProvider,
    AuthenticatorTokenProvider,
    DataProtectorTokenProvider,
)
from pydentity.types import UserProtokol
from pydentity.utils import ensure_bytes


class MockUser(UserProtokol):
    authenticator_key: str


class MockUserManager:
    options = IdentityOptions()

    @property
    def supports_user_security_stamp(self):
        return True

    async def create_security_token(self, user) -> bytes:
        return ensure_bytes(user.security_stamp)

    async def get_user_id(self, user) -> str:
        return user.id

    async def get_authenticator_key(self, user) -> str:
        return user.authenticator_key

    async def get_security_stamp(self, user) -> str:
        return user.security_stamp


@pytest.fixture
def user():
    user = MockUser()
    user.id = uuid7str()
    user.security_stamp = uuid7str()
    user.authenticator_key = generate_key()
    return user


@pytest.fixture(scope="session")
def manager():
    return MockUserManager()


@pytest.mark.asyncio
async def test_totp_security_stamp_based_token_provider(manager, user):
    provider = TotpSecurityStampBasedTokenProvider()
    assert await provider.can_generate_two_factor(manager, user) is True
    token = await provider.generate(manager, "totp", user)
    result = await provider.validate(manager, "totp", token, user)
    assert result is True
    result = await provider.validate(manager, "fake", token, user)
    assert result is False


@pytest.mark.asyncio
async def test_authenticator_token_provider(manager, user):
    provider = AuthenticatorTokenProvider()
    assert await provider.can_generate_two_factor(manager, user) is True
    token = await provider.generate(manager, "", user)
    assert token == ""
    token = generate_code(await manager.get_authenticator_key(user))
    result = await provider.validate(manager, "", token, user)
    assert result is True


@pytest.mark.asyncio
async def test_data_protector_token_provider(manager, user):
    provider = DataProtectorTokenProvider()
    assert await provider.can_generate_two_factor(manager, user) is False
    token = await provider.generate(manager, "totp", user)
    result = await provider.validate(manager, "totp", token, user)
    assert result is True
    result = await provider.validate(manager, "fake", token, user)
    assert result is False
