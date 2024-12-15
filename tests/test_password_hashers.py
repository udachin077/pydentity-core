import pytest

from pydentity.hashers.password_hashers import BcryptPasswordHasher, Argon2PasswordHasher
from pydentity.interfaces import PasswordVerificationResult
from pydentity.types import UserProtokol


class MockUser(UserProtokol):
    pass


@pytest.fixture
def user():
    return MockUser()


hashers = [BcryptPasswordHasher(), Argon2PasswordHasher()]
passwords = ["s>(2-8C;gP5X?[pYU=aM@9", "jwNt;&d6SkTBvu_c-n]=LY", "Dw2Cr]c>~duV(:$B6zSFgW"]


@pytest.mark.parametrize("hasher", hashers)
@pytest.mark.parametrize("password", passwords)
def test_password_hasher(hasher, password, user):
    pwd_hash = hasher.hash_password(user, password)
    assert password != pwd_hash
    result = hasher.verify_hashed_password(user, pwd_hash, password)
    assert result == PasswordVerificationResult.Success


@pytest.mark.parametrize("hasher", hashers)
@pytest.mark.parametrize("password", passwords)
def test_password_hasher_failed(hasher, password, user):
    pwd_hash = hasher.hash_password(user, "password")
    assert password != pwd_hash
    result = hasher.verify_hashed_password(user, pwd_hash, password)
    assert result == PasswordVerificationResult.Failed
