import os

import pytest

from pydentity.dataprotector import DefaultPersonalDataProtector

PERSONAL_DATA = (
    "email@email.com",
    123456,
    ["a", "b", "c"],
    {"phone_number": "+ 0 (000) 000 00 00", "email": "email@email.com", "id": 123456},
)


@pytest.fixture(scope="function")
def fernet_protector() -> DefaultPersonalDataProtector:
    return DefaultPersonalDataProtector()


@pytest.mark.parametrize("data", PERSONAL_DATA)
def test_fernet(fernet_protector, data):
    protected_message = fernet_protector.protect(data)
    unprotected_message = fernet_protector.unprotect(protected_message)
    assert unprotected_message == data


@pytest.mark.parametrize("data", PERSONAL_DATA)
def test_fernet_raise(fernet_protector, data):
    invalid_protector = DefaultPersonalDataProtector(os.urandom(32))
    protected_message = fernet_protector.protect(data)
    with pytest.raises(Exception):
        invalid_protector.unprotect(protected_message)


def test_init_protector_raise():
    with pytest.raises(ValueError):
        # invalid key length
        DefaultPersonalDataProtector("protector")
