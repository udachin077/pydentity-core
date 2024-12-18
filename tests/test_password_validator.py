import pytest

from pydentity.identity_options import IdentityOptions
from pydentity.validators import PasswordValidator


class MockUserManager:
    def __init__(self, options):
        self.options = options


@pytest.fixture
def manager():
    return MockUserManager(IdentityOptions())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("t=yFV%w$`AG:vNP;8q9~/2", 'p"9Vu-Hk}>n/M*NPfZYUsa', "Ad%x7aZC",), True,),
        (("apnioxa8f114cy0s839ten", "W3$o90", "Gqz<u?+)`].<oLF.>",), False,),
    ],
)
async def test_validate(manager, passwords, expected):
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("BkEzD)<#", "SHx&|L{VjCF>leYP", "Oj8zSZu[e[`7/[Q;",), True,),
    ],
)
async def test_validate_not_required_digit(manager, passwords, expected):
    manager.options.password.required_digit = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("i*5b8[Jq#2W'-e%;", "z_.j$*hN;'_1HO", "a]CQe+BuAFNj#i7t",), True,),
        (("Mgn9L,U,XYo", "EVJ|*D_5dwfuV"), False,),
    ],
)
async def test_validate_required_length(manager, passwords, expected):
    manager.options.password.required_length = 14
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:",), True,),
        (("V;V1VVVgVV", "R;AuVMw>kC", "tLJ)MFkG[x:",), False,),
    ],
)
async def test_validate_required_unique_chars(manager, passwords, expected):
    manager.options.password.required_unique_chars = 8
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (('t~;r|%`c?j3vq<*y"b{h8d', 'e]:~6+>.n*!^g-a"}0#<$b', "p>`iznfg6bqr)#93j%_&h7",), True,),
    ],
)
async def test_validate_required_uppercase(manager, passwords, expected):
    manager.options.password.required_uppercase = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("PC_VT7F9H=]3K>6+A<N8M~", "XE[9.B4NU;D83L={", "TLJ8)MFKG[x2*3V6D>W}&:",), True,),
    ],
)
async def test_validate_required_lowercase(manager, passwords, expected):
    manager.options.password.required_lowercase = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (("RF6HwsoTzmB81q9e", "jbTg62GeyOw5UoB3", "vj789D3lw250eZAh",), True,),
    ],
)
async def test_validate_required_lowercase(manager, passwords, expected):
    manager.options.password.required_non_alphanumeric = False
    validator = PasswordValidator()
    for password in passwords:
        result = await validator.validate(manager, password)
        assert result.succeeded is expected, result.errors
