import pytest

from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim, ClaimTypes
from pydentity.security.claims.serializer import principal_dumps, principal_loads


@pytest.fixture
def principal():
    identity_1 = ClaimsIdentity(
        "Application.Auth",
        Claim(ClaimTypes.Name, "john_username"),
        Claim(ClaimTypes.Email, "john@mail.example"),
    )
    identity_2 = ClaimsIdentity(
        None,
        Claim(ClaimTypes.Locality, "London"),
        Claim("age", 22),
    )
    return ClaimsPrincipal(
        identity_1,
        identity_2,
    )


def test_principal_serialize(principal):
    sp = principal_dumps(principal)
    dp = principal_loads(sp)
    assert dp.identity.authentication_type == "Application.Auth"
    assert dp.identity.is_authenticated is True
    assert dp.has_claim(ClaimTypes.Locality, "London") is True
    assert dp.has_claim(ClaimTypes.Email, "john@mail.example") is True
    assert dp.has_claim(ClaimTypes.Name, "john_username") is True
    assert dp.has_claim("age", 22) is True
    assert dp.has_claim(ClaimTypes.AuthenticationMethod, "amr") is False
