import pytest

from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity, Claim, ClaimTypes


@pytest.fixture
def identity():
    return ClaimsIdentity(
        "Application.Auth",
        Claim(ClaimTypes.Name, "john_username"),
        Claim(ClaimTypes.Email, "john@mail.example"),
        Claim(ClaimTypes.Role, "role1"),
        Claim(ClaimTypes.Role, "role2"),
        Claim(ClaimTypes.Locality, "Paris"),
    )


@pytest.fixture
def principal(identity):
    identity_2 = ClaimsIdentity(
        None,
        Claim(ClaimTypes.Locality, "London"),
        Claim("age", 22),
    )
    return ClaimsPrincipal(
        identity,
        identity_2,
    )


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, 2,),
        (ClaimTypes.Name, 1,),
        (ClaimTypes.AuthenticationMethod, 0,),
        (lambda c: bool(c and c.type == ClaimTypes.Name), 1,),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), 0,),
    ],
)
def test_claims_identity_find_all(identity, _match, expected):
    assert len(list(identity.find_all(_match))) == expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, True,),
        (ClaimTypes.Name, True,),
        (ClaimTypes.AuthenticationMethod, False,),
        (lambda c: bool(c and c.type == ClaimTypes.Name), True,),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), False,),
    ],
)
def test_claims_identity_find_first(identity, _match, expected):
    assert bool(identity.find_first(_match)) is expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, ("role1", "role2",),),
        (ClaimTypes.Name, ("john_username",),),
        (ClaimTypes.AuthenticationMethod, (None,),),
        (lambda c: bool(c and c.type == ClaimTypes.Name), ("john_username",),),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), (None,),),
    ],
)
def test_claims_identity_find_first(identity, _match, expected):
    assert identity.find_first_value(_match) in expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        ((ClaimTypes.Role, "role1",), True,),
        ((ClaimTypes.Name, "john_username",), True,),
        ((ClaimTypes.AuthenticationMethod, "amr"), False,),
        ((lambda c: bool(c and c.type == ClaimTypes.Name),), True,),
        ((lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod),), False,),
    ],
)
def test_claims_identity_find_first(identity, _match, expected):
    assert identity.has_claim(*_match) is expected  # type: ignore


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, 2,),
        (ClaimTypes.Name, 1,),
        (ClaimTypes.AuthenticationMethod, 0,),
        (lambda c: bool(c and c.type == ClaimTypes.Name), 1,),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), 0,),
    ],
)
def test_claims_principal_find_all(principal, _match, expected):
    assert len(list(principal.find_all(_match))) == expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, True,),
        (ClaimTypes.Name, True,),
        (ClaimTypes.AuthenticationMethod, False,),
        (lambda c: bool(c and c.type == ClaimTypes.Name), True,),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), False,),
    ],
)
def test_claims_principal_find_first(principal, _match, expected):
    assert bool(principal.find_first(_match)) is expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        (ClaimTypes.Role, ("role1", "role2",),),
        (ClaimTypes.Name, ("john_username",),),
        (ClaimTypes.AuthenticationMethod, (None,),),
        (lambda c: bool(c and c.type == ClaimTypes.Name), ("john_username",),),
        (lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod), (None,),),
    ],
)
def test_claims_principal_find_first(principal, _match, expected):
    assert principal.find_first_value(_match) in expected


@pytest.mark.parametrize(
    "_match,expected",
    [
        (("age", 22,), True,),
        ((ClaimTypes.Locality, "London",), True,),
        ((ClaimTypes.AuthenticationMethod, "amr"), False,),
        ((lambda c: bool(c and c.type == ClaimTypes.Name),), True,),
        ((lambda c: bool(c and c.type == ClaimTypes.AuthenticationMethod),), False,),
    ],
)
def test_claims_principal_find_first(principal, _match, expected):
    assert principal.has_claim(*_match) is expected  # type: ignore


@pytest.mark.parametrize(
    "_match,expected",
    [
        ("role1", True,),
        ("role2", True,),
        ("admin", False,),
    ],
)
def test_claims_principal_is_in_role(principal, _match, expected):
    assert principal.is_in_role(_match) is expected


@pytest.mark.parametrize(
    "_match,expected_any,expected_all",
    [
        (("role1", "role2",), True, True,),
        (("admin", "role2",), True, False,),
        (("admin", "manager",), False, False,),
    ],
)
def test_claims_principal_is_in_roles(principal, _match, expected_any, expected_all):
    assert principal.is_in_roles(*_match, mode="any") is expected_any
    assert principal.is_in_roles(*_match, mode="all") is expected_all
