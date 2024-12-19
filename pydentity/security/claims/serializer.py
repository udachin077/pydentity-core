import json
from collections import defaultdict
from typing import Any

from pydentity.security.claims.claims import ClaimsPrincipal, ClaimsIdentity, Claim, DEFAULT_ISSUER  # noqa

__all__ = (
    "principal_dumps",
    "principal_loads",
)


def _generate_identity_name(identity: ClaimsIdentity) -> str:
    return "%s$%s$%s" % (
        identity.authentication_type,
        identity.name_claim_type,
        identity.role_claim_type,
    )


def _parse_identity_name(key: str) -> tuple[str, str | None, str | None]:
    auth, name_type, role_type = key.rsplit("$", maxsplit=2)
    return (
        auth,
        name_type,
        role_type,
    )


def claim_to_dict(claim: Claim, exclude_default: bool = True) -> dict[str, Any]:
    result = {"claim_type": claim.type, "claim_value": claim.value}

    if exclude_default:
        if claim.issuer != DEFAULT_ISSUER:
            result.update({"issuer": claim.issuer})

        if claim.original_issuer != DEFAULT_ISSUER:
            result.update({"original_issuer": claim.original_issuer})
    else:
        result.update({"issuer": claim.issuer, "original_issuer": claim.original_issuer})

    return result


def claim_from_dict(kwargs: dict[str, Any]) -> Claim:
    return Claim(**kwargs)


def principal_dumps(principal: ClaimsPrincipal) -> str | None:
    if principal is None:
        return None

    result: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for identity in principal.identities:
        key = _generate_identity_name(identity)
        for claim in identity.claims:
            result[key].append(claim_to_dict(claim))

    return json.dumps(result, separators=(",", ":"))


def principal_loads(data: str | bytes | bytearray) -> ClaimsPrincipal | None:
    if data is None:
        return None

    principal = ClaimsPrincipal()
    load_data: dict[str, list[dict[str, Any]]] = json.loads(data)

    for key, value in load_data.items():
        authentication_type, name_claim_type, role_claim_type = _parse_identity_name(key)
        identity = ClaimsIdentity(
            authentication_type,
            *(claim_from_dict(claim_dict) for claim_dict in value),
            name_claim_type=name_claim_type,
            role_claim_type=role_claim_type,
        )
        principal.add_identities(identity)

    return principal
