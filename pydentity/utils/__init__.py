__all__ = (
    "is_null_or_whitespace",
    "ensure_str",
    "ensure_bytes",
)


def is_null_or_whitespace(v: str | None, /) -> bool:
    return bool(not v or v.isspace())


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v
