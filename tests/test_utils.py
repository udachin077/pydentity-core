import pytest

from pydentity.utils import is_none_or_space, ensure_str, ensure_bytes


def test_is_none_or_space() -> None:
    assert is_none_or_space("") is True
    assert is_none_or_space(" ") is True
    assert is_none_or_space("  ") is True
    assert is_none_or_space(None) is True
    assert is_none_or_space("None") is False
    assert is_none_or_space("_") is False
    assert is_none_or_space("  .") is False

@pytest.mark.parametrize("v", ["string", b"string", "string".encode()])
def test_ensure_str(v):
    assert isinstance(ensure_str(v), str)


@pytest.mark.parametrize("v", ["string", b"string", "string".encode()])
def test_ensure_bytes(v):
    assert isinstance(ensure_bytes(v), bytes)