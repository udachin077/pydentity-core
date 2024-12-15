from pydentity.utils import is_none_or_space


def test_is_none_or_space() -> None:
    assert is_none_or_space("") is True
    assert is_none_or_space(" ") is True
    assert is_none_or_space("  ") is True
    assert is_none_or_space(None) is True
    assert is_none_or_space("None") is False
    assert is_none_or_space("_") is False
    assert is_none_or_space("  .") is False

