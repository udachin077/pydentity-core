import base64
from time import sleep

import pytest

from pydentity.rfc6238service import generate_code, validate_code

tokens = ["EmailConfirmation", "Authenticator"]
intervals_false = [1, 2, 3]


@pytest.mark.parametrize("token", tokens)
def test_generate_code_true(token):
    secret = base64.b32encode(token.encode()).decode()
    code = generate_code(secret)
    sleep(2)
    result = validate_code(secret, code)
    assert result is True


@pytest.mark.parametrize("token", tokens)
@pytest.mark.parametrize("interval", intervals_false)
def test_generate_code_false(token, interval):
    secret = base64.b32encode(token.encode()).decode()
    code = generate_code(secret, interval=interval)
    sleep(3)
    result = validate_code(secret, code, interval=interval)
    assert result is False


@pytest.mark.parametrize("token", tokens)
def test_generate_code_with_modifier(token):
    secret = base64.b32encode(token.encode()).decode()
    code = generate_code(secret)
    result = validate_code(secret, code)
    assert result is True
