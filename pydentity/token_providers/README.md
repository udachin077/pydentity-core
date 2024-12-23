## Token providers

Token providers uses [pyotp](https://github.com/pyauth/pyotp).

* EmailTokenProvider
* PhoneNumberTokenProvider
* AuthenticatorTokenProvider
* DataProtectorTokenProvider

### Custom token provider

Implement the interface `IUserTwoFactorTokenProvider`.

```python
from pydentity.interfaces import IUserTwoFactorTokenProvider
from pydentity.types import TUser


class CustomTokenProvider(IUserTwoFactorTokenProvider[TUser]):
    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        ...

    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        ...

    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        ...
```

Inherit the `TotpSecurityStampBasedTokenProvider` class.

```python
from typing import Generic, override

from pydentity.token_providers import TotpSecurityStampBasedTokenProvider
from pydentity.types import TUser


class CustomTokenProvider(TotpSecurityStampBasedTokenProvider[TUser], Generic[TUser]):
    @override
    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        ...

    @override
    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        ...

    @override
    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        ...
```