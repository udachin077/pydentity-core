## Validators

* UserValidator (uses [email-validator](https://github.com/JoshData/python-email-validator))
* RoleValidator
* PasswordValidator

### Custom validators

Implement the interface `IUserValidator`, `IRoleValidator`, `IPasswordValidator`.

```python
from typing import Generic

from pydentity import IdentityResult
from pydentity.interfaces import IUserValidator, IRoleValidator, IPasswordValidator
from pydentity.types import TUser, TRole


class CustomUserValidator(IUserValidator[TUser], Generic[TUser]):
    async def validate(self, manager: "UserManager[TUser]", user: TUser) -> IdentityResult:
        pass


class CustomRoleValidator(IRoleValidator[TUser], Generic[TUser]):
    async def validate(self, manager: "RoleManager[TRole]", role: TRole) -> IdentityResult:
        pass


class CustomPasswordValidator(IPasswordValidator[TUser], Generic[TUser]):
    async def validate(self, manager: "UserManager[TUser]", password: str) -> IdentityResult:
        pass
```

Inherit the `UserValidator`, `RoleValidator`, `PasswordValidator` class.

```python
from typing import Generic, override

from pydentity import IdentityResult
from pydentity.types import TUser, TRole
from pydentity.validators import RoleValidator, UserValidator, PasswordValidator


class CustomUserValidator(UserValidator[TUser], Generic[TUser]):
    @override
    async def validate(self, manager: "UserManager[TUser]", user: TUser) -> IdentityResult:
        pass


class CustomRoleValidator(RoleValidator[TUser], Generic[TUser]):
    @override
    async def validate(self, manager: "RoleManager[TRole]", role: TRole) -> IdentityResult:
        pass


class CustomPasswordValidator(PasswordValidator[TUser], Generic[TUser]):
    @override
    async def validate(self, manager: "UserManager[TUser]", password: str) -> IdentityResult:
        pass
```