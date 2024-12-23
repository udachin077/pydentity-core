## Password hashers

Password hasher uses [pwdlib](https://github.com/frankie567/pwdlib).

* BcryptPasswordHasher
* Argon2PasswordHasher
* PBKDF2PasswordHasher

### Custom password hasher

Implement the interface `IPasswordHasher`.

```python
from typing import Generic

from pydentity.interfaces import IPasswordHasher, PasswordVerificationResult
from pydentity.types import TUser


class CustomPasswordHasher(IPasswordHasher[TUser], Generic[TUser]):
    def hash_password(self, user: TUser, password: str) -> str:
        ...

    def verify_hashed_password(
            self,
            user: TUser,
            hashed_password: str,
            password: str
    ) -> PasswordVerificationResult:
        ...
```

Inherit the `PasswordHasher` class.

```python
from typing import Generic

from pwdlib.hashers import HasherProtocol

from pydentity.hashers.password_hashers import PasswordHasher
from pydentity.types import TUser


class MyHasher(HasherProtocol):
    ...


class CustomPasswordHasher(PasswordHasher[TUser], Generic[TUser]):
    def __init__(self):
        super().__init__((MyHasher(),))
```