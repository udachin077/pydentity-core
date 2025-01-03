from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from tortoise import fields

from pydentity.ext.tortoise.base.model import Model
from pydentity.ext.tortoise.fields import PersonalDataField
from pydentity.types import TKey

__all__ = (
    "AbstractIdentityUser",
    "AbstractIdentityRole",
    "AbstractIdentityUserRole",
    "AbstractIdentityUserClaim",
    "AbstractIdentityRoleClaim",
    "AbstractIdentityUserToken",
    "AbstractIdentityUserLogin",
    "Model",
)


class AbstractIdentityUser(Model):
    if TYPE_CHECKING:
        access_failed_count: int
        concurrency_stamp: str | UUID | None
        email: str | None
        email_confirmed: bool
        id: TKey
        lockout_enabled: bool
        lockout_end: datetime | None
        normalized_email: str | None
        normalized_username: str | None
        password_hash: str | None
        phone_number: str | None
        phone_number_confirmed: bool
        security_stamp: str | UUID | None
        two_factor_enabled: bool
        username: str | None
    else:
        access_failed_count = fields.IntField(default=0)
        concurrency_stamp = fields.TextField(null=True)
        email = PersonalDataField(256, null=True)
        email_confirmed = fields.BooleanField(default=False)
        lockout_enabled = fields.BooleanField(default=True)
        lockout_end = fields.DatetimeField(null=True)
        normalized_email = PersonalDataField(256, null=True)
        normalized_username = PersonalDataField(256, null=True)
        password_hash = fields.TextField(null=True)
        phone_number = PersonalDataField(256, null=True)
        phone_number_confirmed = fields.BooleanField(default=False)
        security_stamp = fields.UUIDField(null=True)
        two_factor_enabled = fields.BooleanField(default=False)
        username = PersonalDataField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self) -> str:
        return self.username or self.email or self.id

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {str(self)} object at {hex(id(self))}>"


class AbstractIdentityRole(Model):
    if TYPE_CHECKING:
        concurrency_stamp: str | UUID | None
        id: TKey
        name: str | None
        normalized_name: str | None
    else:
        concurrency_stamp = fields.TextField(null=True)
        name = fields.CharField(256, null=True)
        normalized_name = fields.CharField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self):
        return self.name or self.id

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {str(self)} object at {hex(id(self))}>"


class AbstractIdentityUserRole(Model):
    if TYPE_CHECKING:
        user_id: TKey
        role_id: TKey

    class Meta:
        abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.role_id=}) object at {hex(id(self))}>"


class AbstractIdentityUserClaim(Model):
    if TYPE_CHECKING:
        claim_type: str | None
        claim_value: str | None
        user_id: TKey
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.TextField(null=True)
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.claim_type=}) object at {hex(id(self))}>"


class AbstractIdentityUserLogin(Model):
    if TYPE_CHECKING:
        login_provider: str
        provider_key: str
        provider_display_name: str | None
        user_id: TKey
    else:
        login_provider = fields.CharField(128)
        provider_key = fields.CharField(128)
        provider_display_name = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"


class AbstractIdentityUserToken(Model):
    if TYPE_CHECKING:
        login_provider: str
        name: str
        value: str | None
        user_id: TKey
    else:
        login_provider = fields.CharField(128)
        name = fields.CharField(128)
        value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"


class AbstractIdentityRoleClaim(Model):
    if TYPE_CHECKING:
        id: int
        claim_type: str | None
        claim_value: str | None
        role_id: TKey
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.CharField(455)
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.role_id=}, {self.claim_type=}) object at {hex(id(self))}>"
