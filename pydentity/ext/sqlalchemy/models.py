from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, declared_attr, relationship
from uuid_extensions import uuid7str

from pydentity.ext.sqlalchemy.base.abstract import (
    AbstractIdentityUser,
    AbstractIdentityRole,
    AbstractIdentityUserRole,
    AbstractIdentityUserClaim,
    AbstractIdentityUserLogin,
    AbstractIdentityUserToken,
    AbstractIdentityRoleClaim,
)

__all__ = (
    "IdentityRole",
    "IdentityRoleClaim",
    "IdentityUser",
    "IdentityUserClaim",
    "IdentityUserLogin",
    "IdentityUserRole",
    "IdentityUserToken",
)


class IdentityUser(AbstractIdentityUser):
    """The default implementation of AbstractIdentityUser which uses a string as a primary key."""

    __personal_data__ = (
        "id",
        "username",
        "email",
        "email_confirmed",
        "phone_number",
        "phone_number_confirmed",
        "two_factor_enabled",
    )

    id: Mapped[str] = mapped_column(sa.String(450))

    @declared_attr
    def roles(cls) -> Mapped[list["IdentityRole"]]:
        return relationship(
            "IdentityRole", back_populates="users", secondary="pydentity_user_roles", cascade="all, delete"
        )

    @declared_attr
    def claims(cls) -> Mapped[list["IdentityUserClaim"]]:
        return relationship("IdentityUserClaim", back_populates="user", cascade="all, delete")

    @declared_attr
    def logins(cls) -> Mapped[list["IdentityUserLogin"]]:
        return relationship("IdentityUserLogin", back_populates="user", cascade="all, delete")

    @declared_attr
    def tokens(cls) -> Mapped[list["IdentityUserToken"]]:
        return relationship("IdentityUserToken", back_populates="user", cascade="all, delete")

    def __init__(self, email: str, username: str | None = None, **kwargs) -> None:
        super().__init__(id=uuid7str(), email=email, username=username, security_stamp=str(uuid4()), **kwargs)


class IdentityRole(AbstractIdentityRole):
    """The default implementation of AbstractIdentityRole which uses a string as the primary key."""

    id: Mapped[str] = mapped_column(sa.String(450))

    @declared_attr
    def users(cls) -> Mapped[list["IdentityUser"]]:
        return relationship("IdentityUser", back_populates="roles", secondary="pydentity_user_roles")

    @declared_attr
    def claims(cls) -> Mapped[list["IdentityRoleClaim"]]:
        return relationship("IdentityRoleClaim", back_populates="role", cascade="all, delete")

    def __init__(self, name: str, **kwargs) -> None:
        super().__init__(id=uuid7str(), name=name, **kwargs)


class IdentityUserRole(AbstractIdentityUserRole):
    """Represents the link between a user and a role."""


class IdentityUserClaim(AbstractIdentityUserClaim):
    """Represents a claim that a user possesses."""

    @declared_attr
    def user(self) -> Mapped["IdentityUser"]:
        return relationship("IdentityUser", back_populates="claims")


class IdentityUserLogin(AbstractIdentityUserLogin):
    """Represents a login and its associated provider for a user."""

    @declared_attr
    def user(self) -> Mapped["IdentityUser"]:
        return relationship("IdentityUser", back_populates="logins")


class IdentityUserToken(AbstractIdentityUserToken):
    """Represents an authentication token for a user."""

    @declared_attr
    def user(self) -> Mapped["IdentityUser"]:
        return relationship("IdentityUser", back_populates="tokens")


class IdentityRoleClaim(AbstractIdentityRoleClaim):
    """Represents a claim that is granted to all users within a role."""

    @declared_attr
    def role(self) -> Mapped["IdentityRole"]:
        return relationship("IdentityRole", back_populates="claims")
