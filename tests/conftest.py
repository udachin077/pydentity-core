from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from uuid_extensions import uuid7str

from pydentity.types import RoleProtokol, UserProtokol, GUID


@dataclass
class MockUser(UserProtokol):
    email: Optional[str]
    username: Optional[str]
    access_failed_count: int = 0
    concurrency_stamp: Optional[GUID] = None
    email_confirmed: bool = False
    id: str = field(default_factory=uuid7str)
    lockout_enabled: bool = True
    lockout_end: Optional[datetime] = None
    normalized_email: Optional[str] = None
    normalized_username: Optional[str] = None
    password_hash: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_confirmed: bool = False
    security_stamp: Optional[GUID] = field(default_factory=uuid7str)
    two_factor_enabled: bool = False


@dataclass
class MockRole(RoleProtokol):
    name: Optional[str]
    concurrency_stamp: Optional[GUID] = None
    id: str = field(default_factory=uuid7str)
    normalized_name: Optional[str] = None
