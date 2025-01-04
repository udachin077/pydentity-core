from typing import override

from sqlalchemy import TypeDecorator, String

from pydentity.dataprotector import PersonalDataProtector
from pydentity.interfaces.dataprotector import IDataProtector


class PersonalDataField(TypeDecorator):
    """A variably sized protected string type.

    If a protector is installed, the data will be encrypted when writing and decrypted when receiving.
    """

    impl = String
    cache_ok = True
    protector: IDataProtector | None = PersonalDataProtector()

    @override
    def process_bind_param(self, value, dialect):
        if value and self.protector:
            value = self.protector.protect(value)
        return value

    @override
    def process_result_value(self, value, dialect):
        if value and self.protector:
            value = self.protector.unprotect(value)
        return value
