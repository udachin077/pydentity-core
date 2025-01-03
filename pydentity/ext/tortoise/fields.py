from typing import override

from tortoise.fields import CharField

from pydentity.dataprotector import PersonalDataProtector
from pydentity.interfaces.dataprotector import IDataProtector


class PersonalDataField(CharField):
    """A variably sized protected CharField.

    If a protector is installed, the data will be encrypted when writing and decrypted when receiving.
    """

    protector: IDataProtector | None = PersonalDataProtector()

    @override
    def to_db_value(self, value, instance):
        if value and self.protector:
            value = self.protector.protect(value)
        return value

    @override
    def to_python_value(self, value):
        if value and self.protector:
            value = self.protector.unprotect(value)
        return value
