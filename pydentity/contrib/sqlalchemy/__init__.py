from pydentity.dataprotector import PersonalDataProtector
from pydentity.contrib.sqlalchemy.fields import PersonalDataField
from pydentity.interfaces.dataprotector import IDataProtector

__all__ = ("use_personal_data_protector",)


def use_personal_data_protector(protector: IDataProtector | None = None) -> None:
    """
    Sets the *IDataProtector* for *PersonalDataField* fields.
    When using the function, a protector will be installed,
    the data will be encrypted when writing and decrypted when receiving.
    If the value of protector is None, the default protector will be set.

    :param protector:
    :return:
    """
    PersonalDataField.protector = protector or PersonalDataProtector()
