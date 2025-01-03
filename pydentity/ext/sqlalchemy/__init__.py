from pydentity import DefaultPersonalDataProtector
from pydentity.interfaces import IPersonalDataProtector

from pydentity_db.fields import PersonalDataField

__all__ = ("use_personal_data_protector",)


def use_personal_data_protector(protector: IPersonalDataProtector | None = None) -> None:
    """
    Sets the ``IPersonalDataProtector`` for ``ProtectedPersonalDataField`` fields.
    When using the function, a protector will be installed,
    the data will be encrypted when writing and decrypted when receiving.
    If the value of protector is None, the default protector will be set.

    :param protector:
    :return:
    """
    PersonalDataField.protector = protector or DefaultPersonalDataProtector()
