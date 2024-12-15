from abc import ABC, abstractmethod
from typing import Any


class IPersonalDataProtector(ABC):
    """Provides an abstraction used for personal data encryption."""

    @abstractmethod
    def protect(self, data: Any) -> str:
        """
        Protect the data.

        :param data: The data to protect.
        :return: The protected data.
        """

    @abstractmethod
    def unprotect(self, data: str) -> Any:
        """
        Unprotect the data.

        :param data: The data to unprotect.
        :return: The unprotected data.
        """


class ILookupProtector(ABC):
    """Used to protect/unprotect lookups with a specific key."""

    @abstractmethod
    def protect(self, key: str, data: Any) -> str:
        """
        Protect the data using the specified key.

        :param key: The key to use.
        :param data: The data to protect.
        :return: The protected data.
        """

    @abstractmethod
    def unprotect(self, key: str, data: str) -> Any:
        """
        Unprotect the data using the specified key.

        :param key: The key to use.
        :param data: The data to unprotect.
        :return: The unprotected data.
        """
