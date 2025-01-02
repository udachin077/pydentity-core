from abc import ABC, abstractmethod


class IDataProtector(ABC):
    """Provides an abstraction used for personal data encryption."""

    @abstractmethod
    def protect(self, data: str | bytes) -> str:
        """
        Protect the data.

        :param data: The data to protect.
        :return: The protected data.
        """

    @abstractmethod
    def unprotect(self, data: str | bytes) -> str:
        """
        Unprotect the data.

        :param data: The data to unprotect.
        :return: The unprotected data.
        """
