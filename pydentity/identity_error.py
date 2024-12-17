class IdentityError:
    """Encapsulates an error from the identity subsystem."""

    __slots__ = (
        "_code",
        "_description",
    )

    def __init__(self, code: str, description: str) -> None:
        """

        :param code: The code for this error.
        :param description: The description for this error.
        """
        self._code = code
        self._description = description

    @property
    def code(self) -> str:
        """Gets the code for this error."""
        return self._code

    @property
    def description(self) -> str:
        """Gets the description for this error."""
        return self._description

    def __str__(self) -> str:
        return f"{self.code}: {self.description}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.code} object at {hex(id(self))}>"
