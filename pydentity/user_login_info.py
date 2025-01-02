class UserLoginInfo:
    """Represents login information and source for a user record."""

    __slots__ = (
        "_login_provider",
        "_provider_key",
        "_display_name",
    )

    def __init__(self, login_provider: str, provider_key: str, display_name: str | None = None) -> None:
        self._login_provider = login_provider
        self._provider_key = provider_key
        self._display_name = display_name

    @property
    def login_provider(self) -> str:
        """Gets the provider for this instance of *UserLoginInfo*."""
        return self._login_provider

    @property
    def provider_key(self) -> str:
        """Gets the unique identifier for the user identity user provided by the login provider."""
        return self._provider_key

    @property
    def provider_display_name(self) -> str | None:
        """Gets the display name for the provider."""
        return self._display_name

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.login_provider}:{self.provider_key} object at {hex(id(self))}>"
