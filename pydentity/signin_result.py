from typing import Any


class SignInResult:
    __slots__ = (
        "_succeeded",
        "_is_locked_out",
        "_is_not_allowed",
        "_requires_two_factor",
        "_response",
    )

    def __init__(
        self,
        succeeded: bool = False,
        is_locked_out: bool = False,
        is_not_allowed: bool = False,
        requires_two_factor: bool = False,
        response: Any | None = None,
    ):
        self._succeeded = succeeded
        self._is_locked_out = is_locked_out
        self._is_not_allowed = is_not_allowed
        self._requires_two_factor = requires_two_factor
        self._response = response

    @property
    def is_locked_out(self) -> bool:
        return self._is_locked_out

    @property
    def succeeded(self) -> bool:
        return self._succeeded

    @property
    def is_not_allowed(self) -> bool:
        return self._is_not_allowed

    @property
    def requires_two_factor(self) -> bool:
        return self._requires_two_factor

    @property
    def response(self) -> Any | None:
        return self._response

    @staticmethod
    def success(response: Any) -> "SignInResult":
        return SignInResult(succeeded=True, response=response)

    @staticmethod
    def locked_out(response: Any | None = None) -> "SignInResult":
        return SignInResult(is_locked_out=True, response=response)

    @staticmethod
    def not_allowed(response: Any | None = None) -> "SignInResult":
        return SignInResult(is_not_allowed=True, response=response)

    @staticmethod
    def two_factor_required(response: Any) -> "SignInResult":
        return SignInResult(requires_two_factor=True, response=response)

    @staticmethod
    def failed(response: Any | None = None) -> "SignInResult":
        return SignInResult(response=response)

    def __str__(self) -> str:
        if self._is_locked_out:
            return "Locked out"
        if self.is_not_allowed:
            return "Not Allowed"
        if self.requires_two_factor:
            return "Requires Two-Factor"
        if self._succeeded:
            return "Succeeded"
        return "Failed"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.__str__()} object at {hex(id(self))}>"
