from datetime import timedelta, datetime
from typing import Literal

__all__ = ("CookieAuthenticationOptions",)


def ensure_timedelta(td: timedelta | float | None) -> timedelta | None:
    return timedelta(seconds=td) if isinstance(td, (int, float)) else td


def convert_to_seconds(dt: datetime) -> int:
    return int(dt.timestamp())


class CookieAuthenticationOptions:
    __slots__ = (
        "name",
        "_max_age_timedelta",
        "_expires_timedelta",
        "path",
        "domain",
        "httponly",
        "secure",
        "samesite",
        "use_max_age",
    )

    def __init__(
        self,
        name: str | None = None,
        max_age_timedelta: timedelta | int | None = 604800,
        expires_timedelta: timedelta | int | None = None,
        path: str = "/",
        domain: str | None = None,
        httponly: bool = True,
        secure: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ) -> None:
        """
        Cookie parameters that will be used by the *CookieAuthenticationHandler* to receive and set cookies.

        :param name: A string that will be the cookie's key.
        :param max_age_timedelta: An integer that defines the lifetime of the cookie in seconds.
            A negative integer or a value of 0 will discard the cookie immediately.
            The time interval that will be set when logging in using *SignInManager*
            if the `is_persistent` parameter is set to `True`. Defaults to 7 days.
        :param expires_timedelta: Timedelta, which defines the interval until the cookie expires.
        :param path: A string that specifies the subset of routes to which the cookie will apply.
        :param domain: A string that specifies the domain for which the cookie is valid.
        :param httponly: A bool indicating that the cookie cannot be accessed
            via JavaScript through *Document.cookie* property, the *XMLHttpRequest* or Request APIs.
        :param secure: A bool indicating that the cookie will only be sent to the server
            if request is made using SSL and the HTTPS protocol.
        :param samesite: A string that specifies the samesite strategy for the cookie.
            Valid values are 'lax', 'strict' and 'none'. Defaults to 'lax'.
        """
        self._max_age_timedelta = ensure_timedelta(max_age_timedelta)
        self._expires_timedelta = ensure_timedelta(expires_timedelta)
        self.name = name
        self.path = path
        self.domain = domain
        self.httponly = httponly
        self.secure = secure
        self.samesite = samesite
        self.use_max_age: bool = False

    @property
    def max_age_timedelta(self) -> timedelta | None:
        return self._max_age_timedelta

    @max_age_timedelta.setter
    def max_age_timedelta(self, value: timedelta | float) -> None:
        self._max_age_timedelta = ensure_timedelta(value)

    @property
    def expires_timedelta(self) -> timedelta | None:
        return self._expires_timedelta

    @expires_timedelta.setter
    def expires_timedelta(self, value: timedelta | float) -> None:
        self._expires_timedelta = ensure_timedelta(value)

    @property
    def expires(self) -> int | None:
        delta = self._max_age_timedelta if self.use_max_age else self._expires_timedelta
        return convert_to_seconds(datetime.now() + delta) if delta is not None else None
