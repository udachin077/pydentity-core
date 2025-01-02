from typing import Final


class IdentityConstants:
    __CookiePrefix: Final[str] = "Pydentity"
    ApplicationScheme: Final[str] = __CookiePrefix + ".Application"
    ExternalScheme: Final[str] = __CookiePrefix + ".External"
    TwoFactorRememberMeScheme: Final[str] = __CookiePrefix + ".TwoFactorRememberMe"
    TwoFactorUserIdScheme: Final[str] = __CookiePrefix + ".TwoFactorUserId"
