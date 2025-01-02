from datetime import timedelta
from typing import TYPE_CHECKING, Generic

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from pydentity.interfaces.logger import ILogger
from pydentity.interfaces.token_provider import IUserTwoFactorTokenProvider
from pydentity.loggers import data_protector_token_provider_logger
from pydentity.types import TUser

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ("DataProtectorTokenProvider",)


class DataProtectorTokenProvider(IUserTwoFactorTokenProvider[TUser], Generic[TUser]):
    __slots__ = (
        "_serializer",
        "_token_lifespan",
        "_logger",
    )

    def __init__(
        self,
        purpose: str | None = None,
        token_lifespan: int | timedelta = 600,
        logger: ILogger["DataProtectorTokenProvider[TUser]"] | None = None,
    ) -> None:
        """

        :param purpose:
        :param token_lifespan: The amount of time a generated token remains valid. Default to 600 seconds.
        :param logger:
        """
        self._serializer = URLSafeTimedSerializer(purpose or "DataProtectorTokenProvider")

        self._token_lifespan = token_lifespan
        if isinstance(token_lifespan, timedelta):
            self._token_lifespan = int(token_lifespan.total_seconds())

        self._logger = logger or data_protector_token_provider_logger

    async def generate(self, manager: "UserManager[TUser]", purpose: str, user: TUser) -> str:
        user_id = await manager.get_user_id(user)
        stamp = None

        if manager.supports_user_security_stamp:
            stamp = await manager.get_security_stamp(user)

        return self._serializer.dumps({"user_id": user_id, "purpose": purpose or "", "stamp": stamp or ""})

    async def can_generate_two_factor(self, manager: "UserManager[TUser]", user: TUser) -> bool:
        return False

    async def validate(self, manager: "UserManager[TUser]", purpose: str, token: str, user: TUser) -> bool:
        try:
            assert isinstance(self._token_lifespan, int)
            data = self._serializer.loads(token, max_age=self._token_lifespan)
        except BadSignature:
            self._logger.error("Bad signature.")
            return False
        except SignatureExpired:
            self._logger.error("Invalid expiration time.")
            return False
        else:
            try:
                if data["user_id"] != await manager.get_user_id(user):
                    self._logger.error("User ID not equals.")
                    return False

                if data["purpose"] != purpose:
                    self._logger.error("Purpose not equals.")
                    return False

                if manager.supports_user_security_stamp:
                    is_equals_security_stamp = data["stamp"] == await manager.get_security_stamp(user)

                    if not is_equals_security_stamp:
                        self._logger.error("Security stamp not equals.")

                    return is_equals_security_stamp  # type:ignore[no-any-return]

                stamp_is_empty = not bool(data["stamp"])

                if not stamp_is_empty:
                    self._logger.error("Security stamp is not empty.")

                return stamp_is_empty

            except KeyError as ex:
                self._logger.error(str(ex))
                return False
