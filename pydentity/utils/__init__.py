from datetime import datetime as _datetime, timedelta, UTC

__all__ = (
    "datetime",
    "is_none_or_space",
)


class datetime(_datetime):
    @classmethod
    def utcnow(cls) -> "datetime":
        return datetime.now(UTC)

    def add(self, __td: timedelta, /) -> "datetime":
        return self.__add__(__td)

    def add_days(self, days: float, /) -> "datetime":
        return self.add(timedelta(days=days))

    def add_seconds(self, seconds: float, /) -> "datetime":
        return self.add(timedelta(seconds=seconds))

    def add_microseconds(self, microseconds: float, /) -> "datetime":
        return self.add(timedelta(microseconds=microseconds))

    def add_milliseconds(self, milliseconds: float, /) -> "datetime":
        return self.add(timedelta(milliseconds=milliseconds))

    def add_minutes(self, minutes: float, /) -> "datetime":
        return self.add(timedelta(minutes=minutes))

    def add_hours(self, hours: float, /) -> "datetime":
        return self.add(timedelta(hours=hours))

    def add_weeks(self, weeks: float, /) -> "datetime":
        return self.add(timedelta(weeks=weeks))


def is_none_or_space(value: str | None, /) -> bool:
    """
    Indicates whether a specified string is `None`, `empty`, or consists only of `white-space` characters.

    :param value: The string to test.
    :return: ``True`` if the value parameter is `None` or `empty`, or if value consists exclusively of `white-space` characters.
    """
    return bool(not value or value.isspace())
