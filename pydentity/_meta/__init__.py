from typing import Any, ParamSpec

P = ParamSpec("P")


class SingletonMeta(type):
    _instances = {}  # type:ignore[var-annotated]

    def __call__(cls, *args: P.args, **kwargs: P.kwargs) -> Any:
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
