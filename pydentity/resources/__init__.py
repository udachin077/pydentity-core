import importlib
import inspect
from typing import Sequence, Any

from typing_extensions import deprecated

from pydentity._meta import SingletonMeta
from pydentity.resources._error_messages import _ERROR_MESSAGES

__all__ = (
    "Resources",
    "initialize_resources",
)


class ErrorsModule:
    def __getitem__(self, item: str) -> str:
        return _ERROR_MESSAGES[item]

    def __getattr__(self, item: str) -> str:
        return _ERROR_MESSAGES[item]

    @staticmethod
    def FormatNoTokenProvider(token_provider: str) -> str:
        return _ERROR_MESSAGES["NoTokenProvider"].format(token_provider)


def _predicate(obj: Any) -> bool:
    return inspect.isclass(obj) and obj.__name__.endswith("Module")


def _get_module_classes(module: str) -> list[tuple[str, type]]:
    m = importlib.import_module(module)
    return inspect.getmembers(m, _predicate)


def _attr_name(name: str) -> str:
    return name.removesuffix("Module").lower()


class Resources:
    @deprecated
    def __class_getitem__(cls, item):
        return _ERROR_MESSAGES[item]

    def __getattr__(self, item: str) -> str:
        return _ERROR_MESSAGES[item]


class ResourceManager(metaclass=SingletonMeta):
    @classmethod
    def load_modules(cls, *, modules: Sequence[str] | None = ()) -> None:
        resource_modules = []

        for m in (_get_module_classes(module) for module in modules):
            resource_modules.extend(m)

        resource_modules.sort()

        for m_name, m_type in resource_modules:
            setattr(Resources, _attr_name(m_name), m_type())


def initialize_resources(*, modules: Sequence[str] | None = ()):
    ResourceManager.load_modules(modules=[__name__, *modules])


# deprecated
initialize_resources()
