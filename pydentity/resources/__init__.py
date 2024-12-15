from pydentity.resources._error_messages import _ERROR_MESSAGES


# noinspection PyPep8Naming
class _ModuleResources:
    def __getitem__(self, item: str) -> str:
        return _ERROR_MESSAGES[item]

    def __getattr__(self, item: str) -> str:
        return _ERROR_MESSAGES[item]

    @staticmethod
    def FormatNoTokenProvider(token_provider: str) -> str:
        return _ERROR_MESSAGES["NoTokenProvider"].format(token_provider)


Resources = _ModuleResources()
