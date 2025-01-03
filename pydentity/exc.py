class ArgumentNullException(ValueError):
    def __init__(self, argument_name: str):
        super().__init__("Value '%s' cannot be None." % argument_name)


class InvalidOperationException(Exception):
    pass


class NotSupportedException(Exception):
    pass


class PersonalDataError(Exception):
    pass
