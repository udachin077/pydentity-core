from functools import cache

from pydentity.authorization.interfaces import IAuthorizationPolicyProvider
from pydentity.authorization.options import AuthorizationOptions
from pydentity.authorization.policy import AuthorizationPolicy
from pydentity.exc import ArgumentNullException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthorizationPolicyProvider",)


class AuthorizationPolicyProvider(IAuthorizationPolicyProvider):
    """
    The default implementation of a policy provider, which provides a *AuthorizationPolicy* for a particular name.
    """

    __slots__ = ("_options",)

    def __init__(self) -> None:
        self._options = AuthorizationOptions()

    @cache
    def get_policy(self, name: str) -> AuthorizationPolicy | None:
        """
        Gets a *AuthorizationPolicy* from the given name.

        :param name: The policy name to retrieve.
        :return:
        """
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        return self._options.policy_map.get(name)

    @cache
    def get_default_policy(self) -> AuthorizationPolicy | None:
        """Gets the default authorization policy."""
        return self._options.default_policy
