from typing import overload, Callable, Self

from pydentity.authorization.options import AuthorizationOptions
from pydentity.authorization.policy import AuthorizationPolicy
from pydentity.authorization.policy_builder import AuthorizationPolicyBuilder

__all__ = ("AuthorizationBuilder",)


class AuthorizationBuilder:
    """Used to configure authorization."""

    __slots__ = ("__options",)

    def __init__(self, default_policy: AuthorizationPolicy | None = None):
        self.__options = AuthorizationOptions()

        if default_policy:
            self.set_default_policy(default_policy)

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy, /) -> Self:
        """
        Adds a *AuthorizationPolicy*.

        :param name: The name of this policy.
        :param policy: The *AuthorizationPolicy*.
        :return:
        """

    @overload
    def add_policy(self, name: str, configure_policy: Callable[[AuthorizationPolicyBuilder], None], /) -> Self:
        """
        Add a policy that is built from a delegate with the provided name.

        :param name: The name of the policy.
        :param configure_policy: The delegate that will be used to build the policy.
        :return:
        """

    def add_policy(
        self, name: str, policy_or_builder: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> Self:
        self.__options.add_policy(name, policy_or_builder)
        return self

    def __iadd__(self, policy: AuthorizationPolicy) -> Self:
        return self.add_policy(policy.name, policy)

    def set_default_policy(self, policy: AuthorizationPolicy) -> Self:
        self.__options.default_policy = policy
        return self
