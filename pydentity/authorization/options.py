from inspect import isfunction
from typing import overload, Callable

from pydentity._meta import SingletonMeta
from pydentity.authorization.policy import AuthorizationPolicy
from pydentity.authorization.policy_builder import AuthorizationPolicyBuilder
from pydentity.exc import ArgumentNullException, InvalidOperationException
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthorizationOptions",)


class AuthorizationOptions(metaclass=SingletonMeta):
    """Provides programmatic configuration used by *IAuthorizationService* and *IAuthorizationPolicyProvider*."""

    __slots__ = (
        "__policy_map",
        "default_policy",
    )

    def __init__(self) -> None:
        self.__policy_map: dict[str, AuthorizationPolicy] = {}
        self.default_policy = AuthorizationPolicyBuilder("default_policy").require_authenticated_user().build()
        """Gets or sets the default authorization policy. Defaults to require authenticated users."""

    @property
    def policy_map(self) -> dict[str, AuthorizationPolicy]:
        """Maps polices by name."""
        return self.__policy_map

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy, /) -> None:
        """
        Add an authorization policy with the provided name.

        :param name: The name of the policy.
        :param policy: The authorization policy.
        :return:
        """

    @overload
    def add_policy(self, name: str, configure_policy: Callable[[AuthorizationPolicyBuilder], None], /) -> None:
        """
        Add a policy that is built from a delegate with the provided name.

        :param name: The name of the policy.
        :param configure_policy: The delegate that will be used to build the policy.
        :return:
        """

    def add_policy(
        self,
        name: str,
        policy_or_builder: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None],
    ) -> None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        if policy_or_builder is None:
            raise ArgumentNullException("policy_or_builder")

        if name in self.__policy_map:
            raise InvalidOperationException(f"Policy already exists: {name}.")

        if isinstance(policy_or_builder, AuthorizationPolicy):
            self.__policy_map[name] = policy_or_builder
        elif isfunction(policy_or_builder):
            builder = AuthorizationPolicyBuilder(name)
            policy_or_builder(builder)
            self.__policy_map[name] = builder.build()
        else:
            raise NotImplementedError
