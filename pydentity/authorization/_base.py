from collections.abc import Iterable, Callable, Awaitable
from functools import lru_cache
from inspect import isfunction
from typing import Literal, Any, overload

from pydentity.authorization.interfaces import (
    IAuthorizationPolicyProvider,
    IAuthorizationHandler,
    IAuthorizationOptionsAccessor,
)
from pydentity.exc import ArgumentNoneException, InvalidOperationException
from pydentity.security.claims import ClaimsPrincipal, Claim
from pydentity.types import TRequest

__all__ = (
    "AuthorizationError",
    "AuthorizationHandlerContext",
    "AuthorizationOptions",
    "AuthorizationPolicy",
    "AuthorizationPolicyBuilder",
    "AuthorizationPolicyProvider",
)

_HandlerType = Callable[["AuthorizationHandlerContext"], Awaitable[bool]]


class AuthorizationError(Exception):
    pass


class AuthorizationHandlerContext:
    __slots__ = (
        "_request",
        "_fail_called",
        "_succeeded_called",
    )

    def __init__(self, request: TRequest) -> None:
        self._request = request
        self._fail_called = False
        self._succeeded_called = False

    @property
    def user(self) -> ClaimsPrincipal | None:
        """The ClaimsPrincipal representing the current user."""
        return self._request.user  # type: ignore

    @property
    def has_succeeded(self) -> bool:
        """Flag indicating whether the current authorization processing has succeeded."""
        return not self._fail_called and self._succeeded_called

    def fail(self) -> None:
        """
        Called to indicate ``AuthorizationHandlerContext.has_succeeded`` will
        never return true, even if all requirements are met.
        """
        self._fail_called = True

    def succeed(self) -> None:
        """Called to mark the specified requirement as being successfully evaluated."""
        self._succeeded_called = True


class AuthorizationPolicy:
    """Represents a collection of authorization requirements evaluated against, all of which must succeed for authorization to succeed."""

    __slots__ = (
        "_name",
        "_requirements",
    )

    def __init__(self, name: str, requirements: Iterable[IAuthorizationHandler]) -> None:
        """

        :param name: Policy name.
        :param requirements: The iterable of ``IAuthorizationRequirement`` which must succeed for this policy to be successful.
        """
        self._name = name
        self._requirements: tuple[IAuthorizationHandler, ...] = tuple(requirements or [])

    @property
    def name(self) -> str:
        """Gets policy name."""
        return self._name

    @property
    def requirements(self) -> tuple[IAuthorizationHandler, ...]:
        """Gets a tuple of ``IAuthorizationHandlers`` which must succeed for this policy to be successful."""
        return self._requirements


class RolesAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an ``IAuthorizationHandler`` and `IAuthorizationRequirement``
    which requires at least one role claim whose value must be any of the allowed roles.
    """

    __slots__ = (
        "_allowed_roles",
        "_mode",
    )

    def __init__(self, *allowed_roles: str, mode: Literal["all", "any"] = "any") -> None:
        """

        :param allowed_roles: A collection of allowed roles.
        :param mode: Role comparison mode.
        If ``any`` is selected, at least one role statement is required, the value of which must be any of the allowed roles.
        If ``all`` is specified, then approvals are required for each of the allowed roles.
        """
        if not allowed_roles:
            raise ArgumentNoneException("allowed_roles")

        self._allowed_roles = allowed_roles
        self._mode = mode

    @property
    def allowed_roles(self) -> tuple[str, ...]:
        """Gets the collection of allowed roles."""
        return self._allowed_roles

    @property
    def mode(self) -> Literal["all", "any"]:
        return self._mode

    async def handle(self, context: "AuthorizationHandlerContext") -> None:
        """
        Makes a decision if authorization is allowed based on a specific requirement.

        :param context: The authorization context.
        :return:
        """
        if context.user:
            if context.user.is_in_roles(*self.allowed_roles, mode=self.mode):
                context.succeed()


class ClaimsAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an ``IAuthorizationHandler`` and ``IAuthorizationRequirement``
    which requires at least one instance of the specified claim type, and, if allowed values are specified,
    the claim value must be any of the allowed values.
    """

    __slots__ = (
        "_claim_type",
        "_allowed_values",
    )

    def __init__(self, claim_type: str, *allowed_values: Any) -> None:
        """

        :param claim_type: The claim type that must be present.
        :param allowed_values: Optional list of claim values. If specified, the claim must match one or more of these values.
        """
        if not claim_type:
            raise ArgumentNoneException("claim_type")

        self._claim_type = claim_type
        self._allowed_values = allowed_values

    @property
    def claim_type(self) -> str:
        """Gets the claim type that must be present."""
        return self._claim_type

    @property
    def allowed_values(self) -> tuple[Any, ...]:
        """Gets the optional list of claim values, which, if present, the claim must match."""
        return self._allowed_values

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Makes a decision if authorization is allowed based on the claims requirements specified.

        :param context: The authorization context.
        :return:
        """
        if context.user:
            predicate: Callable[[Claim], bool] = (
                self.__check_claim_with_value if self.allowed_values else self.__check_claim
            )

            for claim in context.user.claims:
                if predicate(claim):
                    context.succeed()
                    return

    def __check_claim(self, claim: Claim) -> bool:
        return claim.type.casefold() == self.claim_type.casefold()

    def __check_claim_with_value(self, claim: Claim) -> bool:
        return self.__check_claim(claim) and claim.value in self.allowed_values


class NameAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an ``IAuthorizationHandler`` and ``IAuthorizationRequirement``
    which requires the current username must match the specified value.
    """

    __slots__ = ("_required_name",)

    def __init__(self, required_name: str) -> None:
        """

        :param required_name: The required name that the current user must have.
        """
        if not required_name:
            raise ArgumentNoneException("required_name")

        self._required_name = required_name

    @property
    def required_name(self) -> str:
        """Gets the required name that the current user must have."""
        return self._required_name

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Makes a decision if authorization is allowed based on a specific requirement.

        :param context: The authorization context.
        :return:
        """
        if context.user and context.user.identity and self.required_name == context.user.identity.name:
            context.succeed()


class AssertionRequirement(IAuthorizationHandler):
    """
    Implements an ``IAuthorizationHandler`` and ``IAuthorizationRequirement``
    that takes a user specified assertion.
    """

    __slots__ = ("_handler",)

    def __init__(self, handler: _HandlerType) -> None:
        if handler is None:
            raise ArgumentNoneException("handler")

        self._handler = handler

    @property
    def handler(self) -> _HandlerType:
        """Function that is called to handle this requirement."""
        return self._handler

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Calls ``AssertionRequirement.handler`` to see if authorization is allowed.

        :param context: The authorization information.
        :return:
        """
        if await self.handler(context):
            context.succeed()


class DenyAnonymousAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an <see ``IAuthorizationHandler`` and ``IAuthorizationRequirement``
    which requires the current user must be authenticated.
    """

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Makes a decision if authorization is allowed based on a specific requirement.

        :param context: The authorization context.
        :return:
        """
        if context.user and context.user.identity and context.user.identity.is_authenticated:
            context.succeed()


class AuthorizationPolicyBuilder:
    __slots__ = (
        "name",
        "_requirements",
    )

    def __init__(self, name: str) -> None:
        self.name = name
        self._requirements: list[IAuthorizationHandler] = []

    def add_requirements(self, *requirements: IAuthorizationHandler) -> "AuthorizationPolicyBuilder":
        """
        Adds the specified requirements to the for this instance.

        :param requirements: The authorization requirements to add.
        :return:
        """
        if not requirements:
            raise ArgumentNoneException("requirements")

        self._requirements.extend(requirements)
        return self

    def require_claim(self, claim_type: str, *allowed_values: Any) -> "AuthorizationPolicyBuilder":
        """
        Adds ``ClaimsAuthorizationRequirement`` to the current instance which requires that the current user
        has the specified claim and that the claim value must be one of the allowed values.

        :param claim_type: The claim type required.
        :param allowed_values: Optional list of claim values.
        If specified, the claim must match one or more of these values.
        :return:
        """
        self._requirements.append(ClaimsAuthorizationRequirement(claim_type, *allowed_values))
        return self

    def require_role(self, *roles: str) -> "AuthorizationPolicyBuilder":
        """
        Adds a ``RolesAuthorizationRequirement`` to the current instance which enforces that the current user
        must have at least one of the specified roles.

        :param roles: The allowed roles.
        :return:
        """
        self._requirements.append(RolesAuthorizationRequirement(*roles, mode="any"))
        return self

    def require_roles(self, *roles: str) -> "AuthorizationPolicyBuilder":
        """
        Adds a ``RolesAuthorizationRequirement`` to the current instance which enforces that the current user
        must have at all the specified roles.

        :param roles: The allowed roles.
        :return:
        """
        self._requirements.append(RolesAuthorizationRequirement(*roles, mode="all"))
        return self

    def require_username(self, name: str) -> "AuthorizationPolicyBuilder":
        """
        Adds a ``NameAuthorizationRequirement`` to the current instance which enforces that the current user
        matches the specified name.

        :param name: The username the current user must have.
        :return:
        """
        self._requirements.append(NameAuthorizationRequirement(name))
        return self

    def require_assertion(self, handler: _HandlerType) -> "AuthorizationPolicyBuilder":
        """
        Adds an ``AssertionRequirement`` to the current instance.

        :param handler: The handler to evaluate during authorization.
        :return:
        """
        self._requirements.append(AssertionRequirement(handler))
        return self

    def require_authenticated_user(self) -> "AuthorizationPolicyBuilder":
        """
        Adds ``DenyAnonymousAuthorizationRequirement`` to the current instance which enforces that the current user
        is authenticated.

        :return:
        """
        self._requirements.append(DenyAnonymousAuthorizationRequirement())
        return self

    def build(self) -> AuthorizationPolicy:
        """
        Builds a new ``AuthorizationPolicy`` from the requirements in this instance.

        :return:
        """
        return AuthorizationPolicy(self.name, self._requirements)


class AuthorizationOptions:
    """Provides programmatic configuration used by ``IAuthorizationService`` and ``IAuthorizationPolicyProvider``."""

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
        if not name:
            raise ArgumentNoneException("name")
        if not policy_or_builder:
            raise ArgumentNoneException("policy_or_builder")
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

    @lru_cache
    def get_policy(self, name: str) -> AuthorizationPolicy | None:
        """
        Returns the policy for the specified name, or null if a policy with the name does not exist.

        :param name: The name of the policy to return.
        :return:
        """
        if not name:
            raise ArgumentNoneException("name")
        return self.__policy_map.get(name)


class AuthorizationPolicyProvider(IAuthorizationPolicyProvider):
    """
    The default implementation of a policy provider, which provides a ``AuthorizationPolicy`` for a particular name.
    """

    __slots__ = ("_options",)

    def __init__(self, options: IAuthorizationOptionsAccessor):
        self._options = options.value

    @lru_cache
    async def get_policy(self, name: str) -> AuthorizationPolicy | None:
        """
        Gets a ``AuthorizationPolicy`` from the given name.

        :param name: The policy name to retrieve.
        :return:
        """
        return self._options.get_policy(name)

    @lru_cache
    async def get_default_policy(self) -> AuthorizationPolicy | None:
        """Gets the default authorization policy."""
        return self._options.default_policy
