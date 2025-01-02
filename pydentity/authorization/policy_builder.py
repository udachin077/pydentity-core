from typing import Callable, Awaitable, Literal, Any, Self

from pydentity.authorization.context import AuthorizationHandlerContext
from pydentity.authorization.interfaces import IAuthorizationHandler
from pydentity.authorization.policy import AuthorizationPolicy
from pydentity.exc import ArgumentNullException
from pydentity.security.claims import Claim
from pydentity.utils import is_null_or_whitespace

__all__ = ("AuthorizationPolicyBuilder",)

_HandlerType = Callable[["AuthorizationHandlerContext"], Awaitable[bool]]


class RolesAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an *IAuthorizationHandler* and `IAuthorizationRequirement*
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
        If *any* is selected, at least one role statement is required, the value of which must be any of the allowed roles.
        If *all* is specified, then approvals are required for each of the allowed roles.
        """
        if not allowed_roles:
            raise ArgumentNullException("allowed_roles")

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
    Implements an *IAuthorizationHandler* and *IAuthorizationRequirement*
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
        if is_null_or_whitespace(claim_type):
            raise ArgumentNullException("claim_type")

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
    Implements an *IAuthorizationHandler* and *IAuthorizationRequirement*
    which requires the current username must match the specified value.
    """

    __slots__ = ("_required_name",)

    def __init__(self, required_name: str) -> None:
        """

        :param required_name: The required name that the current user must have.
        """
        if is_null_or_whitespace(required_name):
            raise ArgumentNullException("required_name")

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
    Implements an *IAuthorizationHandler* and *IAuthorizationRequirement*
    that takes a user specified assertion.
    """

    __slots__ = ("_handler",)

    def __init__(self, handler: _HandlerType) -> None:
        if handler is None:
            raise ArgumentNullException("handler")

        self._handler = handler

    @property
    def handler(self) -> _HandlerType:
        """Function that is called to handle this requirement."""
        return self._handler

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Calls *AssertionRequirement.handler* to see if authorization is allowed.

        :param context: The authorization information.
        :return:
        """
        if await self.handler(context):
            context.succeed()


class DenyAnonymousAuthorizationRequirement(IAuthorizationHandler):
    """
    Implements an <see *IAuthorizationHandler* and *IAuthorizationRequirement*
    which requires the current user must be authenticated.
    """

    async def handle(self, context: AuthorizationHandlerContext) -> None:
        """
        Makes a decision if authorization is allowed based on a specific requirement.

        :param context: The authorization context.
        :return:
        """
        if context.user is not None and context.user.identity is not None and context.user.identity.is_authenticated:
            context.succeed()


class AuthorizationPolicyBuilder:
    __slots__ = (
        "_name",
        "_requirements",
    )

    def __init__(self, name: str) -> None:
        if is_null_or_whitespace(name):
            raise ArgumentNullException("name")

        self._name = name
        self._requirements: list[IAuthorizationHandler] = []

    @property
    def name(self) -> str:
        """Gets the name of the policy being built."""
        return self._name

    def add_requirements(self, *requirements: IAuthorizationHandler) -> Self:
        """
        Adds the specified requirements to the for this instance.

        :param requirements: The authorization requirements to add.
        :return:
        """
        if not requirements:
            raise ArgumentNullException("requirements")

        self._requirements.extend(requirements)
        return self

    def require_claim(self, claim_type: str, *allowed_values: Any) -> Self:
        """
        Adds *ClaimsAuthorizationRequirement* to the current instance which requires that the current user
        has the specified claim and that the claim value must be one of the allowed values.

        :param claim_type: The claim type required.
        :param allowed_values: Optional list of claim values.
        If specified, the claim must match one or more of these values.
        :return:
        """
        self._requirements.append(ClaimsAuthorizationRequirement(claim_type, *allowed_values))
        return self

    def require_role(self, *roles: str) -> Self:
        """
        Adds a *RolesAuthorizationRequirement* to the current instance which enforces that the current user
        must have at least one of the specified roles.

        :param roles: The allowed roles.
        :return:
        """
        self._requirements.append(RolesAuthorizationRequirement(*roles, mode="any"))
        return self

    def require_roles(self, *roles: str) -> Self:
        """
        Adds a *RolesAuthorizationRequirement* to the current instance which enforces that the current user
        must have at all the specified roles.

        :param roles: The allowed roles.
        :return:
        """
        self._requirements.append(RolesAuthorizationRequirement(*roles, mode="all"))
        return self

    def require_username(self, name: str) -> Self:
        """
        Adds a *NameAuthorizationRequirement* to the current instance which enforces that the current user
        matches the specified name.

        :param name: The username the current user must have.
        :return:
        """
        self._requirements.append(NameAuthorizationRequirement(name))
        return self

    def require_assertion(self, handler: _HandlerType) -> Self:
        """
        Adds an *AssertionRequirement* to the current instance.

        :param handler: The handler to evaluate during authorization.
        :return:
        """
        self._requirements.append(AssertionRequirement(handler))
        return self

    def require_authenticated_user(self) -> Self:
        """
        Adds *DenyAnonymousAuthorizationRequirement* to the current instance which enforces that the current user
        is authenticated.

        :return:
        """
        self._requirements.append(DenyAnonymousAuthorizationRequirement())
        return self

    def build(self) -> AuthorizationPolicy:
        """
        Builds a new *AuthorizationPolicy* from the requirements in this instance.

        :return:
        """
        return AuthorizationPolicy(self._name, self._requirements)
