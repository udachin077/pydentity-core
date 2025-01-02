from collections.abc import Iterable
from typing import Any

from pydentity.authorization.context import AuthorizationHandlerContext
from pydentity.authorization.exc import AuthorizationError
from pydentity.authorization.interfaces import IAuthorizationPolicyProvider
from pydentity.authorization.provider import AuthorizationPolicyProvider
from pydentity.exc import InvalidOperationException

__all__ = ("Authorize",)


def ensure_set(roles: Iterable[str] | str | None) -> set[str]:
    if roles is None:
        return set()
    if isinstance(roles, str):
        roles = roles.replace(" ", "").split(",")
    return set(roles)


class Authorize:
    def __init__(self, roles: Iterable[str] | str | None = None, policy: str | None = None) -> None:
        """
        Indicates that the route or router to which this dependency is applied requires the specified authorization.

        :param roles: A list of roles that are allowed to access the resource.
        :param policy: Policy name that determines access to the resource.
        :return:
        :raise InvalidOperationException: If the specified policy name is not found.
        :raise AuthorizationError: If authorization failed.
        """
        self.policy = policy
        self.roles = ensure_set(roles)

    async def _check_roles(self, context: AuthorizationHandlerContext) -> None:
        if context.user is None or (self.roles and not any([context.user.is_in_role(r) for r in self.roles])):
            raise AuthorizationError()

    async def _check_policy(
        self,
        context: AuthorizationHandlerContext,
        provider: IAuthorizationPolicyProvider,
    ) -> None:
        if default_policy := provider.get_default_policy():
            for req in default_policy.requirements:
                await req.handle(context)

        if self.policy:
            policy = provider.get_policy(self.policy)

            if policy is None:
                raise InvalidOperationException(f"The AuthorizationPolicy named: '{self.policy}' was not found.")

            for req in policy.requirements:
                await req.handle(context)

        if not context.has_succeeded:
            raise AuthorizationError()

    async def __call__(self, request: Any) -> None:
        context = AuthorizationHandlerContext(request)
        provider = AuthorizationPolicyProvider()
        await self._check_policy(context, provider)
        await self._check_roles(context)
