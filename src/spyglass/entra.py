"""Entra (directory-plane) identity collector.

Resolves a Service Principal strictly by object id via
`GET /servicePrincipals/{id}`, falling back to an `appId eq` filter only on a
404, and attaches its related Application as a nullable object. The pure
mapping functions (Graph model -> record) are network-free so they can be
unit-tested without a live Graph client.

The network-bound collectors live on `EntraCollector`, which owns the Graph
client plus the run-scoped single-flight caches and the concurrency bound. One
collector instance is one selection/run: its caches are shared across every SP
it processes (so a group's schedules or a resource SP's appRoles are fetched
once) and must not be reused across logically separate runs. The pure mapping
functions stay module-level — they hold no state and are unit-tested directly.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Literal

from kiota_abstractions.api_error import APIError
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.applications.applications_request_builder import (
    ApplicationsRequestBuilder,
)
from msgraph.generated.applications.item.owners.owners_request_builder import (
    OwnersRequestBuilder as ApplicationOwnersRequestBuilder,
)
from msgraph.generated.groups.item.group_item_request_builder import (
    GroupItemRequestBuilder,
)
from msgraph.generated.identity_governance.privileged_access.group.assignment_schedules.assignment_schedules_request_builder import (  # noqa: E501
    AssignmentSchedulesRequestBuilder,
)
from msgraph.generated.models.app_role_assignment import AppRoleAssignment
from msgraph.generated.models.application import Application
from msgraph.generated.models.directory_object import DirectoryObject
from msgraph.generated.models.group import Group
from msgraph.generated.models.o_auth2_permission_grant import OAuth2PermissionGrant
from msgraph.generated.models.privileged_access_group_assignment_schedule import (
    PrivilegedAccessGroupAssignmentSchedule,
)
from msgraph.generated.models.privileged_access_group_relationships import (
    PrivilegedAccessGroupRelationships,
)
from msgraph.generated.models.service_principal import ServicePrincipal
from msgraph.generated.models.unified_role_assignment_schedule import (
    UnifiedRoleAssignmentSchedule,
)
from msgraph.generated.models.user import User
from msgraph.generated.role_management.directory.role_assignment_schedules.role_assignment_schedules_request_builder import (  # noqa: E501
    RoleAssignmentSchedulesRequestBuilder,
)
from msgraph.generated.service_principals.item.member_of.member_of_request_builder import (  # noqa: E501
    MemberOfRequestBuilder,
)
from msgraph.generated.service_principals.item.owners.owners_request_builder import (
    OwnersRequestBuilder as ServicePrincipalOwnersRequestBuilder,
)
from msgraph.generated.service_principals.item.service_principal_item_request_builder import (  # noqa: E501
    ServicePrincipalItemRequestBuilder,
)
from msgraph.generated.service_principals.item.transitive_member_of.transitive_member_of_request_builder import (  # noqa: E501
    TransitiveMemberOfRequestBuilder,
)
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)

from .credentials import map_credentials
from .graph_errors import describe_graph_error
from .models import (
    ApplicationPermissionRecord,
    ApplicationRecord,
    DelegatedPermissionRecord,
    DirectoryRoleRecord,
    GroupMembershipRecord,
    OwnerRecord,
    ServicePrincipalRecord,
)
from .single_flight import SingleFlight

# The all-zero appRole GUID is Graph's "default access" marker, not a named role.
DEFAULT_ACCESS_APP_ROLE = "00000000-0000-0000-0000-000000000000"

# Conservative default fan-out across SPs; dialed down via --concurrency when a
# throttling-prone tenant starts returning 429s.
DEFAULT_CONCURRENCY = 5

# Resource SPs are fetched once per resourceId and reused across every SP and
# both permission planes; the cached value is the resource's display name plus
# its appRoleId -> value map.
type ResourceInfo = tuple[str | None, dict[str, str]]

# Unified $select so SP-side fields are never path-dependent across the
# selection routes (by object id, appId-eq fallback, and tag query). Every SP
# enters the per-SP fan-out with the same baseline, including the credential
# fields, so SP-side credentials are never path-dependent.
SP_SELECT = [
    "id",
    "displayName",
    "appId",
    "tags",
    "passwordCredentials",
    "keyCredentials",
]
APP_SELECT = [
    "id",
    "displayName",
    "appId",
    "passwordCredentials",
    "keyCredentials",
]
GROUP_SELECT = ["id", "displayName", "isAssignableToRole"]
RESOURCE_SELECT = ["id", "displayName", "appId", "appRoles"]
OWNER_SELECT = ["id", "displayName"]

# Service principals can only ever hold *active* directory-role assignments
# (eligible assignments require an interactive activation an SP cannot perform),
# so the collector reads only assignment schedules. `scheduleInfo` lives on the
# concrete subclass rather than `UnifiedRoleScheduleBase`, so this aliases the
# concrete type the readers expect.
type RoleSchedule = UnifiedRoleAssignmentSchedule


def application_record_from_graph(app: Application) -> ApplicationRecord:
    """Map a Graph Application onto the nullable attached Application record."""
    return {
        "objectId": app.id,
        "appId": app.app_id,
        "displayName": app.display_name,
    }


def sp_record_from_graph(
    sp: ServicePrincipal, application: Application | None
) -> ServicePrincipalRecord:
    """Map a Graph servicePrincipal (+ optional Application) onto a record.

    Pure: no network, no clock. `objectId` must be present on a resolved SP;
    everything else degrades to `None`/empty.
    """
    if sp.id is None:
        raise ValueError("Resolved service principal has no object id")
    return {
        "objectId": sp.id,
        "appId": sp.app_id,
        "displayName": sp.display_name,
        "tags": list(sp.tags) if sp.tags else [],
        "application": (
            application_record_from_graph(application)
            if application is not None
            else None
        ),
        # Azure RBAC plane is folded in by the CLI after the ARG batch query;
        # every record starts with an empty (directory-plane-only) list.
        "azureRoleAssignments": [],
        "groupMemberships": [],
        "directoryRoles": [],
        "credentials": [],
        "applicationPermissions": [],
        "delegatedPermissions": [],
        "owners": [],
        "errors": [],
    }


def group_membership_from_graph(
    group: Group, membership_type: Literal["direct", "transitive"]
) -> GroupMembershipRecord:
    """Map a Graph Group onto a membership record, labeling how it is held.

    Pure: no network. `membership_type` is supplied by the caller — `member_of`
    yields `direct`, `transitiveMemberOf` yields `transitive`. `pimMembership`
    starts unset (`None`); `apply_pim_membership` fills it in once the
    PIM-for-Groups schedules are collected.
    """
    return {
        "groupId": group.id,
        "displayName": group.display_name,
        "membershipType": membership_type,
        "isAssignableToRole": group.is_assignable_to_role,
        "pimMembership": None,
    }


# Only PIM-for-Groups *assignment* (active) schedules are read: an SP cannot
# activate an eligible membership, so eligibility schedules never apply to it.
type PimSchedule = PrivilegedAccessGroupAssignmentSchedule


def _member_group_ids(schedules: list[PimSchedule]) -> set[str]:
    """Group ids the SP holds with `accessId = member` (not `owner`).

    Role inheritance flows through *member* PIM-for-Groups access, never owner
    access, so owner schedules are dropped here.
    """
    return {
        schedule.group_id
        for schedule in schedules
        if schedule.group_id is not None
        and schedule.access_id == PrivilegedAccessGroupRelationships.Member
    }


def apply_pim_membership(
    memberships: list[GroupMembershipRecord],
    active_schedules: list[PrivilegedAccessGroupAssignmentSchedule],
) -> list[GroupMembershipRecord]:
    """Annotate each role-assignable membership with its PIM-for-Groups status.

    Pure: no network. `active_schedules` are PIM-for-Groups assignment schedules
    (standing membership → `assigned`); a role-assignable group not among them is
    `none`. Eligible (must-activate) membership is never considered: an SP cannot
    perform the interactive activation it requires, so it can only ever hold a
    standing membership. Only `member` access counts (see `_member_group_ids`).
    Non-role-assignable memberships are left at `None`, since PIM-for-Groups
    status is only meaningful for role-inheritance reasoning. Returns new records;
    inputs are not mutated.
    """
    active = _member_group_ids(list(active_schedules))
    annotated: list[GroupMembershipRecord] = []
    for membership in memberships:
        pim: Literal["assigned", "none"] | None = None
        if membership["isAssignableToRole"]:
            group_id = membership["groupId"]
            pim = "assigned" if group_id in active else "none"
        annotated.append({**membership, "pimMembership": pim})
    return annotated


def directory_role_from_schedule(
    schedule: RoleSchedule,
    source: str,
    source_group_id: str | None,
) -> DirectoryRoleRecord:
    """Map a Graph role assignment schedule onto a Directory Role record.

    Pure: no network, no clock. `assignmentType` is always `active`: only
    `roleAssignmentSchedules` are read, because an SP cannot hold an eligible
    assignment. `source`/`source_group_id` carry the Via-group attribution:
    `"direct"`/`None` for a role targeting the SP itself, or the group's display
    name/id for one reached through a role-assignable group. Raw facts only.
    """
    role_definition = schedule.role_definition
    role_name = role_definition.display_name if role_definition is not None else None
    schedule_info = schedule.schedule_info
    start = schedule_info.start_date_time if schedule_info is not None else None
    expiration = schedule_info.expiration if schedule_info is not None else None
    end = expiration.end_date_time if expiration is not None else None
    return {
        "roleName": role_name,
        "assignmentType": "active",
        "source": source,
        "sourceGroupId": source_group_id,
        "directoryScopeId": schedule.directory_scope_id,
        "startDateTime": start.isoformat() if start is not None else None,
        "endDateTime": end.isoformat() if end is not None else None,
    }


def app_role_value_map(resource: ServicePrincipal) -> dict[str, str]:
    """Build a resource SP's `appRoleId -> value` map for permission resolution.

    Pure: no network. Roles without an id or value are dropped — they cannot be
    matched against an assignment's `appRoleId` nor surfaced as a name.
    """
    return {
        str(role.id): role.value
        for role in resource.app_roles or []
        if role.id is not None and role.value is not None
    }


def resolve_app_role_value(app_role_id: Any, app_roles: dict[str, str]) -> str | None:
    """Resolve an `appRoleId` GUID to its human-readable value.

    Pure: no network. The all-zero GUID is Graph's "default access" marker, not a
    named role. An unknown GUID degrades to `None` rather than the raw GUID, which
    is retained separately on the record.
    """
    if app_role_id is None:
        return None
    role_id = str(app_role_id)
    if role_id == DEFAULT_ACCESS_APP_ROLE:
        return "default access"
    return app_roles.get(role_id)


def application_permission_from_graph(
    assignment: AppRoleAssignment,
    resource_display_name: str | None,
    permission: str | None,
) -> ApplicationPermissionRecord:
    """Map a Graph `appRoleAssignment` onto an application permission record.

    Pure: no network. The resource display name and resolved `permission` value
    are supplied by the caller, which threads them through the resourceId cache.
    """
    return {
        "resourceId": (
            str(assignment.resource_id) if assignment.resource_id is not None else None
        ),
        "resourceDisplayName": resource_display_name,
        "appRoleId": (
            str(assignment.app_role_id) if assignment.app_role_id is not None else None
        ),
        "permission": permission,
    }


def delegated_permission_from_graph(
    grant: OAuth2PermissionGrant, resource_display_name: str | None
) -> DelegatedPermissionRecord:
    """Map a Graph `oauth2PermissionGrant` onto a delegated permission record.

    Pure: no network. The space-delimited `scope` string is split into a list;
    `principalId` is meaningful only for the `Principal` consent type.
    """
    return {
        "resourceId": (
            str(grant.resource_id) if grant.resource_id is not None else None
        ),
        "resourceDisplayName": resource_display_name,
        "scopes": grant.scope.split() if grant.scope else [],
        "consentType": grant.consent_type,
        "principalId": grant.principal_id,
    }


def _owner_type(
    owner: DirectoryObject,
) -> Literal["user", "servicePrincipal", "group"] | None:
    """Classify an owner by its concrete DirectoryObject subtype.

    Pure: no network. An unrecognized directory object kind degrades to `None`
    rather than guessing.
    """
    if isinstance(owner, User):
        return "user"
    if isinstance(owner, ServicePrincipal):
        return "servicePrincipal"
    if isinstance(owner, Group):
        return "group"
    return None


def owner_from_graph(
    owner: DirectoryObject, owned: Literal["application", "servicePrincipal"]
) -> OwnerRecord:
    """Map a Graph owner DirectoryObject onto an owner record.

    Pure: no network. `owned` is supplied by the caller — which object's owners
    are being read — mirroring the credential discriminator. `ownerType` is taken
    from the concrete subtype so an SP-owns-SP privilege chain stays visible, not
    hidden among human owners.
    """
    return {
        "owner": owned,
        "ownerType": _owner_type(owner),
        "id": owner.id,
        "displayName": getattr(owner, "display_name", None),
    }


async def _page_all(
    builder: Any, config: RequestConfiguration | None = None
) -> list[Any]:
    """Follow `@odata.nextLink` over any collection builder, returning all items.

    The single paging primitive: every collector pages through this and shapes
    or filters the result itself (e.g. `_page_groups` keeps only `Group`s).
    """
    items: list[Any] = []
    page = await builder.get(request_configuration=config)
    while page is not None:
        items.extend(page.value or [])
        next_link = page.odata_next_link
        if not next_link:
            break
        page = await builder.with_url(next_link).get()
    return items


async def _page_groups(builder: Any, config: RequestConfiguration) -> list[Group]:
    """Page a membership builder, keeping only groups.

    `memberOf`/`transitiveMemberOf` return mixed directory objects (groups,
    directory roles, administrative units); only `Group` entries are memberships
    in the sense this audit cares about.
    """
    return [obj for obj in await _page_all(builder, config) if isinstance(obj, Group)]


async def _page_pim_schedules(
    builder: Any, config: RequestConfiguration
) -> list[PimSchedule]:
    """Follow `@odata.nextLink` over a PIM-for-Groups schedule builder."""
    schedules: list[PimSchedule] = []
    page = await builder.get(request_configuration=config)
    while page is not None:
        schedules.extend(page.value or [])
        next_link = page.odata_next_link
        if not next_link:
            break
        page = await builder.with_url(next_link).get()
    return schedules


class EntraCollector:
    """Run-scoped collector for the directory plane.

    Owns the Graph `client`, the two single-flight caches, and the concurrency
    semaphore so the network collectors no longer thread them through every
    signature. One instance is one selection/run: the caches are shared across
    every SP processed by this instance — a group's directory-role schedules and
    a resource SP's appRoles/display name are each fetched once, and single-flight
    keeps them from stampeding under concurrency — so an instance must not be
    reused across logically separate runs. The caches accept injection (for tests
    or to deliberately share state) but default to fresh ones per instance.

    asyncio is cooperatively scheduled on one thread, so the instance state
    (caches, semaphore) is safe to share across the fanned-out collectors without
    extra locking beyond what `SingleFlight` already provides.
    """

    def __init__(
        self,
        client: GraphServiceClient,
        *,
        concurrency: int = DEFAULT_CONCURRENCY,
        schedule_cache: SingleFlight[str, list[DirectoryRoleRecord]] | None = None,
        resource_cache: SingleFlight[str, ResourceInfo] | None = None,
        group_name_cache: SingleFlight[str, str | None] | None = None,
    ) -> None:
        self._client = client
        self._semaphore = asyncio.Semaphore(concurrency)
        self._schedule_cache = schedule_cache or SingleFlight()
        self._resource_cache = resource_cache or SingleFlight()
        self._group_name_cache = group_name_cache or SingleFlight()

    async def collect_by_object_ids(
        self, object_ids: list[str]
    ) -> tuple[list[ServicePrincipalRecord], list[str]]:
        """Collect records for an explicit set of object ids.

        Each id is resolved independently, so an unresolvable id degrades to a Run
        Error rather than aborting the run; the rest are then collected via the
        shared `_collect_all` path under the concurrency bound. Returns the records
        plus all Run Errors.
        """
        service_principals: list[ServicePrincipal] = []
        run_errors: list[str] = []
        for object_id in object_ids:
            try:
                service_principals.append(
                    await self._resolve_service_principal(object_id)
                )
            except Exception as exc:  # noqa: BLE001 - degrade to a Run Error, never abort
                run_errors.append(f"Failed to resolve '{object_id}': {exc}")
        records, collect_errors = await self._collect_all(service_principals)
        return records, run_errors + collect_errors

    async def collect_by_tag(
        self, tag: str
    ) -> tuple[list[ServicePrincipalRecord], list[str]]:
        """Collect every Service Principal carrying `tag` into records.

        Tag selection is a single Graph query: if it fails the whole selection is a
        Run Error. The selected SPs are then collected via the shared `_collect_all`
        path under the concurrency bound, so one SP's failure no longer drops the
        rest. Returns the records plus all Run Errors.
        """
        try:
            service_principals = await self._select_by_tag(tag)
        except Exception as exc:  # noqa: BLE001 - degrade to a Run Error, never abort
            return [], [f"Failed to select by tag '{tag}': {exc}"]
        return await self._collect_all(service_principals)

    async def _select_by_tag(self, tag: str) -> list[ServicePrincipal]:
        """Select Service Principals by tag, paging through all results.

        Queries `tags/any(c:c eq '{tag}')` with OData single-quote escaping and
        follows `@odata.nextLink` until the result set is exhausted. Requests the
        unified `$select` so tag-selected SPs share the by-id baseline.
        """
        escaped = tag.replace("'", "''")
        config = RequestConfiguration(
            query_parameters=ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                filter=f"tags/any(c:c eq '{escaped}')",
                select=SP_SELECT,
            )
        )
        selected: list[ServicePrincipal] = []
        page = await self._client.service_principals.get(request_configuration=config)
        while page is not None:
            if page.value:
                selected.extend(page.value)
            next_link = page.odata_next_link
            if not next_link:
                break
            page = await self._client.service_principals.with_url(next_link).get()
        return selected

    async def _resolve_service_principal(self, object_id: str) -> ServicePrincipal:
        """Resolve by object id; fall back to `appId eq '{id}'` only on a 404."""
        item_config = RequestConfiguration(
            query_parameters=ServicePrincipalItemRequestBuilder.ServicePrincipalItemRequestBuilderGetQueryParameters(
                select=SP_SELECT,
            )
        )
        try:
            sp = await self._client.service_principals.by_service_principal_id(
                object_id
            ).get(request_configuration=item_config)
        except APIError as exc:
            if exc.response_status_code != 404:
                raise
            sp = None

        if sp is not None:
            return sp

        # 404 on the object-id route: try resolving the value as an appId.
        escaped = object_id.replace("'", "''")
        list_config = RequestConfiguration(
            query_parameters=ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                filter=f"appId eq '{escaped}'",
                select=SP_SELECT,
            )
        )
        page = await self._client.service_principals.get(
            request_configuration=list_config
        )
        matches = page.value if page is not None and page.value else []
        if not matches:
            raise LookupError(
                f"No service principal found by object id or appId '{object_id}'."
            )
        return matches[0]

    async def _resolve_application(self, app_id: str) -> Application | None:
        """Fetch the related Application by `appId eq`; `None` if there is none."""
        escaped = app_id.replace("'", "''")
        config = RequestConfiguration(
            query_parameters=ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                filter=f"appId eq '{escaped}'",
                select=APP_SELECT,
            )
        )
        page = await self._client.applications.get(request_configuration=config)
        matches = page.value if page is not None and page.value else []
        return matches[0] if matches else None

    async def _collect_all(
        self, service_principals: list[ServicePrincipal]
    ) -> tuple[list[ServicePrincipalRecord], list[str]]:
        """Collect a list of already-resolved SPs into records, isolating failures.

        Shared by both selection paths so a per-SP failure never aborts the batch.
        SPs are processed concurrently under this instance's `asyncio.Semaphore`
        bound so a large fleet completes without flooding the tenant. The shared
        `schedule_cache`/`resource_cache` mean a group's directory-role schedules
        and a resource SP's appRoles/display name are each fetched once for the run
        — single-flight keeps them from stampeding under concurrency. Per-SP
        sections already degrade to SP Gaps; an unexpected collection failure here
        degrades to a Run Error rather than dropping every other SP.
        """
        run_errors: list[str] = []

        async def collect_one(sp: ServicePrincipal) -> ServicePrincipalRecord | None:
            async with self._semaphore:
                try:
                    return await self._collect_for_service_principal(sp)
                except Exception as exc:  # noqa: BLE001 - degrade to a Run Error
                    run_errors.append(f"Failed to collect '{sp.id}': {exc}")
                    return None

        results = await asyncio.gather(*(collect_one(sp) for sp in service_principals))
        records = [record for record in results if record is not None]
        return records, run_errors

    async def _collect_for_service_principal(
        self, sp: ServicePrincipal
    ) -> ServicePrincipalRecord:
        """Build a record for an already-resolved SP: Application, memberships, roles.

        Every section degrades to an SP Gap in the record's `errors[]` rather than
        aborting the whole SP (two-tier failures), so this never raises:
        the base record is mapped first from the already-resolved SP, then the
        independent sections are gathered concurrently. The three chains carry the
        only intra-SP ordering: owners follows Application resolution (it needs the
        Application object id), and directory-role attribution follows memberships.
        """
        record = sp_record_from_graph(sp, None)
        now = datetime.now(UTC)
        record["credentials"] = map_credentials(
            "servicePrincipal", sp.password_credentials, sp.key_credentials, now
        )

        async def application_and_owners() -> None:
            app_object_id: str | None = None
            if sp.app_id:
                try:
                    application = await self._resolve_application(sp.app_id)
                except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                    record["errors"].append(
                        f"Failed to resolve application: {describe_graph_error(exc)}"
                    )
                else:
                    if application is not None:
                        record["application"] = application_record_from_graph(
                            application
                        )
                        app_object_id = application.id
                        record["credentials"].extend(
                            map_credentials(
                                "application",
                                application.password_credentials,
                                application.key_credentials,
                                now,
                            )
                        )
                    else:
                        record["errors"].append(
                            "No Application object found for appId "
                            f"'{sp.app_id}' (SP Gap)"
                        )
            try:
                record["owners"] = await self.collect_owners(
                    record["objectId"], app_object_id
                )
            except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                record["errors"].append(
                    f"Failed to collect owners: {describe_graph_error(exc)}"
                )

        async def memberships_and_roles() -> None:
            try:
                record["groupMemberships"] = await self.collect_group_memberships(
                    record["objectId"]
                )
            except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                record["errors"].append(
                    f"Failed to collect group memberships: {describe_graph_error(exc)}"
                )
            try:
                active = await self.collect_pim_for_groups(record["objectId"])
                record["groupMemberships"] = apply_pim_membership(
                    record["groupMemberships"], active
                )
            except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                record["errors"].append(
                    "Failed to collect PIM-for-Groups status: "
                    f"{describe_graph_error(exc)}"
                )
            try:
                record["directoryRoles"] = await self.collect_directory_roles(
                    record["objectId"], record["groupMemberships"]
                )
            except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                record["errors"].append(
                    f"Failed to collect directory roles: {describe_graph_error(exc)}"
                )

        async def api_permissions() -> None:
            try:
                app_perms, delegated_perms = await self.collect_api_permissions(
                    record["objectId"]
                )
                record["applicationPermissions"] = app_perms
                record["delegatedPermissions"] = delegated_perms
            except Exception as exc:  # noqa: BLE001 - degrade to an SP Gap
                record["errors"].append(
                    f"Failed to collect API permissions: {describe_graph_error(exc)}"
                )

        await asyncio.gather(
            application_and_owners(), memberships_and_roles(), api_permissions()
        )
        return record

    async def collect_group_memberships(
        self, object_id: str
    ) -> list[GroupMembershipRecord]:
        """Collect a Service Principal's group memberships, labeled by how held.

        Pages `memberOf` (labeled `direct`) and `transitiveMemberOf` (labeled
        `transitive`), requesting `isAssignableToRole` so downstream via-group
        attribution can decide which groups actually confer a directory role.
        """
        sp_item = self._client.service_principals.by_service_principal_id(object_id)
        direct_config = RequestConfiguration(
            query_parameters=MemberOfRequestBuilder.MemberOfRequestBuilderGetQueryParameters(
                select=GROUP_SELECT,
            )
        )
        transitive_config = RequestConfiguration(
            query_parameters=TransitiveMemberOfRequestBuilder.TransitiveMemberOfRequestBuilderGetQueryParameters(
                select=GROUP_SELECT,
            )
        )
        memberships = [
            group_membership_from_graph(group, "direct")
            for group in await _page_groups(sp_item.member_of, direct_config)
        ]
        memberships.extend(
            group_membership_from_graph(group, "transitive")
            for group in await _page_groups(
                sp_item.transitive_member_of, transitive_config
            )
        )
        return memberships

    async def resolve_group_name(self, group_id: str) -> str | None:
        """Resolve a group's display name, fetching at most once per group id.

        Backed by the instance's group-name cache: concurrent or repeat lookups
        for the same group share one `GET /groups/{id}` instead of refetching.

        The cache key is namespaced by the Graph resource path (`/groups/{id}`) so
        it never collides with the other instance caches (e.g. schedules) keyed by
        bare id.
        """

        async def fetch() -> str | None:
            config = RequestConfiguration(
                query_parameters=GroupItemRequestBuilder.GroupItemRequestBuilderGetQueryParameters(
                    select=["id", "displayName"],
                )
            )
            group = await self._client.groups.by_group_id(group_id).get(
                request_configuration=config
            )
            return group.display_name if group is not None else None

        return await self._group_name_cache.do(f"/groups/{group_id}", fetch)

    async def _principal_schedules(
        self, principal_id: str
    ) -> list[RoleSchedule]:
        """Fetch the active directory-role assignment schedules for one principal id.

        The principal may be the SP itself (direct paths) or a role-assignable group
        (via-group paths); both are filtered by `principalId` with
        `$expand=roleDefinition` so role display names resolve in the same call. Only
        assignment (active) schedules are read — eligibility schedules are skipped
        because an SP cannot activate an eligible role.
        """
        escaped = principal_id.replace("'", "''")
        active_config = RequestConfiguration(
            query_parameters=RoleAssignmentSchedulesRequestBuilder.RoleAssignmentSchedulesRequestBuilderGetQueryParameters(
                filter=f"principalId eq '{escaped}'",
                expand=["roleDefinition"],
            )
        )
        directory = self._client.role_management.directory
        return await _page_all(directory.role_assignment_schedules, active_config)

    async def collect_pim_for_groups(
        self, principal_id: str
    ) -> list[PrivilegedAccessGroupAssignmentSchedule]:
        """Fetch the SP's active PIM-for-Groups (standing-membership) schedules.

        The endpoint returns HTTP 400 without a `$filter`, so it is always issued
        with a `principalId` filter; `groupId` and `accessId` are then read off the
        results by `apply_pim_membership`. Only assignment (standing-membership)
        schedules are read — eligibility schedules are skipped because an SP cannot
        activate an eligible membership.
        """
        escaped = principal_id.replace("'", "''")
        active_config = RequestConfiguration(
            query_parameters=AssignmentSchedulesRequestBuilder.AssignmentSchedulesRequestBuilderGetQueryParameters(
                filter=f"principalId eq '{escaped}'",
            )
        )
        group = self._client.identity_governance.privileged_access.group
        active = await _page_pim_schedules(group.assignment_schedules, active_config)
        return [
            s for s in active if isinstance(s, PrivilegedAccessGroupAssignmentSchedule)
        ]

    async def collect_directory_roles(
        self,
        object_id: str,
        memberships: list[GroupMembershipRecord],
    ) -> list[DirectoryRoleRecord]:
        """Collect active Directory Roles across both paths, with Via-group attribution.

        Direct path filters the SP's own id (`source = "direct"`). Via-group path
        queries, for each role-assignable group the SP is a transitive member of, the
        group's schedules and attributes every returned role to the SP with the
        group's display name as `source` and its id as `sourceGroupId` — regardless
        of intermediate non-role-assignable groups, since `memberships` already holds
        the transitive closure. Only active assignments are collected: an SP cannot
        hold an eligible role, directly or via a group it cannot activate.

        A group's schedules are fetched at most once across every SP that reaches it
        via this instance's `schedule_cache`. Its key is namespaced by the Graph
        resource path so the cache never collides with other single-flight users
        (e.g. group-name lookups) keyed by bare id.
        """
        roles: list[DirectoryRoleRecord] = []

        active = await self._principal_schedules(object_id)
        roles.extend(
            directory_role_from_schedule(s, "direct", None) for s in active
        )

        seen_groups: set[str] = set()
        for membership in memberships:
            group_id = membership["groupId"]
            if not membership["isAssignableToRole"] or group_id is None:
                continue
            if group_id in seen_groups:
                continue
            seen_groups.add(group_id)
            source = membership["displayName"] or group_id

            async def fetch(
                gid: str = group_id, src: str = source
            ) -> list[DirectoryRoleRecord]:
                g_active = await self._principal_schedules(gid)
                return [
                    directory_role_from_schedule(s, src, gid) for s in g_active
                ]

            roles.extend(
                await self._schedule_cache.do(
                    f"/roleManagement/directory/schedules/{group_id}", fetch
                )
            )
        return roles

    async def _resolve_resource(self, resource_id: str) -> ResourceInfo:
        """Resolve a resource SP to its display name and `appRoleId -> value` map.

        Backed by this instance's `resource_cache`, keyed by the Graph resource
        path: the Microsoft Graph SP — targeted by most assignments — is fetched
        once and reused across every SP and both permission planes for the run.
        """

        async def fetch() -> ResourceInfo:
            config = RequestConfiguration(
                query_parameters=ServicePrincipalItemRequestBuilder.ServicePrincipalItemRequestBuilderGetQueryParameters(
                    select=RESOURCE_SELECT,
                )
            )
            resource = await self._client.service_principals.by_service_principal_id(
                resource_id
            ).get(request_configuration=config)
            if resource is None:
                return None, {}
            return resource.display_name, app_role_value_map(resource)

        return await self._resource_cache.do(f"/servicePrincipals/{resource_id}", fetch)

    async def collect_api_permissions(
        self, object_id: str
    ) -> tuple[list[ApplicationPermissionRecord], list[DelegatedPermissionRecord]]:
        """Collect the SP's application and delegated API permissions.

        Application permissions (`appRoleAssignments`) resolve their `appRoleId` to a
        human-readable value through the resource SP's `appRoles`; delegated
        permissions (`oauth2PermissionGrants`) resolve only their resource display
        name. Both resolutions go through this instance's `resource_cache` keyed by
        `resourceId`, so a resource SP is fetched once per run.
        """
        sp_item = self._client.service_principals.by_service_principal_id(object_id)

        application_permissions: list[ApplicationPermissionRecord] = []
        for assignment in await _page_all(sp_item.app_role_assignments):
            resource_id = assignment.resource_id
            display_name, app_roles = (None, {})
            if resource_id is not None:
                display_name, app_roles = await self._resolve_resource(str(resource_id))
            permission = resolve_app_role_value(assignment.app_role_id, app_roles)
            application_permissions.append(
                application_permission_from_graph(assignment, display_name, permission)
            )

        delegated_permissions: list[DelegatedPermissionRecord] = []
        for grant in await _page_all(sp_item.oauth2_permission_grants):
            resource_id = grant.resource_id
            display_name = None
            if resource_id is not None:
                display_name, _ = await self._resolve_resource(str(resource_id))
            delegated_permissions.append(
                delegated_permission_from_graph(grant, display_name)
            )

        return application_permissions, delegated_permissions

    async def collect_owners(
        self, object_id: str, app_object_id: str | None
    ) -> list[OwnerRecord]:
        """Collect Owners of the SP and (when present) its Application, flattened.

        Pages `/servicePrincipals/{id}/owners` and, only when the SP has an
        Application object, `/applications/{id}/owners`, each with `$select=id,
        displayName`. Every entry is tagged with which object it owns; `ownerType` is
        derived from the owner's directory subtype so a non-human owner is visible.
        """
        sp_config = RequestConfiguration(
            query_parameters=ServicePrincipalOwnersRequestBuilder.OwnersRequestBuilderGetQueryParameters(
                select=OWNER_SELECT,
            )
        )
        sp_item = self._client.service_principals.by_service_principal_id(object_id)
        owners = [
            owner_from_graph(obj, "servicePrincipal")
            for obj in await _page_all(sp_item.owners, sp_config)
            if isinstance(obj, DirectoryObject)
        ]
        if app_object_id is not None:
            app_config = RequestConfiguration(
                query_parameters=ApplicationOwnersRequestBuilder.OwnersRequestBuilderGetQueryParameters(
                    select=OWNER_SELECT,
                )
            )
            app_item = self._client.applications.by_application_id(app_object_id)
            owners.extend(
                owner_from_graph(obj, "application")
                for obj in await _page_all(app_item.owners, app_config)
                if isinstance(obj, DirectoryObject)
            )
        return owners
