"""Typed shapes for the Audit Report envelope and its sub-objects.

These TypedDicts are the single source of truth for the JSON the tool writes.
They are network-free and exist so `ty` enforces the schema at type-check time
rather than leaving it aspirational.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class ApplicationRecord(TypedDict):
    """The Application related to a Service Principal via `appId`.

    Attached to a Service Principal as a nullable object — `null` for managed
    identities, multi-tenant apps, and gallery apps that have no Application.
    """

    objectId: str | None
    appId: str | None
    displayName: str | None


class AzureRoleAssignment(TypedDict):
    """An Azure RBAC (resource-plane) role assignment held by a Service Principal.

    Carried in `ServicePrincipalRecord.azureRoleAssignments`. Distinct from a
    Directory Role. `managementGroupId` is parsed only for a Management Group
    scope; `subscriptionId`/`subscriptionName` are `None` for
    management-group-scoped assignments.
    """

    roleName: str
    scopeType: str
    scope: str
    subscriptionId: str | None
    subscriptionName: str | None
    managementGroupId: str | None


class GroupMembershipRecord(TypedDict):
    """One group the Service Principal belongs to, directly or transitively.

    `membershipType` distinguishes a directly-assigned group (`memberOf`) from
    one reached only through nesting (`transitiveMemberOf`). `isAssignableToRole`
    is the Graph flag that decides whether a directory role targeting the group
    is actually attributed to the SP (see CONTEXT.md, Via-group attribution).
    `pimMembership` records how the SP holds a role-assignable group via
    PIM-for-Groups — standing (`assigned`) or `none` — and is `None` for
    memberships where it does not apply (non-role-assignable groups). Eligible
    (must-activate) membership never appears: an SP cannot perform the interactive
    activation it requires.
    """

    groupId: str | None
    displayName: str | None
    membershipType: Literal["direct", "transitive"]
    isAssignableToRole: bool | None
    pimMembership: Literal["assigned", "none"] | None


class DirectoryRoleRecord(TypedDict):
    """A Directory Role (Entra plane) held by the Service Principal.

    Carried in `ServicePrincipalRecord.directoryRoles`, populated from both active
    assignment paths (direct and via-group). `assignmentType` is always `active`:
    an SP cannot hold an eligible assignment, which would require an interactive
    activation it cannot perform. `source` is `"direct"` when the role targets the
    SP itself, or the group's display name when attributed through a role-assignable
    group; `sourceGroupId` carries that group's id (`None` for direct). Raw facts
    only — no computed `effective` field (see CONTEXT.md, Via-group attribution).
    """

    roleName: str | None
    assignmentType: Literal["active"]
    source: str
    sourceGroupId: str | None
    directoryScopeId: str | None
    startDateTime: str | None
    endDateTime: str | None


class CredentialRecord(TypedDict):
    """A secret or certificate that can authenticate as the identity.

    Carried in `ServicePrincipalRecord.credentials`, flattened from both the
    Service Principal and its Application. `owner` records which object holds it
    (`application`/`servicePrincipal`); `credentialType` is `secret` for a
    password credential and `certificate` for a key credential. `status` is
    derived from both dates against a timezone-aware UTC now; the raw
    `startDateTime`/`endDateTime` are retained so "expiring soon" stays a
    consumer-side judgment.
    """

    owner: Literal["application", "servicePrincipal"]
    credentialType: Literal["secret", "certificate"]
    displayName: str | None
    keyId: str | None
    startDateTime: str | None
    endDateTime: str | None
    status: Literal["active", "expired", "not-yet-valid"]


class ApplicationPermissionRecord(TypedDict):
    """An application API permission (Graph `appRoleAssignment`) held by the SP.

    Carried in `ServicePrincipalRecord.applicationPermissions`. `permission` is
    the appRole's human-readable value (e.g. `User.Read.All`) resolved from the
    resource SP's `appRoles`, `"default access"` for the all-zero `appRoleId`
    GUID, or `None` when the GUID resolves to no known role.
    """

    resourceId: str | None
    resourceDisplayName: str | None
    appRoleId: str | None
    permission: str | None


class DelegatedPermissionRecord(TypedDict):
    """A delegated API permission (Graph `oauth2PermissionGrant`) held by the SP.

    Carried in `ServicePrincipalRecord.delegatedPermissions`. `scopes` is the
    space-delimited `scope` string split into a list; `consentType` is
    `AllPrincipals`/`Principal` and `principalId` is set only for `Principal`.
    """

    resourceId: str | None
    resourceDisplayName: str | None
    scopes: list[str]
    consentType: str | None
    principalId: str | None


class OwnerRecord(TypedDict):
    """A principal that can modify the audited identity (and mint Credentials).

    Carried in `ServicePrincipalRecord.owners`, flattened from the owners of both
    the Service Principal and its Application. `owner` records which object is
    owned (`application`/`servicePrincipal`), mirroring the credential
    discriminator; `ownerType` is the owning principal's kind
    (`user`/`servicePrincipal`/`group`) so an SP-owns-SP privilege chain stays
    visible rather than hidden among human owners.
    """

    owner: Literal["application", "servicePrincipal"]
    ownerType: Literal["user", "servicePrincipal", "group"] | None
    id: str | None
    displayName: str | None


class ServicePrincipalRecord(TypedDict):
    """A single audited Service Principal: identity, tags, attached Application."""

    objectId: str
    appId: str | None
    displayName: str | None
    tags: list[str]
    application: ApplicationRecord | None
    azureRoleAssignments: list[AzureRoleAssignment]
    groupMemberships: list[GroupMembershipRecord]
    directoryRoles: list[DirectoryRoleRecord]
    credentials: list[CredentialRecord]
    applicationPermissions: list[ApplicationPermissionRecord]
    delegatedPermissions: list[DelegatedPermissionRecord]
    owners: list[OwnerRecord]
    errors: list[str]


class Selection(TypedDict):
    """How the audited set was chosen for this run.

    `objectIds` is the resolved selection set (always present). `tag` records the
    tag filter when the set was chosen via `--tag`; it is absent for the
    id-driven paths (`--object-id`/`--ids-file`).
    """

    objectIds: list[str]
    tag: NotRequired[str]


class Meta(TypedDict):
    """Run-scoped metadata carried at the top of the Audit Report.

    `runErrors` holds plane-wide / precondition failures (Run Errors). It is
    empty in the walking skeleton; collection-time failures populate it later.
    """

    generatedAt: str
    tenantId: str
    selection: Selection
    toolVersion: str
    runErrors: list[str]


class AuditReport(TypedDict):
    """The object envelope a run produces. Not a bare array."""

    meta: Meta
    servicePrincipals: list[ServicePrincipalRecord]
