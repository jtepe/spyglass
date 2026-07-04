"""Typed shapes for the Audit Report envelope and its sub-objects.

These TypedDicts are the single source of truth for the JSON the tool writes.
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
    """An Azure RBAC (resource-plane) role assignment held by a Service Principal."""

    roleName: str
    scopeType: str
    scope: str
    subscriptionId: str | None
    subscriptionName: str | None
    managementGroupId: str | None


class GroupMembershipRecord(TypedDict):
    """One group the Service Principal belongs to, directly or transitively."""

    groupId: str | None
    displayName: str | None
    membershipType: Literal["direct", "transitive"]
    isAssignableToRole: bool | None
    pimMembership: Literal["assigned", "none"] | None


class DirectoryRoleRecord(TypedDict):
    """A Directory Role (Entra plane) held by the Service Principal."""

    roleName: str | None
    assignmentType: Literal["active"]
    source: str
    sourceGroupId: str | None
    directoryScopeId: str | None
    startDateTime: str | None
    endDateTime: str | None


class CredentialRecord(TypedDict):
    """A secret or certificate that can authenticate as the identity."""

    owner: Literal["application", "servicePrincipal"]
    credentialType: Literal["secret", "certificate"]
    displayName: str | None
    keyId: str | None
    startDateTime: str | None
    endDateTime: str | None
    status: Literal["active", "expired", "not-yet-valid"]


class ApplicationPermissionRecord(TypedDict):
    """An application API permission (Graph `appRoleAssignment`) held by the SP."""

    resourceId: str | None
    resourceDisplayName: str | None
    appRoleId: str | None
    permission: str | None


class DelegatedPermissionRecord(TypedDict):
    """A delegated API permission (Graph `oauth2PermissionGrant`) held by the SP."""

    resourceId: str | None
    resourceDisplayName: str | None
    scopes: list[str]
    consentType: str | None
    principalId: str | None


class OwnerRecord(TypedDict):
    """A principal that can modify the audited identity (and mint Credentials)."""

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
