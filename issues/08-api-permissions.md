---
labels: [Implemented]
---

# API permissions — application and delegated

## What to build

Collect the SP's API permissions on both planes of Graph consent.

- **Application permissions** (`appRoleAssignments`): each has `resourceId`,
  `resourceDisplayName`, and an `appRoleId` GUID. Resolve `appRoleId` to its
  human-readable value (e.g. `User.Read.All`) by fetching the resource SP's
  `appRoles` once and mapping. The all-zero GUID means "default access," not a
  specific role.
- **Delegated permissions** (`oauth2PermissionGrants`): each has `resourceId`,
  `scope` (space-delimited), `consentType` (`AllPrincipals`/`Principal`), and
  `principalId`. Surface scopes as a list.

Resolve `resourceId → displayName` and `appRoleId → value` through single-flight
caches keyed by `resourceId`, so the Microsoft Graph resource SP (targeted by most
assignments) is fetched once and reused across all SPs. A per-section failure
degrades to an SP Gap.

## Acceptance criteria

- [x] `applicationPermissions[]` lists each assignment with `resourceId`,
      `resourceDisplayName`, `appRoleId`, and the resolved permission value.
- [x] `delegatedPermissions[]` lists each grant with `resourceId`,
      `resourceDisplayName`, scopes (as a list), `consentType`, and `principalId`.
- [x] Resource SP and appRole lookups go through single-flight caches keyed by
      `resourceId`; the Microsoft Graph SP is fetched once for a multi-SP run.
- [x] The all-zero appRole GUID is handled as "default access," not a named role.
- [x] A failure on either collection records an SP Gap and the run continues.

## Resolution

`ApplicationPermissionRecord`/`DelegatedPermissionRecord` added to `models` and
folded into `ServicePrincipalRecord`. The pure mappers
(`application_permission_from_graph`, `delegated_permission_from_graph`,
`app_role_value_map`, `resolve_app_role_value`) live in `entra` alongside the
existing record mappers and are unit-tested in `test_entra_mapping`; the network
collector `collect_api_permissions` resolves each `resourceId` through a
run-scoped `SingleFlight[str, ResourceInfo]` cache (display name + appRole map),
so the Microsoft Graph resource SP is fetched once across all SPs and both
planes. The cache is created in `_collect_all` and threaded through
`_collect_for_service_principal`, where the section degrades to an SP Gap on
failure. Per the testing decisions, only the pure mappers are tested; the
I/O collector is not. Full suite, ruff format/lint, and `ty` all pass.

## Blocked by

- Issue 04 (group memberships + single-flight)
