# Required permissions, in detail

This document derives the **least-privileged** permission set for Spyglass from
the actual API calls the tool makes, per plane. It is the reference behind the
[Required permissions](../README.md#required-permissions) section of the
top-level README. Domain terms in **bold** (Service Principal, Application,
Directory Role, Plane, SP Gap, …) are defined in [`CONTEXT.md`](../CONTEXT.md).

Spyglass is strictly read-only, so every permission below is a read
permission. The tool degrades gracefully: a missing permission turns the
affected section into an **SP Gap** in that SP's `errors[]` rather than
failing the run.

## The minimal set at a glance

| Plane | Identity | Needs |
| --- | --- | --- |
| Directory (Graph) | `az login` user | **Global Reader** directory role |
| Directory (Graph) | service principal / managed identity | `Directory.Read.All`, `RoleAssignmentSchedule.Read.Directory`, `PrivilegedAssignmentSchedule.Read.AzureADGroup` (application permissions, admin consent) |
| Azure RBAC (ARM) | `az login` user (always) | **Reader** over the management group hierarchy to cover |

## Directory plane: every Graph call, mapped

The Graph collector (`src/spyglass/entra.py`) makes exactly the calls below.
For each, the table lists the least-privileged **application** permission
Microsoft's Graph reference documents for that endpoint, and which permission
of the minimal set covers it.

| Call | Report section | Least-privileged permission | Covered by |
| --- | --- | --- | --- |
| `GET /servicePrincipals/{id}`, `GET /servicePrincipals?$filter=…` | identity, tags, SP credentials | `Application.Read.All` | `Directory.Read.All` |
| `GET /applications?$filter=appId eq …` | attached Application, its credentials | `Application.Read.All` | `Directory.Read.All` |
| `GET /servicePrincipals/{id}/memberOf` and `/transitiveMemberOf` | `groupMemberships` | `Application.Read.All` | `Directory.Read.All` |
| `GET /groups/{id}` | group display names | `GroupMember.Read.All` | `Directory.Read.All` |
| `GET /servicePrincipals/{id}/appRoleAssignments` | `applicationPermissions` | `Application.Read.All` | `Directory.Read.All` |
| `GET /servicePrincipals/{id}/oauth2PermissionGrants` | `delegatedPermissions` | **`Directory.Read.All`** | itself — the blocker |
| `GET /servicePrincipals/{id}/owners`, `GET /applications/{id}/owners` | `owners` | `Application.Read.All` | `Directory.Read.All` |
| `GET /roleManagement/directory/roleAssignmentSchedules?$filter=principalId…&$expand=roleDefinition` | `directoryRoles` | `RoleAssignmentSchedule.Read.Directory` | itself |
| `GET /identityGovernance/privilegedAccess/group/assignmentSchedules?$filter=principalId…` | `pimMembership` | `PrivilegedAssignmentSchedule.Read.AzureADGroup` | itself |

### Why `Directory.Read.All` cannot be narrowed away

One call has no granular read alternative:
`GET /servicePrincipals/{id}/oauth2PermissionGrants` (the
`delegatedPermissions` section). Its least-privileged permission *is*
`Directory.Read.All` — the only granular permission in that family,
`DelegatedPermissionGrant.ReadWrite.All`, is a **write** permission and would
be strictly worse. And once `Directory.Read.All` is held, it is an accepted
(higher-privileged) permission on every other directory call above, which is
why `Application.Read.All` would be pure redundancy and is not requested.

If the `delegatedPermissions` section were ever made optional,
`Directory.Read.All` could be replaced by `Application.Read.All` +
`GroupMember.Read.All`. As the tool stands, it cannot.

### Why the granular schedule permissions, not the umbrellas

- `RoleAssignmentSchedule.Read.Directory` replaces the broader
  `RoleManagement.Read.All`, which also grants role-management reads across
  Exchange, Intune, Cloud PC and entitlement management — providers Spyglass
  never touches. The tool reads only directory-role *assignment* schedules
  (an SP can never hold an eligible one, so eligibility schedules are never
  queried). The `$expand=roleDefinition` on that call reads role definitions,
  which `Directory.Read.All` (held anyway) covers; should the expand still
  return `403` with only the granular permission, the conservative fallback
  is `RoleManagement.Read.Directory` — still far narrower than
  `RoleManagement.Read.All`.
- `PrivilegedAssignmentSchedule.Read.AzureADGroup` replaces the broader
  `PrivilegedAccess.Read.AzureADGroup`, which also covers PIM-for-Groups
  *eligibility* schedules and policy — again, never queried. Microsoft's
  permission tables for the assignment-schedules endpoint now list only the
  granular permission.

### The `az login` user path

When the Graph plane runs as the `az login` user, access is governed by the
user's **directory role**, not by consented application permissions.
**Global Reader** covers every call above. **Directory Readers** alone cannot
read the role-assignment schedules or the PIM-for-Groups endpoints, so the
`directoryRoles` and `pimMembership` sections degrade to SP Gaps (the run
still completes and exits 0).

## Azure RBAC plane

The RBAC collector (`src/spyglass/azure_rbac.py`) only shells out to
`az graph query` (Azure Resource Graph, reading `authorizationresources` and
`resourcecontainers`) and `az role definition list` (ARM). Azure Resource
Graph returns only resources the caller can see, so the `az login` identity
needs a **Reader** (or equivalent) role assignment over the management group
hierarchy the report should cover. That is already the least-privileged ARM
role for the job; scopes without Reader simply do not appear in the results.
