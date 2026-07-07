# Spyglass

A read-only CLI (`spyglass`) that, for a selected set of Entra service principals, gathers
everything the directory (Entra) and Azure RBAC know about them and writes it to
a single JSON file, optionally rendered to self-contained HTML.

## Language

**Service Principal**:
The per-tenant identity object being audited (the portal's "enterprise
application"). It is always the subject of the audit and the join key with Azure
RBAC via `principalId`. Identified by its `objectId`, with `appId` linking to its
Application.
_Avoid_: enterprise application, SP (in prose/schema), workload identity

**Application**:
The app-registration object (global app definition) related to a Service
Principal via `appId`. An optional, nullable attached attribute of the audit
subject — `null` for managed identities, multi-tenant apps, and gallery apps.
_Avoid_: app registration, enterprise application

**appId**:
The Application (Client) ID. The canonical name for this identifier across code,
schema, and docs.
_Avoid_: applicationId, Client ID

**objectId**:
The Service Principal's directory object id. The canonical identifier of the
audit subject.

**Directory Role**:
An Entra (directory-plane) role held by the Service Principal, e.g. Global
Reader. Carried in the `directoryRoles` field. Distinct from an Azure Role
Assignment.
_Avoid_: Entra role (in schema field names), admin role

**Azure Role Assignment**:
An Azure RBAC (ARM/resource-plane) role assignment held by the Service
Principal at a management group, subscription, resource group, or resource
scope. Carried in the `azureRoleAssignments` field. Distinct from a Directory
Role.
_Avoid_: roleAssignments (unqualified — ambiguous against directory roles), RBAC role

**Via-group attribution**:
The rule for crediting a Directory Role to a Service Principal through a group:
if the SP is a *transitive* member of a role-assignable group (`isAssignableToRole
= true`) that holds role R, then R is attributed to the SP — regardless of the
path, including intermediate non-role-assignable groups. Recorded on the role
with `source = <group displayName>` and `sourceGroupId`. `source = "direct"` when
the role targets the SP itself.

**Plane**:
Which authorization system a privilege belongs to: the **directory plane**
(Entra, via Microsoft Graph) or the **Azure RBAC plane** (ARM, via Azure
Resource Graph). The tool always reports both for every Service Principal and
keeps them in separately-named fields.

**Audit Report**:
The single JSON document a run produces: an object with run-scoped `meta`
(including `runErrors`) and a `servicePrincipals` array. Not a bare array.
_Avoid_: results array, output list

**Run Error**:
A plane-wide or precondition failure recorded in the report's top-level
`meta.runErrors` (e.g. the Azure RBAC batch query failed). Distinct from a per-SP
gap.
_Avoid_: global error

**SP Gap**:
A per-Service-Principal, per-section failure (e.g. a 403 on a PIM call, a missing
Application object) recorded in that SP's `errors[]`. The run still completes and
exits 0; gaps are data, not run failures.
_Avoid_: per-SP error (ambiguous), failure

**Credential**:
Any secret or certificate that can authenticate as the Service Principal or its
Application. Flattened across both owners (`application`/`servicePrincipal`) and
both kinds into one `credentials[]` array.

**Secret**:
A password-type Credential (Graph `passwordCredentials`). Surfaced as
`credentialType: "secret"` in the schema.
_Avoid_: password, passwordCredential, client secret

**Certificate**:
A key-type Credential (Graph `keyCredentials`).
_Avoid_: key, keyCredential

**Credential status**:
A derived enum on each Credential — `active` | `expired` | `not-yet-valid` —
computed from both `startDateTime` and `endDateTime` against a timezone-aware UTC
now. Raw dates are retained so "expiring soon" stays a consumer-side judgment.
_Avoid_: expired (as a bare boolean)

**Owner**:
A principal that can modify the audited identity (and thus mint Credentials for
it). Flattened across both owned objects into one `owners[]` array, each entry
tagged with `owner` (`application`/`servicePrincipal` — which object is owned)
and `ownerType` (`user`/`servicePrincipal`/`group`). An SP-owns-SP entry is a
privilege chain, not noise.

**retrievedAt**:
Per-section retrieval timestamps on each Service Principal record: each key is
stamped (ISO 8601 UTC) when the call that produced that section returned. A
missing key means the section was *not observed* that run (its call failed as
an SP Gap) — absence of data, never absence of privilege.
_Avoid_: fetchedAt, timestamp (unqualified)

**Run Store**:
The optional SQLite database (`--db`) that persists each run as an append-only
normalized snapshot for change tracking over time. Every fact row carries its
section's `retrievedAt`; the `sp_sections` table records which sections were
observed per SP per run, so a differ can tell "removed" from "not observed".
_Avoid_: history database, cache
