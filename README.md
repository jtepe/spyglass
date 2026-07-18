<p align="center">
  <img src="assets/logo-wordmark-v2.svg" alt="Spyglass — Entra service principals in focus" width="560">
</p>

A read-only spyglass for Microsoft Entra service principals: a CLI that, for a
selected set of Entra **Service Principals**, gathers
everything the directory (Entra) and Azure RBAC planes know about them and writes
it to a single JSON **Audit Report**, optionally rendered to a self-contained HTML
view.

By default the tool runs as the user who ran `az login`, inheriting that user's
permissions, and never writes to the tenant. The Microsoft Graph (directory)
plane can instead authenticate as a **service principal** or a **managed
identity** (see [Authentication](#authentication)); the Azure RBAC plane always
uses `az login`. Domain terms used throughout (Service Principal, Application,
Directory Role, Azure Role Assignment, Plane, Credential, Owner, Audit Report,
Run Error, SP Gap, Via-group attribution) are defined in
[`CONTEXT.md`](CONTEXT.md).

## Prerequisites

1. **Azure CLI** — install `az` and ensure it is on your `PATH`.
2. **Log in** — run `az login` (the Azure RBAC plane always uses it; on a
   managed-identity host, `az login --identity` works too).
3. **Permissions** — see [Required permissions](#required-permissions) below.
   In short: **Global Reader** in Entra plus a **Reader** role over the
   management group hierarchy you want covered.

The project is managed with [uv](https://docs.astral.sh/uv/). Installing it
exposes the `spyglass` console command:

```bash
uv sync
uv run spyglass --help
```

## Usage

`spyglass` always writes a JSON Audit Report. You choose the set of Service
Principals to audit with exactly one selection method.

### Select by object id

Pass one or more Service Principal `objectId`s (an `appId` is accepted as a
fallback and resolved to its Service Principal). The flag repeats:

```bash
uv run spyglass \
  --object-id 22222222-2222-2222-2222-222222222222 \
  --object-id 99999999-9999-9999-9999-999999999999 \
  --output audit-report.json
```

### Select from an ids file

Point `--ids-file` at a file of object ids — either a newline-separated list or
a JSON array. Values are merged and de-duplicated with any `--object-id` flags:

```bash
uv run spyglass --ids-file ./sp-ids.txt --output audit-report.json
```

### Select by tag

Audit every Service Principal carrying a given Entra tag. This is mutually
exclusive with `--object-id` / `--ids-file`:

```bash
uv run spyglass --tag terraform-iac --output audit-report.json
```

### Rendering HTML

Add `--html` to additionally render a single self-contained HTML file (data, CSS
and JS embedded — no external assets), suitable for sharing as one file. JSON is
always written; `--html` only adds the HTML view. `--html-output` overrides the
path (and implies `--html`); by default the HTML path is the JSON path with an
`.html` suffix.

```bash
uv run spyglass --tag terraform-iac --html
# writes audit-report.json and audit-report.html

uv run spyglass --tag terraform-iac --html-output report.html
```

The HTML view is **security-focused**: it foregrounds Directory Roles,
Credentials (flagging `expired`, with raw dates kept so "expiring soon" is a
consumer-side judgment) and Azure Role Assignments, while showing group
memberships, API permissions, owners and raw identity as collapsible JSON.
Management-Group-scoped assignments get their own bucket rather than being folded
under a subscription. A sticky search box filters Service Principals by display
name (space-separated tokens matched in order; press `/` to focus, `Esc` to
clear).

### Persisting runs (`--db`)

Point `--db` at a SQLite file to additionally persist the run into a local
**Run Store** — one append-only snapshot per run, so changes can be tracked
over time. The file and its schema are created on first use; JSON (and HTML)
output is unchanged.

```bash
uv run spyglass --tag terraform-iac --output audit-report.json --db spyglass.db
```

See [The Run Store](docs/run-store.md) for the schema, its timestamp
semantics, and how to query history.

### Other flags

- `--output PATH` — path for the JSON Audit Report (default `audit-report.json`).
- `--concurrency N` — maximum Service Principals processed at once (default 8).
  Lower it if a throttling-prone tenant starts returning HTTP 429s.
- `--log-level {error,warn,info,debug}` — logging verbosity on stderr (default
  `info`). `error` shows only run-aborting failures (a clean run at this level
  is silent), `warn` adds non-aborting errors such as SP Gaps and Run Errors,
  `info` adds one line per Service Principal, and `debug` adds every HTTP call
  made, stamped with the Service Principal in context. Colors are disabled when
  stderr is not a terminal or `NO_COLOR` is set.

## The Audit Report

The output is a single JSON **object** (an envelope) — not a bare array:

```json
{
  "meta": { "...": "run-scoped metadata, including runErrors" },
  "servicePrincipals": [ { "...": "one entry per audited SP" } ]
}
```

`meta` carries the run context — `generatedAt`, `tenantId`, the `selection`
(resolved `objectIds`, plus `tag` when selected that way), `toolVersion`, and
`runErrors`. Each entry in `servicePrincipals` (sorted by display name) reports
**both planes** in separately-named fields:

| Field | Plane | What it holds |
| --- | --- | --- |
| `objectId`, `appId`, `displayName`, `tags`, `application` | directory | Identity of the SP and its nullable attached Application (`null` for managed identities, multi-tenant and gallery apps). |
| `directoryRoles` | directory | Active Directory Roles held directly or via a role-assignable group (`assignmentType` is always `active` — an SP cannot hold an eligible assignment, which needs an interactive activation). `source` is `"direct"` or the group's display name, with `sourceGroupId`. |
| `groupMemberships` | directory | Direct and transitive group memberships, with `isAssignableToRole` and PIM-for-Groups status (`pimMembership`). |
| `credentials` | directory | Secrets and certificates flattened across both the SP and its Application, each with a derived `status` (`active`/`expired`/`not-yet-valid`) and the raw dates. |
| `applicationPermissions`, `delegatedPermissions` | directory | API permissions: application (`appRoleAssignment`) and delegated (`oauth2PermissionGrant`). |
| `owners` | directory | Principals that can modify the identity (and mint Credentials), flattened across SP and Application, tagged with `owner` and `ownerType`. |
| `azureRoleAssignments` | Azure RBAC | Role assignments at management group, subscription, resource group or resource scope. MG-scoped entries carry `managementGroupId` (with `subscription*` null). |
| `errors` | — | Per-SP gaps (SP Gaps): a section that failed for this SP (e.g. a 403 on a PIM call, a missing Application). |
| `retrievedAt` | — | Per-section retrieval timestamps (ISO 8601 UTC), stamped when the call that produced each section returned. A missing key means that section was **not observed** this run (its call failed as an SP Gap) — absence of data, not absence of privilege. |

### Two-tier failure model

The run distinguishes two kinds of failure:

- **Run Errors** — plane-wide or precondition failures (e.g. the Azure RBAC batch
  query failed) recorded in top-level `meta.runErrors`. The rest of the report
  still writes.
- **SP Gaps** — a per-SP, per-section failure recorded in that SP's `errors[]`.
  The run still completes and **exits 0**; gaps are data, not run failures.

A failed precondition (not logged in, no Graph token) is the one case that aborts
before collection with a non-zero exit.

See [`example-audit.json`](example-audit.json) for a full report on synthetic
data — including a Management-Group-scoped assignment, all three credential
statuses, a permanent and a time-bound active Directory Role, a managed identity
(`null` Application) with SP Gaps, and a `runErrors` entry — and
[`example-audit.html`](example-audit.html) for the rendered view.

## Authentication

The **Azure RBAC plane always uses `az login`** (it shells out to `az graph
query`), so an active CLI login is always required and is the source of the
reported `tenantId`. On a managed-identity host, `az login --identity` satisfies
this.

The **Microsoft Graph (directory) plane** selects its credential by precedence:

1. **Service principal** — when a client id and tenant id are provided (via
   `--client-id` / `--tenant-id` or `AZURE_CLIENT_ID` / `AZURE_TENANT_ID`) and
   the secret is set in the `AZURE_CLIENT_SECRET` environment variable. The
   secret is read only from the environment — never a flag — so it is not
   exposed in shell history or process listings.
2. **Managed identity** — when `--managed-identity` is passed (system-assigned,
   or user-assigned when `--client-id` is also given).
3. **`az login` user** — the default when neither of the above is configured.

```bash
# Service principal for the Graph plane (RBAC plane still uses az login):
export AZURE_CLIENT_SECRET='...'
spyglass --client-id <app-id> --tenant-id <tenant-id> --object-id <sp-object-id>

# Managed identity for the Graph plane:
spyglass --managed-identity --object-id <sp-object-id>
```

## Required permissions

- **Directory plane (Entra).**
  - **`az login` user.** A directory role that can read the data — **Global
    Reader** is enough; it covers directory reads, the role-management reads, and
    PIM-for-Groups. **Directory Readers** alone cannot read the directory-role
    schedule or the PIM-for-Groups endpoints, so those sections degrade to SP
    Gaps in each affected SP's `errors[]` (the run still completes and exits 0).
  - **Service principal / managed identity.** Grant the **application** Graph
    permissions `Directory.Read.All`, `RoleAssignmentSchedule.Read.Directory`,
    and `PrivilegedAssignmentSchedule.Read.AzureADGroup` (admin consent) — the
    least-privileged set covering every call the tool makes; the per-endpoint
    derivation is in [`docs/permissions.md`](docs/permissions.md). Without the
    last two, the directory-role and PIM-for-Groups sections return `403` and
    degrade to SP Gaps; the run still exits 0.
- **Azure RBAC plane (ARM).** A **Reader** (or equivalent) role over the
  management group hierarchy you want covered, held by the `az login` identity,
  so the Azure Resource Graph query can resolve assignments at every scope.

## Non-goals

The following are explicitly out of scope for this tool:

- **Sign-in / usage activity** — no dormant-SP detection from sign-in or
  last-credential-usage signals.
- **Effective-privilege computation** — the report keeps raw, cross-referenceable
  facts; there is no derived `effective`/`effectiveReason` field.
- **Terraform state input** — there is no `--state-file` / state parsing; selection
  is by object id, ids file, or tag only.
- **`--management-group` scoping** — the Azure RBAC query always covers the full
  management group hierarchy; there is no scoping flag.
- **`--expiring-within` threshold flag** — raw credential dates are retained so
  "expiring soon" stays a consumer-side judgment.

## Documentation

Longer-form references live under [`docs/`](docs/):

- [Directory roles and service principals](docs/service-principal-directory-roles.md)
  — how a Service Principal can hold a Directory Role (direct, via a
  role-assignable group, and via PIM), and why an *eligible* assignment is never
  possible for one.
- [Required permissions, in detail](docs/permissions.md) — the least-privileged
  permission set per plane, derived call-by-call from what the tool queries.
- [The Run Store](docs/run-store.md) — the SQLite database behind `--db`: the
  per-run snapshot schema, its timestamp semantics, and how to query change
  history with plain SQL.

## Development

```bash
uv run pytest        # tests
uv run ruff check .  # lint
uv run ruff format . # format
uv run ty check      # type-check
```

The current sources of truth are this README and [`CONTEXT.md`](CONTEXT.md).
