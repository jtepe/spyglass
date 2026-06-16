---
labels: [implemented]
---

# Walking skeleton: project scaffold + identity audit to JSON

## What to build

The end-to-end backbone everything else hangs off. Convert the repo into the
`service-principal-audit` package with a `src/sp_audit/` layout and a `sp-audit`
console script, add the `azure-identity` + `msgraph-sdk` dependencies, and remove
the Terraform input path entirely. Wire up ruff (format + lint: `E, F, I, UP, B`)
and `ty` (strict) enforced via a pre-commit hook, with `ty` running as a
`repo: local` hook (`uv run ty check`).

Then deliver one thin vertical path: `sp-audit --object-id <id>` runs an async
program that (1) gates on a single up-front precondition verifying both
`az account show` and a live `AzureCliCredential` Graph token, harvesting
`tenantId`; (2) resolves the SP strictly via `GET /servicePrincipals/{id}` with an
`appId eq '{id}'` fallback only on 404; (3) collects identity (objectId, appId,
displayName, tags) plus the related Application as a nullable attached object; and
(4) writes the Audit Report as a `{ meta, servicePrincipals }` object envelope,
sorted by display name, exiting 0.

`meta` carries `generatedAt`, `tenantId`, `selection`, `toolVersion`, and an
(empty for now) `runErrors`. No `signedInUser`. The two-tier failure model is
established here: global preconditions fail fast with a non-zero exit before any
collection; once collection starts, the run completes and exits 0 and writes JSON.

Establishes the `models`, `auth`, `report`, and `cli` modules and a minimal
`entra` identity collector. Uses the glossary vocabulary (Service Principal,
Application, Audit Report, Run Error, SP Gap) and respects the async +
msgraph-sdk and envelope + failure-tier design decisions.

## Acceptance criteria

- [x] `pyproject.toml` renamed to `service-principal-audit` with a real
      description, `azure-identity` + `msgraph-sdk` dependencies, and a `sp-audit`
      console script entry point.
- [x] Source lives under `src/sp_audit/`; Terraform code (`--state-file`,
      `parse_terraform_state`) is gone.
- [x] ruff format + lint and `ty` strict run via a working `.pre-commit-config.yaml`
      (`ty` as a `repo: local` hook).
- [x] `sp-audit --object-id <id>` fails fast with a clear, non-zero exit when not
      logged in OR when a Graph token cannot be acquired, before any collection.
- [x] On success it writes a `{ meta, servicePrincipals }` JSON document; `meta`
      contains `generatedAt`, `tenantId`, `selection`, `toolVersion`, `runErrors`;
      `signedInUser` is absent.
- [x] An SP is resolved by object id, falling back to `appId eq` only on 404; the
      record carries objectId, appId, displayName, tags, and a nullable
      `application`.
- [x] `servicePrincipals` is sorted by display name; the run exits 0.
- [x] Unit tests cover `report` (envelope shape, sort, meta keys), the
      object-id→record mapping, and the `models` shapes type-check under `ty`.

## Blocked by

- None - can start immediately
