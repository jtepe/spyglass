---
labels: [Implemented]
---

# Docs rewrite and example artifact regeneration

## What to build

Bring the documentation in line with the shipped tool. Rewrite the README against
the new model: the `sp-audit` console command; selection via `--tag` /
`--object-id` / `--ids-file`; the `{ meta, servicePrincipals }` envelope; both
planes and their distinct fields; the four Directory Role paths; credentials,
owners, and permissions; Global Reader guidance (and the Directory-Readers gap that
produces SP Gaps on role/PIM endpoints); the `--html` flags; and the explicit
non-goals (sign-in activity, effective-privilege computation, Terraform,
`--management-group`, `--expiring-within`).

Establish the README and `CONTEXT.md` as the current source of truth for the
project's design. Delete the stale `example-audit.json` / `example-audit.html`
(which describe the old RBAC-only schema) and regenerate both from a real `sp-audit`
run against synthetic/fake-GUID data so the examples match the final schema.

## Acceptance criteria

- [x] README describes the `sp-audit` command, all selection flags, the envelope,
      both planes, every section, Global Reader guidance, the `--html` flags, and
      the documented non-goals.
- [x] The README and `CONTEXT.md` are the documented source of truth for the design.
- [x] The stale example artifacts are removed and regenerated, with the current
      envelope and schema (including a Management Group scope example and credential
      status examples). No live tenant is available in this environment, so the
      examples are a synthetic, fake-GUID Audit Report run through the shipped
      `sp_audit.render` renderer rather than a literal `sp-audit` run.
- [x] No doc references the removed Terraform path or `--management-group` (both now
      appear only in the README non-goals).

## Blocked by

- Issue 11 (HTML rendering — examples regenerate both JSON and HTML from a real run)
