# The Run Store

This document describes the SQLite database behind the `--db` flag: what a
persisted run looks like, what the timestamps mean, and how to query history.
It is the reference behind the
[Persisting runs](../README.md#persisting-runs---db) section of the top-level
README. Domain terms in **bold** (Service Principal, Audit Report, SP Gap,
Run Error, retrievedAt, Run Store, …) are defined in
[`CONTEXT.md`](../CONTEXT.md).

## One run, one snapshot

Every spyglass run produces an **Audit Report** that describes a moment in
time. With `--db PATH`, that report is additionally written into the **Run
Store** as one normalized snapshot:

- a `runs` row — the run's `generated_at`, `tenant_id`, `tool_version`, and
  selection (`selection_tag` when selected by tag, plus the resolved
  `selection_object_ids` as a JSON array), with **Run Errors** in
  `run_errors`;
- a `service_principals` row per audited SP — identity, tags, and the
  attached Application (`application_present` distinguishes "no Application"
  from "Application with null fields"), with **SP Gaps** in `sp_errors`;
- one row per fact in the section tables: `credentials`, `directory_roles`,
  `azure_role_assignments`, `group_memberships`, `application_permissions`,
  `delegated_permissions`, and `owners`.

Runs are strictly **append-only**: a new run never rewrites an earlier one.
History is the accumulated set of snapshots, and change tracking is a query
over them. The whole report is written in a single transaction — a failed
persist leaves no partial run, the already-written JSON stays valid, and the
run exits non-zero so the miss is never silent.

The schema is versioned via `PRAGMA user_version`; a database written by a
newer spyglass is refused rather than misread, as is a non-empty database
that is not a Run Store.

## Timestamps

Every fact row carries a `retrieved_at` column: the **retrievedAt** stamp of
the Graph or ARM call that produced its section, recorded when that call
returned. A long run can span minutes and the Azure RBAC batch arrives from a
separate, later call, so per-section stamps are more honest than the run's
single `generatedAt`.

Audit Reports written by spyglass versions without per-section `retrievedAt`
stamps carry no such timestamps; when such a report is persisted, its fact
rows are stamped with the run's `generated_at` instead.

## Observed vs. removed

The `sp_sections` table records which sections were *actually observed* for
each SP in each run, and when. A section with no row there failed as an **SP
Gap** that run (or never ran) — its facts are **unknown** for that run, not
removed. A differ comparing two runs must consult `sp_sections` before
reading an empty section as a deletion: "no credentials rows and the
`servicePrincipal`/`application` sections observed" means the credentials are
gone; "no credentials rows and the sections unobserved" means spyglass could
not look.

## Querying history

Plain SQL is the query interface. When did a credential first appear?

```sql
SELECT MIN(c.retrieved_at)
FROM credentials c
JOIN service_principals sp ON sp.id = c.sp_id
WHERE sp.object_id = '2222...' AND c.key_id = 'abcd...';
```

Which Azure role assignments does the latest run report for an SP?

```sql
SELECT ra.role_name, ra.scope, ra.retrieved_at
FROM azure_role_assignments ra
JOIN service_principals sp ON sp.id = ra.sp_id
WHERE sp.object_id = '2222...'
  AND sp.run_id = (SELECT MAX(id) FROM runs);
```

Which directory roles appeared between two runs (gap-aware on the new side)?

```sql
SELECT dr.role_name, dr.source
FROM directory_roles dr
JOIN service_principals sp ON sp.id = dr.sp_id
JOIN sp_sections obs ON obs.sp_id = sp.id AND obs.section = 'directoryRoles'
WHERE sp.run_id = :new_run AND sp.object_id = :object_id
  AND dr.role_name NOT IN (
    SELECT dr2.role_name
    FROM directory_roles dr2
    JOIN service_principals sp2 ON sp2.id = dr2.sp_id
    WHERE sp2.run_id = :old_run AND sp2.object_id = :object_id
  );
```
