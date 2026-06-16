---
labels: [implemented]
---

# PIM-for-Groups membership status

## What to build

Annotate how the SP holds each role-assignable group membership — standing
(`assigned`), `eligible`, or `none` — which is orthogonal to whether the group's
role is active/eligible. Query the PIM-for-Groups assignment schedules (active
membership) and eligibility schedules (eligible membership), filtered on the SP's
`principalId`.

> Gotcha: these endpoints return **HTTP 400** without a `$filter` on `principalId`
> (or `groupId`). Always filter by the SP id, then read `groupId` and `accessId`
> from the results.

Keep `accessId = member` for role-inheritance reasoning. Use the results to set
each entry's `groupMemberships[].pimMembership`. A per-section failure (e.g. a
Directory-Readers-only user hitting PIM) degrades to an SP Gap.

## Acceptance criteria

- [x] Both PIM-for-Groups schedule calls are always issued with a `principalId`
      `$filter`. — `collect_pim_for_groups` builds both `assignmentSchedules` and
      `eligibilitySchedules` requests with a `principalId eq '{id}'` filter.
- [x] Each role-assignable group membership gets `pimMembership` set to
      `assigned`, `eligible`, or `none`. — `apply_pim_membership` maps an active
      assignment to `assigned`, an eligibility to `eligible`, and a
      role-assignable group in neither to `none`; non-role-assignable memberships
      stay `None`.
- [x] `member` vs `owner` `accessId` is handled so role-inheritance reasoning uses
      `member`. — `_member_group_ids` keeps only schedules with
      `accessId = member`, dropping `owner` access.
- [x] A 403/400 on a PIM call records an SP Gap and the run continues. — the PIM
      collection in `_collect_for_service_principal` is wrapped so any failure
      appends a "Failed to collect PIM-for-Groups status" SP Gap to the record's
      `errors[]` without aborting the run.

## Notes

- Pure annotation logic (`apply_pim_membership`, `_member_group_ids`) is unit
  tested in `tests/test_pim_membership.py`; the Graph I/O collector
  (`collect_pim_for_groups`) stays untested per the pure-modules-only
  testing decision.
- `pimMembership` was added to `GroupMembershipRecord` in `models.py`.

## Blocked by

- Issue 04 (group memberships + single-flight)
