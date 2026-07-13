"""Azure RBAC (resource-plane) collector.

Lifts the working synchronous `az graph query` Azure Resource Graph (ARG)
collector. Without a scoping flag, `az graph query` runs at subscription scope
and never returns management-group-scoped rows, so every query is scoped to
the tenant root management group (whose id equals the tenant id) via
`--management-groups`; that covers every management group and every
subscription beneath it. Row-level
logic — scope classification and role-name resolution — lives in the pure
`arg_transform` module; this module only runs the bounded ARG batch and hands
the raw rows over.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess

from .arg_transform import transform_assignments
from .models import AzureRoleAssignment

_PAGE = 1000

_log = logging.getLogger("spyglass.rbac")

# A bare role-definition GUID is what `transform_assignments` leaves as the
# `roleName` when the ARG role-definition join did not resolve it — used to find
# the assignments that still need a name backfilled from ARM.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Role assignments held by the selected principals, with the raw fields the
# transform expects. `{principals}` is substituted with the OData-escaped,
# comma-separated id list. `order by id` gives a stable total order so the
# skip-token-paged result is repeatable (and the role-name "first wins" dedup is
# deterministic) across runs.
_ASSIGNMENTS_QUERY = """
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId)
| where principalId in~ ({principals})
| order by id asc
| project
    id,
    principalId,
    roleDefinitionId = tostring(properties.roleDefinitionId),
    scope = tostring(properties.scope),
    subscriptionId
"""

# Every role definition in reach. This is unfiltered, so it routinely exceeds
# the 1000-record page — built-in roles repeat once per subscription. The
# transform de-duplicates by trailing GUID so they do not fan out rows.
_ROLE_DEFINITIONS_QUERY = """
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| order by id asc
| project id, roleName = tostring(properties.roleName)
"""

# Subscription display names, joined in by id for friendly scope labels.
_SUBSCRIPTIONS_QUERY = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| order by subscriptionId asc
| project subscriptionId, subscriptionName = name
"""


def _run_arg_query(query: str, label: str, management_group: str) -> list[dict]:
    """Run one ARG query via `az graph query`, paging until exhausted."""
    rows: list[dict] = []
    skip_token: str | None = None
    page_number = 1
    while True:
        command = [
            "az",
            "graph",
            "query",
            "-q",
            query,
            "--first",
            str(_PAGE),
            "--management-groups",
            management_group,
        ]
        if skip_token:
            command += ["--skip-token", skip_token]
        command += ["-o", "json"]
        _log.debug("az graph query (%s): page %d", label, page_number)
        page_number += 1
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
        payload = json.loads(completed.stdout)
        if isinstance(payload, dict):
            rows.extend(payload.get("data", []))
            skip_token = payload.get("skip_token")
        else:  # defensive: a bare array carries no continuation token
            rows.extend(payload)
            skip_token = None
        if not skip_token:
            break
    return rows


def _resolve_role_names_via_arm(guids: set[str]) -> dict[str, str]:
    """Backfill friendly names for role-definition GUIDs ARG left unresolved.

    The unfiltered ARG `authorizationresources` role-definition query does not
    reliably return every built-in role in reach, so an assignment can be left
    showing the raw role-definition GUID. ARM's `az role definition list` is the
    canonical source for built-in roles (whose `name` field *is* the GUID); one
    call resolves them all. Best-effort: any failure leaves the GUID fallback in
    place rather than turning a cosmetic gap into a Run Error.
    """
    if not guids:
        return {}
    try:
        _log.debug("az role definition list (backfilling %d role names)", len(guids))
        completed = subprocess.run(
            ["az", "role", "definition", "list", "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        definitions = json.loads(completed.stdout)
    except (
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        OSError,
        ValueError,
    ) as exc:
        _log.warning("role-name backfill via ARM failed: %s", exc)
        return {}

    resolved: dict[str, str] = {}
    for definition in definitions:
        # ARM keys built-in role definitions by GUID in the `name` field.
        guid = definition.get("name")
        role_name = definition.get("roleName")
        if guid in guids and role_name:
            resolved[guid] = role_name
    return resolved


def collect_azure_role_assignments(
    object_ids: list[str],
    tenant_id: str,
) -> dict[str, list[AzureRoleAssignment]]:
    """Collect Azure Role Assignments for `object_ids`, keyed by principal id.

    Runs the bounded ARG batch (assignments + role definitions + subscriptions)
    scoped to `tenant_id` — the tenant root management group — so
    management-group-scoped assignments are included, and delegates all
    row-level logic to `transform_assignments`. Any role name the ARG join
    could not resolve (left as a bare GUID) is backfilled from ARM via
    `az role definition list`, so built-in roles still surface a friendly name.
    """
    if not object_ids:
        return {}
    if not tenant_id:
        raise ValueError("tenant_id is required to scope the ARG queries")
    quoted = ("'" + oid.replace("'", "''") + "'" for oid in object_ids)
    principals = ", ".join(quoted)
    assignment_rows = _run_arg_query(
        _ASSIGNMENTS_QUERY.format(principals=principals), "role assignments", tenant_id
    )
    role_definition_rows = _run_arg_query(
        _ROLE_DEFINITIONS_QUERY, "role definitions", tenant_id
    )
    subscription_rows = _run_arg_query(_SUBSCRIPTIONS_QUERY, "subscriptions", tenant_id)
    by_principal = transform_assignments(
        assignment_rows, role_definition_rows, subscription_rows
    )

    unresolved = {
        assignment["roleName"]
        for assignments in by_principal.values()
        for assignment in assignments
        if _GUID_RE.match(assignment["roleName"])
    }
    backfill = _resolve_role_names_via_arm(unresolved)
    if backfill:
        for assignments in by_principal.values():
            for assignment in assignments:
                name = backfill.get(assignment["roleName"])
                if name is not None:
                    assignment["roleName"] = name
    return by_principal


async def collect_azure_rbac(
    object_ids: list[str],
    tenant_id: str,
) -> dict[str, list[AzureRoleAssignment]]:
    """Async wrapper: run the sync ARG collector off the event loop thread."""
    return await asyncio.to_thread(
        collect_azure_role_assignments, object_ids, tenant_id
    )
