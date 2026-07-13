"""Pure transforms over raw Azure Resource Graph (ARG) rows.

All row-level logic for the Azure RBAC plane lives here so it is network-free
and unit-testable without an `az graph query` subprocess.
"""

from __future__ import annotations

from .models import AzureRoleAssignment

_MG_PREFIX = "/providers/Microsoft.Management/managementGroups/"


def _trailing_guid(resource_id: str) -> str:
    """Normalize a role-definition resource id to its trailing GUID segment."""
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def classify_scope(scope: str) -> tuple[str, str | None]:
    """Classify an Azure RBAC scope and parse a management-group id.

    Returns `(scopeType, managementGroupId)`. `managementGroupId` is the parsed
    id for a Management Group scope and `None` for every other scope type.
    """
    if scope.startswith(_MG_PREFIX):
        return "Management Group", scope[len(_MG_PREFIX) :].split("/")[0]
    segments = scope.split("/")
    if len(segments) == 3:
        return "Subscription", None
    if len(segments) == 5:
        return "Resource Group", None
    return "Resource", None


def transform_assignments(
    assignment_rows: list[dict],
    role_definition_rows: list[dict],
    subscription_rows: list[dict],
) -> dict[str, list[AzureRoleAssignment]]:
    """Transform raw ARG rows into per-principal Azure Role Assignments.

    `assignment_rows` carry `principalId`, `roleDefinitionId`, `scope`, and
    `subscriptionId`, plus an optional `id` used to de-duplicate rows a
    management-group-scoped ARG query can return once per subscription context.
    `role_definition_rows` carry the role definition `id` and `roleName`.
    `subscription_rows` carry `subscriptionId` and `subscriptionName`.
    """
    role_names: dict[str, str] = {}
    for row in role_definition_rows:
        guid = _trailing_guid(row["id"])
        # First definition wins; de-dup keeps the join from fanning out rows.
        role_names.setdefault(guid, row["roleName"])

    subscription_names: dict[str, str] = {
        row["subscriptionId"]: row["subscriptionName"] for row in subscription_rows
    }

    by_principal: dict[str, list[AzureRoleAssignment]] = {}
    seen_assignment_ids: set[str] = set()
    for row in assignment_rows:
        assignment_id = row.get("id")
        if assignment_id:
            if assignment_id in seen_assignment_ids:
                continue
            seen_assignment_ids.add(assignment_id)
        guid = _trailing_guid(row["roleDefinitionId"])
        scope_type, mg_id = classify_scope(row["scope"])
        subscription_id = None if mg_id is not None else row.get("subscriptionId")
        assignment: AzureRoleAssignment = {
            "roleName": role_names.get(guid, guid),
            "scopeType": scope_type,
            "scope": row["scope"],
            "subscriptionId": subscription_id,
            "subscriptionName": (
                subscription_names.get(subscription_id)
                if subscription_id is not None
                else None
            ),
            "managementGroupId": mg_id,
        }
        by_principal.setdefault(row["principalId"], []).append(assignment)
    return by_principal
