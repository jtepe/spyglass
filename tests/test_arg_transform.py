"""Tests for the pure Azure RBAC row transforms (no `az` subprocess).

Covers the two lifted bug fixes: scope classification by prefix (adding the
"Management Group" scopeType + parsed `managementGroupId`) and GUID-normalized,
de-duplicated role-name resolution with a deleted-role GUID fallback.
"""

from __future__ import annotations

from spyglass.arg_transform import classify_scope, transform_assignments

CONTRIBUTOR_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"


def test_management_group_scope_classifies_and_parses_id() -> None:
    scope = "/providers/Microsoft.Management/managementGroups/contoso-root"

    scope_type, mg_id = classify_scope(scope)

    assert scope_type == "Management Group"
    assert mg_id == "contoso-root"


def test_subscription_resource_group_and_resource_scopes_classify() -> None:
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    rg = f"{sub}/resourceGroups/my-rg"
    resource = f"{rg}/providers/Microsoft.Storage/storageAccounts/mystore"

    assert classify_scope(sub) == ("Subscription", None)
    assert classify_scope(rg) == ("Resource Group", None)
    assert classify_scope(resource) == ("Resource", None)


def test_role_name_resolves_via_trailing_guid_across_scopes() -> None:
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    assignment_rows = [
        {
            "principalId": "sp-1",
            # roleDefinitionId carried on the assignment is scoped to the sub.
            "roleDefinitionId": (
                f"{sub}/providers/Microsoft.Authorization/"
                f"roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "scope": sub,
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
        }
    ]
    role_definition_rows = [
        {
            # The role definition is published at a different (tenant) scope, so
            # the full ids never match — only the trailing GUID does.
            "id": (
                f"/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "roleName": "Contributor",
        }
    ]

    by_principal = transform_assignments(assignment_rows, role_definition_rows, [])

    assert [a["roleName"] for a in by_principal["sp-1"]] == ["Contributor"]


def test_duplicate_role_definitions_do_not_fan_out_assignments() -> None:
    sub_a = "/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assignment_rows = [
        {
            "principalId": "sp-1",
            "roleDefinitionId": (
                f"{sub_a}/providers/Microsoft.Authorization/"
                f"roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "scope": sub_a,
            "subscriptionId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        }
    ]
    # The same built-in role appears once per subscription in ARG.
    role_definition_rows = [
        {
            "id": (
                f"{sub_a}/providers/Microsoft.Authorization/"
                f"roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "roleName": "Contributor",
        },
        {
            "id": (
                "/subscriptions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
                "/providers/Microsoft.Authorization/"
                f"roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "roleName": "Contributor",
        },
    ]

    by_principal = transform_assignments(assignment_rows, role_definition_rows, [])

    # One assignment in, one assignment out — duplicates must not multiply rows.
    assert len(by_principal["sp-1"]) == 1
    assert by_principal["sp-1"][0]["roleName"] == "Contributor"


def test_deleted_role_falls_back_to_guid() -> None:
    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    assignment_rows = [
        {
            "principalId": "sp-1",
            "roleDefinitionId": (
                f"{sub}/providers/Microsoft.Authorization/"
                "roleDefinitions/deadbeef-0000-0000-0000-000000000000"
            ),
            "scope": sub,
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
        }
    ]

    by_principal = transform_assignments(assignment_rows, [], [])

    assert by_principal["sp-1"][0]["roleName"] == (
        "deadbeef-0000-0000-0000-000000000000"
    )


def test_duplicate_assignment_rows_deduplicate_by_id() -> None:
    scope = "/providers/Microsoft.Management/managementGroups/contoso-root"
    row = {
        "id": (
            f"{scope}/providers/Microsoft.Authorization/"
            "roleAssignments/11111111-1111-1111-1111-111111111111"
        ),
        "principalId": "sp-1",
        "roleDefinitionId": (
            f"/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR_GUID}"
        ),
        "scope": scope,
        "subscriptionId": "",
    }
    assignment_rows = [row, dict(row, subscriptionId="s")]

    by_principal = transform_assignments(assignment_rows, [], [])

    assert len(by_principal["sp-1"]) == 1


def test_management_group_assignment_carries_parsed_id_and_no_subscription() -> None:
    scope = "/providers/Microsoft.Management/managementGroups/contoso-root"
    assignment_rows = [
        {
            "principalId": "sp-1",
            "roleDefinitionId": (
                f"{scope}/providers/Microsoft.Authorization/"
                f"roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "scope": scope,
            "subscriptionId": "",
        }
    ]
    role_definition_rows = [
        {
            "id": (
                f"/providers/Microsoft.Authorization/roleDefinitions/{CONTRIBUTOR_GUID}"
            ),
            "roleName": "Contributor",
        }
    ]

    assignment = transform_assignments(assignment_rows, role_definition_rows, [])[
        "sp-1"
    ][0]

    assert assignment["scopeType"] == "Management Group"
    assert assignment["managementGroupId"] == "contoso-root"
    assert assignment["subscriptionId"] is None
    assert assignment["subscriptionName"] is None
