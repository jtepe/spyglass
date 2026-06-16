"""Tests for the pure `render` module: report dict -> self-contained HTML.

These exercise the public `render()` interface only — given a sample Audit
Report, assert observable facts about the produced HTML string. They never
reach into private helpers or the exact markup, beyond the security-relevant
guarantees the report calls out (self-containment, expired-credential flagging,
the Management Group scope bucket, and injection-safe escaping).
"""

from __future__ import annotations

from typing import Any, cast

from spyglass.models import AuditReport
from spyglass.render import render


def _report(*, sp: dict[str, Any] | None = None) -> AuditReport:
    """A minimal but realistic single-SP Audit Report envelope.

    `sp` overrides merge into the baseline Service Principal record so each test
    can vary just the section it exercises.
    """
    sp_record: dict[str, Any] = {
        "objectId": "obj-1",
        "appId": "app-1",
        "displayName": "infra-terraform-sp",
        "tags": ["terraform-iac"],
        "application": {
            "objectId": "app-obj-1",
            "appId": "app-1",
            "displayName": "infra-terraform",
        },
        "azureRoleAssignments": [],
        "groupMemberships": [],
        "directoryRoles": [],
        "credentials": [],
        "applicationPermissions": [],
        "delegatedPermissions": [],
        "owners": [],
        "errors": [],
    }
    if sp:
        sp_record.update(sp)
    report: dict[str, Any] = {
        "meta": {
            "generatedAt": "2026-06-07T12:00:00+00:00",
            "tenantId": "tenant-xyz",
            "selection": {"objectIds": ["obj-1"], "tag": "terraform-iac"},
            "toolVersion": "0.1.0",
            "runErrors": [],
        },
        "servicePrincipals": [sp_record],
    }
    return cast(AuditReport, report)


def test_render_returns_self_contained_html_document() -> None:
    out = render(_report())

    assert out.lstrip().startswith("<!DOCTYPE html>")
    assert "<html" in out and "</html>" in out
    # Styling and behaviour are embedded, not linked out.
    assert "<style>" in out
    # The audited SP's display name appears in the rendered body.
    assert "infra-terraform-sp" in out


def test_script_injection_in_a_field_is_escaped() -> None:
    payload = "</script><script>alert('xss')</script>"
    out = render(_report(sp={"displayName": payload}))

    # The raw closing/opening tags must never appear unescaped in the output.
    assert "<script>alert(" not in out
    assert "</script><script>" not in out
    # The escaped form is present instead.
    assert "&lt;script&gt;alert(" in out


def test_output_has_no_external_asset_references() -> None:
    out = render(_report())

    assert "http://" not in out
    assert "https://" not in out
    assert "<link" not in out
    assert "src=" not in out


def test_expired_credential_is_visibly_flagged() -> None:
    creds = [
        {
            "owner": "application",
            "credentialType": "secret",
            "displayName": "ci-secret",
            "keyId": "key-expired",
            "startDateTime": "2020-01-01T00:00:00Z",
            "endDateTime": "2021-01-01T00:00:00Z",
            "status": "expired",
        },
        {
            "owner": "servicePrincipal",
            "credentialType": "certificate",
            "displayName": "live-cert",
            "keyId": "key-active",
            "startDateTime": "2025-01-01T00:00:00Z",
            "endDateTime": "2030-01-01T00:00:00Z",
            "status": "active",
        },
    ]
    out = render(_report(sp={"credentials": creds}))

    # Both credentials are shown by name...
    assert "ci-secret" in out
    assert "live-cert" in out
    # ...and the expired one carries a distinguishing status marker the active
    # one does not (a status class plus a visible "expired" label).
    assert "status-expired" in out
    assert "status-active" in out


def test_management_group_assignments_render_in_a_distinct_bucket() -> None:
    assignments = [
        {
            "roleName": "Reader",
            "scopeType": "Management Group",
            "scope": "/providers/Microsoft.Management/managementGroups/root-mg",
            "subscriptionId": None,
            "subscriptionName": None,
            "managementGroupId": "root-mg",
        },
        {
            "roleName": "Contributor",
            "scopeType": "Subscription",
            "scope": "/subscriptions/sub-1",
            "subscriptionId": "sub-1",
            "subscriptionName": "Production Sub",
            "managementGroupId": None,
        },
    ]
    out = render(_report(sp={"azureRoleAssignments": assignments}))

    # The MG-scoped assignment is bucketed under a Management Group heading with
    # its parsed id, not folded under a subscription.
    assert "scope-bucket-management-group" in out
    assert "root-mg" in out
    # The subscription bucket is rendered separately by its subscription name.
    assert "Production Sub" in out
    # Both roles are present.
    assert "Reader" in out
    assert "Contributor" in out


def test_directory_roles_are_foregrounded_with_source_and_type() -> None:
    roles = [
        {
            "roleName": "Global Reader",
            "assignmentType": "active",
            "source": "direct",
            "sourceGroupId": None,
            "directoryScopeId": "/",
            "startDateTime": None,
            "endDateTime": None,
        },
        {
            "roleName": "Application Administrator",
            "assignmentType": "active",
            "source": "iac-admins",
            "sourceGroupId": "grp-1",
            "directoryScopeId": "/",
            "startDateTime": None,
            "endDateTime": None,
        },
    ]
    out = render(_report(sp={"directoryRoles": roles}))

    assert "Global Reader" in out
    assert "Application Administrator" in out
    # The via-group attribution source and the assignment type are both shown.
    assert "iac-admins" in out
    assert "active" in out


def test_meta_header_and_run_errors_are_shown() -> None:
    report = _report()
    report["meta"]["runErrors"] = ["Azure RBAC query failed: boom"]
    out = render(report)

    # Meta facts surface in a header.
    assert "tenant-xyz" in out
    assert "2026-06-07T12:00:00+00:00" in out
    # The run error is rendered, not silently dropped.
    assert "Azure RBAC query failed: boom" in out
    assert "run-error" in out


def test_per_sp_errors_are_shown() -> None:
    out = render(_report(sp={"errors": ["PIM call returned 403"]}))

    assert "PIM call returned 403" in out
    assert "sp-error" in out


def test_long_tail_sections_render_as_collapsible_raw_json() -> None:
    out = render(
        _report(
            sp={
                "groupMemberships": [
                    {
                        "groupId": "grp-9",
                        "displayName": "platform-admins",
                        "membershipType": "transitive",
                        "isAssignableToRole": True,
                        "pimMembership": "assigned",
                    }
                ],
                "owners": [
                    {
                        "owner": "servicePrincipal",
                        "ownerType": "servicePrincipal",
                        "id": "owner-sp-1",
                        "displayName": "deployer-sp",
                    }
                ],
            }
        )
    )

    # Long-tail data is in collapsible <details> blocks...
    assert "<details" in out
    assert "</details>" in out
    # ...carrying the raw JSON of those sections.
    assert "platform-admins" in out
    assert "deployer-sp" in out


def test_display_name_filter_is_present_and_wired() -> None:
    out = render(_report())

    # A search box exists and the SP carries a filterable data-name.
    assert 'id="search"' in out
    assert 'data-name="infra-terraform-sp"' in out
    # The filter behaviour is embedded (the script reads data-name), not linked.
    assert "<script>" in out
    assert "data-name" in out
