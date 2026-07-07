"""Tests for the Audit Report envelope: shape, sort, and meta keys."""

from __future__ import annotations

from spyglass.models import Selection, ServicePrincipalRecord
from spyglass.report import build_report

GENERATED_AT = "2026-05-31T00:00:00+00:00"
SELECTION: Selection = {"objectIds": ["oid-1"]}


def _record(display_name: str | None, object_id: str = "oid") -> ServicePrincipalRecord:
    return {
        "objectId": object_id,
        "appId": None,
        "displayName": display_name,
        "tags": [],
        "application": None,
        "azureRoleAssignments": [],
        "groupMemberships": [],
        "directoryRoles": [],
        "credentials": [],
        "applicationPermissions": [],
        "delegatedPermissions": [],
        "owners": [],
        "errors": [],
        "retrievedAt": {},
    }


def test_envelope_shape_is_object_with_meta_and_service_principals() -> None:
    report = build_report(
        [_record("only")],
        tenant_id="tenant-abc",
        selection=SELECTION,
        generated_at=GENERATED_AT,
    )

    assert set(report.keys()) == {"meta", "servicePrincipals"}
    assert isinstance(report["servicePrincipals"], list)
    assert len(report["servicePrincipals"]) == 1


def test_meta_carries_expected_keys_and_no_signed_in_user() -> None:
    report = build_report(
        [],
        tenant_id="tenant-abc",
        selection=SELECTION,
        generated_at=GENERATED_AT,
    )
    meta = report["meta"]

    assert set(meta.keys()) == {
        "generatedAt",
        "tenantId",
        "selection",
        "toolVersion",
        "runErrors",
    }
    assert "signedInUser" not in meta
    assert meta["tenantId"] == "tenant-abc"
    assert meta["generatedAt"] == GENERATED_AT
    assert meta["selection"] == SELECTION
    assert meta["runErrors"] == []
    assert meta["toolVersion"]


def test_service_principals_sorted_by_display_name_case_insensitive() -> None:
    records = [
        _record("zebra", "oid-z"),
        _record("Alpha", "oid-a"),
        _record("mango", "oid-m"),
    ]
    report = build_report(
        records,
        tenant_id="t",
        selection=SELECTION,
        generated_at=GENERATED_AT,
    )

    names = [sp["displayName"] for sp in report["servicePrincipals"]]
    assert names == ["Alpha", "mango", "zebra"]


def test_none_display_name_sorts_first_and_does_not_crash() -> None:
    records = [_record("beta", "oid-b"), _record(None, "oid-none")]
    report = build_report(
        records,
        tenant_id="t",
        selection=SELECTION,
        generated_at=GENERATED_AT,
    )

    assert report["servicePrincipals"][0]["displayName"] is None


def test_run_errors_passthrough() -> None:
    report = build_report(
        [],
        tenant_id="t",
        selection=SELECTION,
        generated_at=GENERATED_AT,
        run_errors=["the sky fell"],
    )
    assert report["meta"]["runErrors"] == ["the sky fell"]
