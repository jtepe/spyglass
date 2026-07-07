"""Tests for the SQLite run store: schema lifecycle and snapshot round-trips."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from spyglass.models import AuditReport, ServicePrincipalRecord
from spyglass.store import SCHEMA_VERSION, StoreError, persist_report

GENERATED_AT = "2026-07-07T10:00:00+00:00"


def _record(object_id: str = "oid-1") -> ServicePrincipalRecord:
    return {
        "objectId": object_id,
        "appId": "app-1",
        "displayName": "infra-terraform-sp",
        "tags": ["terraform-iac"],
        "application": {
            "objectId": "app-obj-1",
            "appId": "app-1",
            "displayName": "infra-terraform",
        },
        "azureRoleAssignments": [
            {
                "roleName": "Reader",
                "scopeType": "Subscription",
                "scope": "/subscriptions/sub-1",
                "subscriptionId": "sub-1",
                "subscriptionName": "prod",
                "managementGroupId": None,
            }
        ],
        "groupMemberships": [
            {
                "groupId": "g-1",
                "displayName": "admins",
                "membershipType": "direct",
                "isAssignableToRole": True,
                "pimMembership": "assigned",
            }
        ],
        "directoryRoles": [
            {
                "roleName": "Global Reader",
                "assignmentType": "active",
                "source": "direct",
                "sourceGroupId": None,
                "directoryScopeId": "/",
                "startDateTime": None,
                "endDateTime": None,
            }
        ],
        "credentials": [
            {
                "owner": "servicePrincipal",
                "credentialType": "secret",
                "displayName": "sp secret",
                "keyId": "key-sp",
                "startDateTime": None,
                "endDateTime": None,
                "status": "active",
            },
            {
                "owner": "application",
                "credentialType": "certificate",
                "displayName": "app cert",
                "keyId": "key-app",
                "startDateTime": None,
                "endDateTime": None,
                "status": "expired",
            },
        ],
        "applicationPermissions": [
            {
                "resourceId": "res-1",
                "resourceDisplayName": "Microsoft Graph",
                "appRoleId": "role-1",
                "permission": "Directory.Read.All",
            }
        ],
        "delegatedPermissions": [
            {
                "resourceId": "res-1",
                "resourceDisplayName": "Microsoft Graph",
                "scopes": ["User.Read", "Mail.Read"],
                "consentType": "AllPrincipals",
                "principalId": None,
            }
        ],
        "owners": [
            {
                "owner": "servicePrincipal",
                "ownerType": "user",
                "id": "user-1",
                "displayName": "Jane Admin",
            }
        ],
        "errors": ["Failed to collect API permissions: HTTP 403"],
        "retrievedAt": {
            "servicePrincipal": "2026-07-07T10:00:01+00:00",
            "application": "2026-07-07T10:00:02+00:00",
            "owners": "2026-07-07T10:00:03+00:00",
            "groupMemberships": "2026-07-07T10:00:04+00:00",
            "pimForGroups": "2026-07-07T10:00:05+00:00",
            "directoryRoles": "2026-07-07T10:00:06+00:00",
            "applicationPermissions": "2026-07-07T10:00:07+00:00",
            "delegatedPermissions": "2026-07-07T10:00:08+00:00",
            "azureRoleAssignments": "2026-07-07T10:00:09+00:00",
        },
    }


def _report(records: list[ServicePrincipalRecord]) -> AuditReport:
    return {
        "meta": {
            "generatedAt": GENERATED_AT,
            "tenantId": "tenant-xyz",
            "selection": {"objectIds": [r["objectId"] for r in records]},
            "toolVersion": "0.1.0",
            "runErrors": ["Azure RBAC query failed: boom"],
        },
        "servicePrincipals": records,
    }


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


def test_persist_creates_schema_and_returns_run_id(tmp_path: Path) -> None:
    db = tmp_path / "runs.db"

    run_id = persist_report(str(db), _report([_record()]))

    assert run_id == 1
    with _connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        run = conn.execute("SELECT * FROM runs").fetchone()
        assert run["generated_at"] == GENERATED_AT
        assert run["tenant_id"] == "tenant-xyz"
        assert run["selection_tag"] is None
        assert json.loads(run["selection_object_ids"]) == ["oid-1"]
        errors = conn.execute("SELECT message FROM run_errors").fetchall()
        assert [e["message"] for e in errors] == ["Azure RBAC query failed: boom"]


def test_snapshot_round_trip_stores_all_sections_with_their_stamps(
    tmp_path: Path,
) -> None:
    db = tmp_path / "runs.db"
    persist_report(str(db), _report([_record()]))

    with _connect(db) as conn:
        sp = conn.execute("SELECT * FROM service_principals").fetchone()
        assert sp["object_id"] == "oid-1"
        assert sp["application_present"] == 1
        assert sp["application_display_name"] == "infra-terraform"
        assert json.loads(sp["tags"]) == ["terraform-iac"]

        sections = dict(
            conn.execute("SELECT section, retrieved_at FROM sp_sections").fetchall()
        )
        assert sections["owners"] == "2026-07-07T10:00:03+00:00"
        assert len(sections) == 9

        ra = conn.execute("SELECT * FROM azure_role_assignments").fetchone()
        assert ra["role_name"] == "Reader"
        assert ra["retrieved_at"] == "2026-07-07T10:00:09+00:00"

        dr = conn.execute("SELECT * FROM directory_roles").fetchone()
        assert dr["role_name"] == "Global Reader"
        assert dr["retrieved_at"] == "2026-07-07T10:00:06+00:00"

        gm = conn.execute("SELECT * FROM group_memberships").fetchone()
        assert gm["is_assignable_to_role"] == 1
        assert gm["pim_membership"] == "assigned"
        assert gm["retrieved_at"] == "2026-07-07T10:00:04+00:00"

        # Credential stamps split by which object carried them.
        creds = {
            row["owner"]: row["retrieved_at"]
            for row in conn.execute("SELECT owner, retrieved_at FROM credentials")
        }
        assert creds["servicePrincipal"] == "2026-07-07T10:00:01+00:00"
        assert creds["application"] == "2026-07-07T10:00:02+00:00"

        dp = conn.execute("SELECT * FROM delegated_permissions").fetchone()
        assert json.loads(dp["scopes"]) == ["User.Read", "Mail.Read"]

        owner = conn.execute("SELECT * FROM owners").fetchone()
        assert owner["principal_id"] == "user-1"
        assert owner["retrieved_at"] == "2026-07-07T10:00:03+00:00"

        errors = conn.execute("SELECT message FROM sp_errors").fetchall()
        assert [e["message"] for e in errors] == [
            "Failed to collect API permissions: HTTP 403"
        ]


def test_unstamped_sections_fall_back_to_generated_at_and_are_not_observed(
    tmp_path: Path,
) -> None:
    """A record without stamps (legacy JSON) persists with run-level times."""
    db = tmp_path / "runs.db"
    record = _record()
    record["retrievedAt"] = {}

    persist_report(str(db), _report([record]))

    with _connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM sp_sections").fetchone()[0] == 0
        ra = conn.execute("SELECT retrieved_at FROM azure_role_assignments").fetchone()
        assert ra["retrieved_at"] == GENERATED_AT


def test_runs_append_and_never_overwrite(tmp_path: Path) -> None:
    db = tmp_path / "runs.db"

    first = persist_report(str(db), _report([_record()]))
    second = persist_report(str(db), _report([_record()]))

    assert (first, second) == (1, 2)
    with _connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 2
        assert (
            conn.execute("SELECT COUNT(*) FROM service_principals").fetchone()[0] == 2
        )


def test_selection_tag_is_stored(tmp_path: Path) -> None:
    db = tmp_path / "runs.db"
    report = _report([_record()])
    report["meta"]["selection"] = {"objectIds": ["oid-1"], "tag": "terraform-iac"}

    persist_report(str(db), report)

    with _connect(db) as conn:
        assert (
            conn.execute("SELECT selection_tag FROM runs").fetchone()[0]
            == "terraform-iac"
        )


def test_newer_schema_version_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "runs.db"
    with sqlite3.connect(db) as conn:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")

    with pytest.raises(StoreError, match="schema version"):
        persist_report(str(db), _report([_record()]))


def test_foreign_non_empty_database_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "other.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE unrelated (x)")

    with pytest.raises(StoreError, match="foreign database"):
        persist_report(str(db), _report([_record()]))
