"""Tests for the Azure RBAC collector's pure boundaries (no `az` subprocess)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from spyglass.azure_rbac import collect_azure_role_assignments


def test_empty_selection_makes_no_subprocess_call() -> None:
    # No object ids => nothing to query; must not shell out to `az`.
    assert collect_azure_role_assignments([], "tenant-1") == {}


def test_missing_tenant_id_raises() -> None:
    with pytest.raises(ValueError):
        collect_azure_role_assignments(["sp-1"], "")


def test_run_arg_query_follows_skip_token_across_pages(monkeypatch) -> None:
    from spyglass import azure_rbac

    pages = [
        # First page returns a continuation token...
        '{"data": [{"id": "a"}], "skip_token": "TOK"}',
        # ...second page exhausts it (no skip_token).
        '{"data": [{"id": "b"}], "skip_token": null}',
    ]
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        stdout = pages[len(calls) - 1]
        return SimpleNamespace(stdout=stdout, returncode=0)

    monkeypatch.setattr(azure_rbac.subprocess, "run", fake_run)

    rows = azure_rbac._run_arg_query("Resources", "test", "tenant-1")

    assert rows == [{"id": "a"}, {"id": "b"}]
    # Page one carries no token; page two passes the token from page one.
    assert "--skip-token" not in calls[0]
    assert calls[1][calls[1].index("--skip-token") + 1] == "TOK"


STORAGE_READER_GUID = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"


def test_unresolved_role_guid_is_backfilled_from_arm(monkeypatch) -> None:
    from spyglass import azure_rbac

    sub = "/subscriptions/00000000-0000-0000-0000-000000000000"
    assignment = {
        "principalId": "sp-1",
        "roleDefinitionId": (
            f"{sub}/providers/Microsoft.Authorization/"
            f"roleDefinitions/{STORAGE_READER_GUID}"
        ),
        "scope": f"{sub}/resourceGroups/rg/providers/X/y/z",
        "subscriptionId": "00000000-0000-0000-0000-000000000000",
    }

    def fake_run(command, **kwargs):
        # The ARG batch: assignments resolve, but the role-definition query
        # returns nothing — exactly the gap that leaves a bare GUID behind.
        if "graph" in command:
            query = command[command.index("-q") + 1]
            if "roleassignments" in query:
                data = [assignment]
            else:  # role definitions and subscriptions both come back empty
                data = []
            return SimpleNamespace(stdout=json.dumps({"data": data}), returncode=0)
        # ARM backfill: `az role definition list` keys built-ins by GUID `name`.
        if command[:4] == ["az", "role", "definition", "list"]:
            return SimpleNamespace(
                stdout=json.dumps(
                    [
                        {
                            "name": STORAGE_READER_GUID,
                            "roleName": "Storage File Data SMB Share Reader",
                        }
                    ]
                ),
                returncode=0,
            )
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(azure_rbac.subprocess, "run", fake_run)

    result = azure_rbac.collect_azure_role_assignments(["sp-1"], "tenant-1")

    assert result["sp-1"][0]["roleName"] == "Storage File Data SMB Share Reader"


def test_arm_backfill_failure_keeps_guid_fallback(monkeypatch) -> None:
    from spyglass import azure_rbac

    monkeypatch.setattr(
        azure_rbac,
        "_run_arg_query",
        lambda query, label, management_group: (
            [
                {
                    "principalId": "sp-1",
                    "roleDefinitionId": (
                        "/subscriptions/s/providers/Microsoft.Authorization/"
                        f"roleDefinitions/{STORAGE_READER_GUID}"
                    ),
                    "scope": "/subscriptions/s",
                    "subscriptionId": "s",
                }
            ]
            if "roleassignments" in query
            else []
        ),
    )

    def failing_arm(command, **kwargs):
        raise OSError("az not found")

    monkeypatch.setattr(azure_rbac.subprocess, "run", failing_arm)

    result = azure_rbac.collect_azure_role_assignments(["sp-1"], "tenant-1")

    # ARM unavailable => the bare GUID remains, never an exception.
    assert result["sp-1"][0]["roleName"] == STORAGE_READER_GUID


def test_arg_queries_are_scoped_to_tenant_root_management_group(monkeypatch) -> None:
    from spyglass import azure_rbac

    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "graph" in command:
            return SimpleNamespace(stdout=json.dumps({"data": []}), returncode=0)
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(azure_rbac.subprocess, "run", fake_run)

    azure_rbac.collect_azure_role_assignments(["sp-1"], "tenant-1")

    graph_calls = [c for c in calls if "graph" in c]
    assert len(graph_calls) == 3
    for command in graph_calls:
        assert command[command.index("--management-groups") + 1] == "tenant-1"
