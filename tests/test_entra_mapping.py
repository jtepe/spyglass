"""Tests for the object-id -> record mapping (pure, no Graph client)."""

from __future__ import annotations

import datetime
import uuid

from msgraph.generated.models.app_role import AppRole
from msgraph.generated.models.app_role_assignment import AppRoleAssignment
from msgraph.generated.models.application import Application
from msgraph.generated.models.expiration_pattern import ExpirationPattern
from msgraph.generated.models.group import Group
from msgraph.generated.models.o_auth2_permission_grant import OAuth2PermissionGrant
from msgraph.generated.models.request_schedule import RequestSchedule
from msgraph.generated.models.service_principal import ServicePrincipal
from msgraph.generated.models.unified_role_assignment_schedule import (
    UnifiedRoleAssignmentSchedule,
)
from msgraph.generated.models.unified_role_definition import UnifiedRoleDefinition
from msgraph.generated.models.user import User

from spyglass.entra import (
    app_role_value_map,
    application_permission_from_graph,
    application_record_from_graph,
    delegated_permission_from_graph,
    directory_role_from_schedule,
    group_membership_from_graph,
    owner_from_graph,
    resolve_app_role_value,
    sp_record_from_graph,
)


def test_group_membership_mapping_labels_membership_type() -> None:
    group = Group(
        id="g-1",
        display_name="role-assignable-group",
        is_assignable_to_role=True,
    )

    assert group_membership_from_graph(group, "direct") == {
        "groupId": "g-1",
        "displayName": "role-assignable-group",
        "membershipType": "direct",
        "isAssignableToRole": True,
        "pimMembership": None,
    }
    assert group_membership_from_graph(group, "transitive")["membershipType"] == (
        "transitive"
    )


def test_sp_record_carries_identity_tags_and_null_application() -> None:
    sp = ServicePrincipal(
        id="22222222-2222-2222-2222-222222222222",
        app_id="11111111-1111-1111-1111-111111111111",
        display_name="app-frontend-sp",
        tags=["terraform-iac", "prod"],
    )

    record = sp_record_from_graph(sp, None)

    assert record == {
        "objectId": "22222222-2222-2222-2222-222222222222",
        "appId": "11111111-1111-1111-1111-111111111111",
        "displayName": "app-frontend-sp",
        "tags": ["terraform-iac", "prod"],
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


def test_sp_record_attaches_application_when_present() -> None:
    sp = ServicePrincipal(
        id="oid",
        app_id="aid",
        display_name="sp",
        tags=None,
    )
    app = Application(id="app-oid", app_id="aid", display_name="my-app-registration")

    record = sp_record_from_graph(sp, app)

    assert record["tags"] == []  # None tags degrade to empty list
    assert record["application"] == {
        "objectId": "app-oid",
        "appId": "aid",
        "displayName": "my-app-registration",
    }


def test_application_record_mapping() -> None:
    app = Application(id="app-oid", app_id="aid", display_name="name")
    assert application_record_from_graph(app) == {
        "objectId": "app-oid",
        "appId": "aid",
        "displayName": "name",
    }


def test_directory_role_mapping_extracts_raw_facts() -> None:
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    end = datetime.datetime(2027, 1, 1, tzinfo=datetime.UTC)
    schedule = UnifiedRoleAssignmentSchedule(
        role_definition=UnifiedRoleDefinition(display_name="Global Reader"),
        directory_scope_id="/",
        schedule_info=RequestSchedule(
            start_date_time=start,
            expiration=ExpirationPattern(end_date_time=end),
        ),
    )

    assert directory_role_from_schedule(schedule, "direct", None) == {
        "roleName": "Global Reader",
        "assignmentType": "active",
        "source": "direct",
        "sourceGroupId": None,
        "directoryScopeId": "/",
        "startDateTime": start.isoformat(),
        "endDateTime": end.isoformat(),
    }


def test_directory_role_mapping_tolerates_missing_role_definition_and_dates() -> None:
    schedule = UnifiedRoleAssignmentSchedule(
        role_definition=None,
        directory_scope_id=None,
        schedule_info=RequestSchedule(start_date_time=None, expiration=None),
    )

    assert directory_role_from_schedule(schedule, "finance-admins", "g-1") == {
        "roleName": None,
        "assignmentType": "active",
        "source": "finance-admins",
        "sourceGroupId": "g-1",
        "directoryScopeId": None,
        "startDateTime": None,
        "endDateTime": None,
    }


def test_sp_without_object_id_is_rejected() -> None:
    sp = ServicePrincipal(id=None, app_id="aid", display_name="sp")
    try:
        sp_record_from_graph(sp, None)
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for missing object id")


def test_delegated_permission_mapping_splits_scopes() -> None:
    grant = OAuth2PermissionGrant(
        resource_id="res-1",
        scope="User.Read Mail.Read   Files.Read.All",
        consent_type="Principal",
        principal_id="user-1",
    )

    assert delegated_permission_from_graph(grant, "Microsoft Graph") == {
        "resourceId": "res-1",
        "resourceDisplayName": "Microsoft Graph",
        "scopes": ["User.Read", "Mail.Read", "Files.Read.All"],
        "consentType": "Principal",
        "principalId": "user-1",
    }


def test_delegated_permission_mapping_tolerates_missing_scope() -> None:
    grant = OAuth2PermissionGrant(
        resource_id="res-1", scope=None, consent_type="AllPrincipals"
    )

    record = delegated_permission_from_graph(grant, None)

    assert record["scopes"] == []
    assert record["consentType"] == "AllPrincipals"
    assert record["principalId"] is None


def test_app_role_value_map_keeps_enabled_named_roles() -> None:
    sp = ServicePrincipal(
        app_roles=[
            AppRole(
                id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
                value="User.Read.All",
            ),
            AppRole(
                id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000002"),
                value="Mail.Read",
            ),
        ]
    )

    assert app_role_value_map(sp) == {
        "aaaaaaaa-0000-0000-0000-000000000001": "User.Read.All",
        "aaaaaaaa-0000-0000-0000-000000000002": "Mail.Read",
    }


def test_resolve_app_role_value_resolves_named_role() -> None:
    role_id = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
    roles = {"aaaaaaaa-0000-0000-0000-000000000001": "User.Read.All"}

    assert resolve_app_role_value(role_id, roles) == "User.Read.All"


def test_resolve_app_role_value_handles_default_access_guid() -> None:
    zero = uuid.UUID("00000000-0000-0000-0000-000000000000")

    assert resolve_app_role_value(zero, {}) == "default access"


def test_resolve_app_role_value_unknown_guid_is_none() -> None:
    role_id = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000009")

    assert resolve_app_role_value(role_id, {}) is None


def test_owner_mapping_tags_a_human_owner_of_the_service_principal() -> None:
    owner = User(id="u-1", display_name="Ada Lovelace")

    assert owner_from_graph(owner, "servicePrincipal") == {
        "owner": "servicePrincipal",
        "ownerType": "user",
        "id": "u-1",
        "displayName": "Ada Lovelace",
    }


def test_owner_mapping_surfaces_sp_owns_application_privilege_chain() -> None:
    owner = ServicePrincipal(id="sp-9", display_name="deploy-pipeline-sp")

    assert owner_from_graph(owner, "application") == {
        "owner": "application",
        "ownerType": "servicePrincipal",
        "id": "sp-9",
        "displayName": "deploy-pipeline-sp",
    }


def test_owner_mapping_recognises_a_group_owner() -> None:
    owner = Group(id="g-3", display_name="platform-admins")

    record = owner_from_graph(owner, "servicePrincipal")

    assert record["ownerType"] == "group"
    assert record["id"] == "g-3"


def test_application_permission_mapping_carries_resolved_value() -> None:
    assignment = AppRoleAssignment(
        resource_id=uuid.UUID("cccccccc-0000-0000-0000-000000000001"),
        app_role_id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
    )

    assert application_permission_from_graph(
        assignment, "Microsoft Graph", "User.Read.All"
    ) == {
        "resourceId": "cccccccc-0000-0000-0000-000000000001",
        "resourceDisplayName": "Microsoft Graph",
        "appRoleId": "aaaaaaaa-0000-0000-0000-000000000001",
        "permission": "User.Read.All",
    }
