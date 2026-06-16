"""Tests for PIM-for-Groups membership annotation (pure, no Graph client)."""

from __future__ import annotations

from msgraph.generated.models.privileged_access_group_assignment_schedule import (
    PrivilegedAccessGroupAssignmentSchedule,
)
from msgraph.generated.models.privileged_access_group_relationships import (
    PrivilegedAccessGroupRelationships,
)

from spyglass.entra import apply_pim_membership
from spyglass.models import GroupMembershipRecord


def _membership(
    group_id: str, is_assignable_to_role: bool | None = True
) -> GroupMembershipRecord:
    return {
        "groupId": group_id,
        "displayName": f"group-{group_id}",
        "membershipType": "transitive",
        "isAssignableToRole": is_assignable_to_role,
        "pimMembership": None,
    }


def test_active_member_schedule_marks_group_assigned() -> None:
    memberships = [_membership("g-1")]
    active = [
        PrivilegedAccessGroupAssignmentSchedule(
            group_id="g-1", access_id=PrivilegedAccessGroupRelationships.Member
        )
    ]

    result = apply_pim_membership(memberships, active)

    assert result[0]["pimMembership"] == "assigned"


def test_role_assignable_group_with_no_schedule_is_none() -> None:
    result = apply_pim_membership([_membership("g-1")], [])

    assert result[0]["pimMembership"] == "none"


def test_owner_access_is_ignored() -> None:
    memberships = [_membership("g-1")]
    active = [
        PrivilegedAccessGroupAssignmentSchedule(
            group_id="g-1", access_id=PrivilegedAccessGroupRelationships.Owner
        )
    ]

    result = apply_pim_membership(memberships, active)

    assert result[0]["pimMembership"] == "none"


def test_non_role_assignable_group_is_left_unset() -> None:
    memberships = [_membership("g-1", is_assignable_to_role=False)]
    active = [
        PrivilegedAccessGroupAssignmentSchedule(
            group_id="g-1", access_id=PrivilegedAccessGroupRelationships.Member
        )
    ]

    result = apply_pim_membership(memberships, active)

    assert result[0]["pimMembership"] is None


def test_inputs_are_not_mutated() -> None:
    memberships = [_membership("g-1")]
    active = [
        PrivilegedAccessGroupAssignmentSchedule(
            group_id="g-1", access_id=PrivilegedAccessGroupRelationships.Member
        )
    ]

    apply_pim_membership(memberships, active)

    assert memberships[0]["pimMembership"] is None
