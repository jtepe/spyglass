"""SQLite persistence for Audit Reports: one append-only snapshot per run.

`persist_report` writes a completed Audit Report into a local SQLite database
(created on first use) as a normalized per-run snapshot: a `runs` row plus one
`service_principals` row per audited SP and one row per fact (credential,
role assignment, owner, ...) in the section tables. Runs are only ever
appended — history is the set of snapshots, and change tracking is a query
over them.

Timestamps: every fact row carries the `retrieved_at` of the call that
produced it (falling back to the run's `generated_at` for reports predating
per-section stamps). The `sp_sections` table records which sections were
actually observed in a run — a section absent there was a gap or never ran,
so its facts being absent must not be read as "removed".

The schema is versioned via `PRAGMA user_version`; a database written by a
newer schema is refused rather than misread.
"""

from __future__ import annotations

import json
import sqlite3

from .models import AuditReport, Meta, ServicePrincipalRecord

SCHEMA_VERSION = 1

# Section names as stored in `sp_sections`, matching the `retrievedAt` keys.
SECTIONS = (
    "servicePrincipal",
    "application",
    "owners",
    "groupMemberships",
    "pimForGroups",
    "directoryRoles",
    "applicationPermissions",
    "delegatedPermissions",
    "azureRoleAssignments",
)

_SCHEMA = """
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    generated_at TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    selection_tag TEXT,
    selection_object_ids TEXT NOT NULL  -- JSON array
);

CREATE TABLE run_errors (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (run_id, position)
);

CREATE TABLE service_principals (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    object_id TEXT NOT NULL,
    app_id TEXT,
    display_name TEXT,
    tags TEXT NOT NULL,  -- JSON array
    application_present INTEGER NOT NULL,  -- 0/1: whether `application` was non-null
    application_object_id TEXT,
    application_app_id TEXT,
    application_display_name TEXT,
    UNIQUE (run_id, object_id)
);
CREATE INDEX idx_sp_object_id ON service_principals(object_id);

-- Which sections were actually observed for an SP in a run, and when. A
-- section with no row here was not observed (SP Gap / never ran): treat its
-- facts as unknown for that run, not as removed.
CREATE TABLE sp_sections (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    section TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    PRIMARY KEY (sp_id, section)
);

CREATE TABLE sp_errors (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (sp_id, position)
);

CREATE TABLE azure_role_assignments (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    subscription_id TEXT,
    subscription_name TEXT,
    management_group_id TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_ara_sp ON azure_role_assignments(sp_id);

CREATE TABLE group_memberships (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    group_id TEXT,
    display_name TEXT,
    membership_type TEXT NOT NULL,
    is_assignable_to_role INTEGER,  -- 0/1/NULL
    pim_membership TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_gm_sp ON group_memberships(sp_id);

CREATE TABLE directory_roles (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    role_name TEXT,
    assignment_type TEXT NOT NULL,
    source TEXT NOT NULL,
    source_group_id TEXT,
    directory_scope_id TEXT,
    start_date_time TEXT,
    end_date_time TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_dr_sp ON directory_roles(sp_id);

CREATE TABLE credentials (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,  -- application | servicePrincipal
    credential_type TEXT NOT NULL,  -- secret | certificate
    display_name TEXT,
    key_id TEXT,
    start_date_time TEXT,
    end_date_time TEXT,
    status TEXT NOT NULL,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_cred_sp ON credentials(sp_id);

CREATE TABLE application_permissions (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    resource_id TEXT,
    resource_display_name TEXT,
    app_role_id TEXT,
    permission TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_ap_sp ON application_permissions(sp_id);

CREATE TABLE delegated_permissions (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    resource_id TEXT,
    resource_display_name TEXT,
    scopes TEXT NOT NULL,  -- JSON array
    consent_type TEXT,
    principal_id TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_dp_sp ON delegated_permissions(sp_id);

CREATE TABLE owners (
    sp_id INTEGER NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,  -- which object is owned: application | servicePrincipal
    owner_type TEXT,  -- user | servicePrincipal | group | NULL
    principal_id TEXT,
    display_name TEXT,
    retrieved_at TEXT NOT NULL
);
CREATE INDEX idx_own_sp ON owners(sp_id);
"""


class StoreError(Exception):
    """The database cannot be used (wrong schema version / not a run store)."""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the schema on a fresh database; refuse a mismatched one."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == SCHEMA_VERSION:
        return
    if version != 0:
        raise StoreError(
            f"database has run-store schema version {version}, but this "
            f"spyglass supports version {SCHEMA_VERSION}"
        )
    has_tables = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
    ).fetchone()
    if has_tables is not None:
        raise StoreError(
            "database is not empty and carries no run-store schema version; "
            "refusing to write into a foreign database"
        )
    conn.executescript(_SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _insert_run(conn: sqlite3.Connection, meta: Meta) -> int:
    selection = meta["selection"]
    cursor = conn.execute(
        "INSERT INTO runs (generated_at, tenant_id, tool_version, selection_tag,"
        " selection_object_ids) VALUES (?, ?, ?, ?, ?)",
        (
            meta["generatedAt"],
            meta["tenantId"],
            meta["toolVersion"],
            selection.get("tag"),
            json.dumps(selection["objectIds"]),
        ),
    )
    run_id = cursor.lastrowid
    assert run_id is not None
    conn.executemany(
        "INSERT INTO run_errors (run_id, position, message) VALUES (?, ?, ?)",
        [(run_id, i, message) for i, message in enumerate(meta["runErrors"])],
    )
    return run_id


def _insert_service_principal(
    conn: sqlite3.Connection,
    run_id: int,
    sp: ServicePrincipalRecord,
    generated_at: str,
) -> None:
    application = sp["application"]
    cursor = conn.execute(
        "INSERT INTO service_principals (run_id, object_id, app_id, display_name,"
        " tags, application_present, application_object_id, application_app_id,"
        " application_display_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            sp["objectId"],
            sp["appId"],
            sp["displayName"],
            json.dumps(sp["tags"]),
            1 if application is not None else 0,
            application["objectId"] if application is not None else None,
            application["appId"] if application is not None else None,
            application["displayName"] if application is not None else None,
        ),
    )
    sp_id = cursor.lastrowid

    # Reports written before per-section stamps existed carry an empty (or
    # absent) `retrievedAt`; their facts fall back to the run's `generatedAt`.
    retrieved_at = sp.get("retrievedAt") or {}

    def stamp(section: str) -> str:
        return retrieved_at.get(section) or generated_at

    conn.executemany(
        "INSERT INTO sp_sections (sp_id, section, retrieved_at) VALUES (?, ?, ?)",
        [
            (sp_id, section, timestamp)
            for section in SECTIONS
            if (timestamp := retrieved_at.get(section)) is not None
        ],
    )
    conn.executemany(
        "INSERT INTO sp_errors (sp_id, position, message) VALUES (?, ?, ?)",
        [(sp_id, i, message) for i, message in enumerate(sp["errors"])],
    )
    conn.executemany(
        "INSERT INTO azure_role_assignments (sp_id, role_name, scope_type, scope,"
        " subscription_id, subscription_name, management_group_id, retrieved_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                ra["roleName"],
                ra["scopeType"],
                ra["scope"],
                ra["subscriptionId"],
                ra["subscriptionName"],
                ra["managementGroupId"],
                stamp("azureRoleAssignments"),
            )
            for ra in sp["azureRoleAssignments"]
        ],
    )
    conn.executemany(
        "INSERT INTO group_memberships (sp_id, group_id, display_name,"
        " membership_type, is_assignable_to_role, pim_membership, retrieved_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                gm["groupId"],
                gm["displayName"],
                gm["membershipType"],
                None
                if gm["isAssignableToRole"] is None
                else int(gm["isAssignableToRole"]),
                gm["pimMembership"],
                stamp("groupMemberships"),
            )
            for gm in sp["groupMemberships"]
        ],
    )
    conn.executemany(
        "INSERT INTO directory_roles (sp_id, role_name, assignment_type, source,"
        " source_group_id, directory_scope_id, start_date_time, end_date_time,"
        " retrieved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                dr["roleName"],
                dr["assignmentType"],
                dr["source"],
                dr["sourceGroupId"],
                dr["directoryScopeId"],
                dr["startDateTime"],
                dr["endDateTime"],
                stamp("directoryRoles"),
            )
            for dr in sp["directoryRoles"]
        ],
    )
    # SP-owned credentials arrived with the SP object; Application-owned ones
    # arrived with the Application lookup.
    conn.executemany(
        "INSERT INTO credentials (sp_id, owner, credential_type, display_name,"
        " key_id, start_date_time, end_date_time, status, retrieved_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                cred["owner"],
                cred["credentialType"],
                cred["displayName"],
                cred["keyId"],
                cred["startDateTime"],
                cred["endDateTime"],
                cred["status"],
                stamp(
                    "servicePrincipal"
                    if cred["owner"] == "servicePrincipal"
                    else "application"
                ),
            )
            for cred in sp["credentials"]
        ],
    )
    conn.executemany(
        "INSERT INTO application_permissions (sp_id, resource_id,"
        " resource_display_name, app_role_id, permission, retrieved_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                ap["resourceId"],
                ap["resourceDisplayName"],
                ap["appRoleId"],
                ap["permission"],
                stamp("applicationPermissions"),
            )
            for ap in sp["applicationPermissions"]
        ],
    )
    conn.executemany(
        "INSERT INTO delegated_permissions (sp_id, resource_id,"
        " resource_display_name, scopes, consent_type, principal_id, retrieved_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                dp["resourceId"],
                dp["resourceDisplayName"],
                json.dumps(dp["scopes"]),
                dp["consentType"],
                dp["principalId"],
                stamp("delegatedPermissions"),
            )
            for dp in sp["delegatedPermissions"]
        ],
    )
    conn.executemany(
        "INSERT INTO owners (sp_id, owner, owner_type, principal_id, display_name,"
        " retrieved_at) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                sp_id,
                owner["owner"],
                owner["ownerType"],
                owner["id"],
                owner["displayName"],
                stamp("owners"),
            )
            for owner in sp["owners"]
        ],
    )


def persist_report(db_path: str, report: AuditReport) -> int:
    """Append one Audit Report as a run snapshot; return the new run's id.

    Creates the database (and schema) on first use. The whole report is
    written in a single transaction: a failed persist leaves no partial run.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        _ensure_schema(conn)
        with conn:
            run_id = _insert_run(conn, report["meta"])
            for sp in report["servicePrincipals"]:
                _insert_service_principal(
                    conn, run_id, sp, report["meta"]["generatedAt"]
                )
        return run_id
    finally:
        conn.close()
