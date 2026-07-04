"""Builds the `{ meta, servicePrincipals }` Audit Report envelope."""

from __future__ import annotations

from . import __version__
from .models import AuditReport, Meta, Selection, ServicePrincipalRecord


def _sort_key(record: ServicePrincipalRecord) -> str:
    return (record["displayName"] or "").lower()


def build_report(
    records: list[ServicePrincipalRecord],
    *,
    tenant_id: str,
    selection: Selection,
    generated_at: str,
    run_errors: list[str] | None = None,
    tool_version: str = __version__,
) -> AuditReport:
    """Assemble the Audit Report envelope from collected SP records.

    `servicePrincipals` is sorted by display name (case-insensitive) for stable,
    diff-friendly output. `signedInUser` is intentionally absent from `meta`.
    """
    meta: Meta = {
        "generatedAt": generated_at,
        "tenantId": tenant_id,
        "selection": selection,
        "toolVersion": tool_version,
        "runErrors": list(run_errors) if run_errors else [],
    }
    return {
        "meta": meta,
        "servicePrincipals": sorted(records, key=_sort_key),
    }
