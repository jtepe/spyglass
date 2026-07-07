"""`spyglass` command-line entry point.

Wires the modules into one async vertical path: gate on preconditions (fail
fast, non-zero), then resolve the selected Service Principal, build the Audit
Report envelope, write JSON, and exit 0 (two-tier failure model).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from kiota_authentication_azure.azure_identity_authentication_provider import (
    AzureIdentityAuthenticationProvider,
)
from msgraph import GraphRequestAdapter, GraphServiceClient
from msgraph_core import GraphClientFactory

from .auth import (
    GRAPH_SCOPE,
    PreconditionError,
    build_graph_credential,
    resolve_graph_auth_config,
    verify_preconditions,
)
from .azure_rbac import collect_azure_rbac
from .entra import DEFAULT_CONCURRENCY, EntraCollector
from .log import LEVELS, configure_logging, instrument_http_client
from .models import Selection, ServicePrincipalRecord
from .render import render
from .report import build_report
from .selection_parse import merge_object_ids, parse_ids_file
from .store import StoreError, persist_report

DEFAULT_OUTPUT = "audit-report.json"

_log = logging.getLogger("spyglass.cli")
_render_log = logging.getLogger("spyglass.render")
_store_log = logging.getLogger("spyglass.store")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="spyglass",
        description=(
            "Audit Entra service principals across the directory plane and "
            "write a JSON Audit Report."
        ),
    )
    parser.add_argument(
        "--object-id",
        action="append",
        dest="object_ids",
        default=[],
        metavar="ID",
        help=(
            "Object id of a service principal to audit (appId accepted as a "
            "fallback). May be repeated and combined with --ids-file."
        ),
    )
    parser.add_argument(
        "--ids-file",
        metavar="PATH",
        help=(
            "Path to a file of object ids, either a newline list or a JSON "
            "array. Merged and deduped with any --object-id values."
        ),
    )
    parser.add_argument(
        "--tag",
        metavar="TAG",
        help=(
            "Select service principals carrying this tag. Mutually exclusive "
            "with --object-id/--ids-file."
        ),
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Path for the JSON Audit Report (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help=(
            "Additionally render a self-contained HTML report. JSON is always "
            "written; this only adds the HTML view."
        ),
    )
    parser.add_argument(
        "--html-output",
        metavar="PATH",
        help=(
            "Path for the HTML report (implies --html). Defaults to the JSON "
            "output path with an .html suffix."
        ),
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        help=(
            "Path to a SQLite run store. When given, the run is additionally "
            "persisted there as an append-only snapshot (the file and schema "
            "are created on first use), enabling change tracking across runs. "
            "JSON output is unaffected."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=list(LEVELS),
        default="info",
        help=(
            "Logging verbosity on stderr (default: info). 'error' shows only "
            "run-aborting failures, 'warn' adds non-aborting errors such as SP "
            "gaps, 'info' adds one line per service principal, 'debug' adds "
            "every call made."
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=(
            "Maximum number of service principals processed at once "
            f"(default: {DEFAULT_CONCURRENCY}). Lower it if a throttling-prone "
            "tenant starts returning 429s."
        ),
    )
    auth = parser.add_argument_group(
        "Graph authentication",
        "Selects the Microsoft Graph credential. A service principal (client id "
        "+ tenant id + the AZURE_CLIENT_SECRET env var) takes precedence, then "
        "--managed-identity, otherwise the 'az login' user. The Azure RBAC plane "
        "always uses 'az login'. The client id and tenant id flags fall back to "
        "AZURE_CLIENT_ID / AZURE_TENANT_ID; the secret is read only from "
        "AZURE_CLIENT_SECRET.",
    )
    auth.add_argument(
        "--client-id",
        metavar="ID",
        help=(
            "Service-principal app (client) id, or the client id of a "
            "user-assigned managed identity (env: AZURE_CLIENT_ID). The "
            "matching secret is read from AZURE_CLIENT_SECRET."
        ),
    )
    auth.add_argument(
        "--tenant-id",
        metavar="ID",
        help="Service-principal tenant id (env: AZURE_TENANT_ID).",
    )
    auth.add_argument(
        "--managed-identity",
        action="store_true",
        help=(
            "Authenticate to Graph with a managed identity (system-assigned, "
            "or user-assigned when --client-id is given)."
        ),
    )
    args = parser.parse_args(argv)

    if args.tag is not None and (args.object_ids or args.ids_file):
        parser.error("--tag is mutually exclusive with --object-id/--ids-file")
    if args.tag is None and not args.object_ids and not args.ids_file:
        parser.error("one of --object-id, --ids-file, or --tag is required")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    return args


async def _run(args: argparse.Namespace) -> int:
    output: str = args.output

    # Select the Graph credential up front so a misconfiguration fails fast,
    # before any collection. The Azure RBAC plane still uses `az login`.
    try:
        auth_config = resolve_graph_auth_config(
            client_id=args.client_id,
            tenant_id=args.tenant_id,
            managed_identity=args.managed_identity,
        )
        credential = build_graph_credential(auth_config)
    except PreconditionError as exc:
        _log.error("precondition failed: %s", exc)
        return 2

    file_ids: list[str] = []
    if args.ids_file:
        try:
            with open(args.ids_file, encoding="utf-8") as fh:
                file_ids = parse_ids_file(fh.read())
        except (OSError, ValueError) as exc:
            _log.error("failed to read --ids-file: %s", exc)
            await credential.close()
            return 2

    selection: Selection
    records: list[ServicePrincipalRecord] = []
    run_errors: list[str] = []

    try:
        # Global precondition: fail fast (non-zero) before any collection.
        try:
            tenant_id = await verify_preconditions(credential)
        except PreconditionError as exc:
            _log.error("precondition failed: %s", exc)
            return 2

        # Collection has started: from here we always complete, write, exit 0.
        http_client = instrument_http_client(
            GraphClientFactory.create_with_default_middleware()
        )
        auth_provider = AzureIdentityAuthenticationProvider(
            credential, scopes=[GRAPH_SCOPE]
        )
        client = GraphServiceClient(
            request_adapter=GraphRequestAdapter(auth_provider, http_client)
        )
        collector = EntraCollector(client, concurrency=args.concurrency)
        if args.tag is not None:
            selection = {"objectIds": [], "tag": args.tag}
            records, tag_errors = await collector.collect_by_tag(args.tag)
            run_errors.extend(tag_errors)
            selection["objectIds"] = [r["objectId"] for r in records]
        else:
            object_ids = merge_object_ids(args.object_ids, file_ids)
            selection = {"objectIds": object_ids}
            records, id_errors = await collector.collect_by_object_ids(object_ids)
            run_errors.extend(id_errors)
    finally:
        await credential.close()

    # Azure RBAC plane: a single full management-group-scoped ARG batch. A
    # failure here is a Run Error — the Entra-plane data still writes.
    try:
        assignments_by_principal = await collect_azure_rbac(
            [r["objectId"] for r in records], tenant_id
        )
    except Exception as exc:  # noqa: BLE001 - degrade to a Run Error, never abort
        run_errors.append(f"Azure RBAC query failed: {exc}")
        _log.warning("Azure RBAC query failed: %s", exc)
    else:
        # One batch answered for every SP, so they share one retrieval stamp.
        rbac_retrieved_at = datetime.now(UTC).isoformat()
        for record in records:
            record["azureRoleAssignments"] = assignments_by_principal.get(
                record["objectId"], []
            )
            record["retrievedAt"]["azureRoleAssignments"] = rbac_retrieved_at

    report = build_report(
        records,
        tenant_id=tenant_id,
        selection=selection,
        generated_at=datetime.now(UTC).isoformat(),
        run_errors=run_errors,
    )

    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    _log.info(
        "wrote %d service principal(s) to %s",
        len(report["servicePrincipals"]),
        output,
    )

    # Optional self-contained HTML rendering on the same run (no prompt).
    if args.html or args.html_output:
        html_path = args.html_output or str(Path(output).with_suffix(".html"))
        Path(html_path).write_text(render(report), encoding="utf-8")
        _render_log.info("wrote HTML report to %s", html_path)

    # Optional run-store persistence. The JSON already written stays valid
    # either way; a failed persist is reported with a non-zero exit so it is
    # never silently skipped.
    if args.db:
        try:
            run_id = persist_report(args.db, report)
        except (sqlite3.Error, StoreError, OSError) as exc:
            _store_log.error("failed to persist run to %s: %s", args.db, exc)
            return 1
        _store_log.info("persisted run %d to %s", run_id, args.db)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configure_logging(args.log_level)
    exit_code = asyncio.run(_run(args))
    if argv is None:
        sys.exit(exit_code)
    return exit_code


if __name__ == "__main__":
    main()
