"""Up-front precondition gating and Graph-plane credential selection.

The Azure RBAC plane always authenticates through `az login` (it shells out to
`az graph query`), so an active CLI login remains a hard precondition and the
source of `tenantId`. The Microsoft Graph plane, by contrast, picks its
credential from the run's configuration: an explicit service principal (client
id + secret + tenant), a managed identity, or — when neither is supplied — the
same `az login` user (the historical default). `verify_preconditions` gates the
run on both: a live CLI login *and* a Graph token from the selected credential.
A failure aborts before any collection with a non-zero exit.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass

from azure.core.credentials_async import AsyncTokenCredential
from azure.identity.aio import (
    AzureCliCredential,
    ClientSecretCredential,
    ManagedIdentityCredential,
)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class PreconditionError(Exception):
    """A global precondition failed; the run must abort before collection."""


@dataclass(frozen=True)
class GraphAuthConfig:
    """Resolved Graph-plane credential inputs (from CLI flags + environment).

    `client_secret` present alongside `client_id`/`tenant_id` selects a service
    principal; `managed_identity` selects a managed identity (`client_id`, if
    set, picks a user-assigned one); neither selects the `az login` user.
    """

    client_id: str | None = None
    client_secret: str | None = None
    tenant_id: str | None = None
    managed_identity: bool = False


def _env(name: str) -> str | None:
    """Return a non-empty environment variable, or None."""
    value = os.environ.get(name)
    return value or None


def resolve_graph_auth_config(
    *,
    client_id: str | None,
    tenant_id: str | None,
    managed_identity: bool,
) -> GraphAuthConfig:
    """Merge CLI inputs with the standard `AZURE_*` env vars (CLI wins).

    The client secret is read only from `AZURE_CLIENT_SECRET` — never a flag — so
    it is not exposed in shell history or process listings.
    """
    return GraphAuthConfig(
        client_id=client_id or _env("AZURE_CLIENT_ID"),
        client_secret=_env("AZURE_CLIENT_SECRET"),
        tenant_id=tenant_id or _env("AZURE_TENANT_ID"),
        managed_identity=managed_identity,
    )


def build_graph_credential(config: GraphAuthConfig) -> AsyncTokenCredential:
    """Select the Graph-plane credential from `config`, by precedence.

    1. Service principal — `client_id` + `tenant_id` plus the `AZURE_CLIENT_SECRET`
       secret.
    2. Managed identity — when `managed_identity` is set (`client_id` picks a
       user-assigned identity; otherwise system-assigned).
    3. `az login` user — the default when nothing else is configured.

    Raises:
        PreconditionError: on a partial service-principal config, or when
        managed identity is combined with service-principal inputs.
    """
    # The identity selectors (client/tenant id) signal intent to use a service
    # principal. The secret is deliberately excluded: it is read only from
    # AZURE_CLIENT_SECRET, which may be present in the environment for other
    # tools, so on its own it must not force service-principal auth.
    has_sp_input = any((config.client_id, config.tenant_id))

    if config.managed_identity:
        if config.client_secret or config.tenant_id:
            raise PreconditionError(
                "Managed identity cannot be combined with a client secret or "
                "tenant id. Choose one authentication mode."
            )
        if config.client_id:
            return ManagedIdentityCredential(client_id=config.client_id)
        return ManagedIdentityCredential()

    if has_sp_input:
        missing = [
            name
            for name, value in (
                ("client id", config.client_id),
                ("client secret", config.client_secret),
                ("tenant id", config.tenant_id),
            )
            if not value
        ]
        if missing:
            raise PreconditionError(
                "Service-principal authentication needs a client id, client "
                f"secret, and tenant id; missing: {', '.join(missing)}. Pass the "
                "client id and tenant id via --client-id/--tenant-id (or "
                "AZURE_CLIENT_ID/AZURE_TENANT_ID), and the secret via the "
                "AZURE_CLIENT_SECRET environment variable."
            )
        # Narrowed to str by the missing-check above.
        assert config.client_id and config.client_secret and config.tenant_id
        return ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret,
        )

    return AzureCliCredential()


def _az_account_tenant_id() -> str:
    """Return the tenantId from `az account show`, or raise PreconditionError."""
    if shutil.which("az") is None:
        raise PreconditionError(
            "The Azure CLI ('az') is not installed or not on PATH. "
            "Install it and run 'az login'."
        )

    try:
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True,
            text=True,
        )
    except OSError as exc:  # pragma: no cover - defensive
        raise PreconditionError(f"Could not invoke 'az account show': {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "no error output"
        raise PreconditionError(
            f"Not logged in to Azure CLI. Run 'az login' first. Details: {detail}"
        )

    try:
        account = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise PreconditionError(
            f"Could not parse 'az account show' output: {exc}"
        ) from exc

    tenant_id = account.get("tenantId")
    if not tenant_id:
        raise PreconditionError("'az account show' did not report a tenantId.")
    return str(tenant_id)


async def verify_preconditions(credential: AsyncTokenCredential) -> str:
    """Gate the run on CLI login and a live Graph token; return the tenantId.

    The Azure RBAC plane shells out to `az`, so an active `az login` is required
    regardless of the Graph credential and remains the `tenantId` source. The
    Graph token is acquired through `credential`, which may be the `az login`
    user, a service principal, or a managed identity.

    Raises:
        PreconditionError: if not logged in, or a Graph token cannot be acquired.
    """
    tenant_id = _az_account_tenant_id()

    try:
        await credential.get_token(GRAPH_SCOPE)
    except Exception as exc:  # noqa: BLE001 - any failure here is a hard gate
        raise PreconditionError(
            f"Could not acquire a Microsoft Graph token: {exc}"
        ) from exc

    return tenant_id
