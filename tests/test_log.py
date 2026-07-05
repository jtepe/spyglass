"""Tests for the tiered, colorful logging setup."""

from __future__ import annotations

import asyncio
import logging

import pytest

from spyglass.log import (
    LEVELS,
    ColorFormatter,
    configure_logging,
    current_sp,
    instrument_http_client,
)


@pytest.fixture(autouse=True)
def _restore_spyglass_logger():
    """Undo configure_logging's handler/propagate changes between tests.

    configure_logging disables propagation on the "spyglass" logger, which
    would otherwise stop caplog (attached at the root) from seeing records
    in tests that run afterwards.
    """
    logger = logging.getLogger("spyglass")
    saved = (logger.level, logger.propagate, list(logger.handlers))
    yield
    logger.level, logger.propagate, logger.handlers = saved


def _record(level: int, message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="spyglass.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_levels_map_the_four_tiers() -> None:
    assert LEVELS == {
        "error": logging.ERROR,
        "warn": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }


def test_each_tier_gets_its_color() -> None:
    formatter = ColorFormatter(color=True)
    expected = {
        logging.ERROR: "\x1b[31mERROR\x1b[0m",
        logging.WARNING: "\x1b[33mWARN\x1b[0m",
        logging.INFO: "\x1b[32mINFO\x1b[0m",
        logging.DEBUG: "\x1b[34mDEBUG\x1b[0m",
    }
    for level, colored in expected.items():
        assert colored in formatter.format(_record(level, "message"))


def test_no_ansi_codes_without_color() -> None:
    formatter = ColorFormatter(color=False)
    line = formatter.format(_record(logging.WARNING, "message"))
    assert "\x1b[" not in line
    assert " WARN message" in line


def test_current_sp_context_prefixes_messages() -> None:
    formatter = ColorFormatter(color=False)
    token = current_sp.set("11111111-1111-1111-1111-111111111111")
    try:
        line = formatter.format(_record(logging.INFO, "resolving"))
    finally:
        current_sp.reset(token)
    assert "sp=11111111-1111-1111-1111-111111111111 resolving" in line
    assert "sp=" not in formatter.format(_record(logging.INFO, "resolving"))


def test_configure_logging_sets_level_and_caps_third_party() -> None:
    configure_logging("debug")
    logger = logging.getLogger("spyglass")
    assert logger.level == logging.DEBUG
    assert not logger.propagate
    assert len(logger.handlers) == 1
    assert logging.getLogger("httpx").level == logging.WARNING

    configure_logging("warn")
    assert logger.level == logging.WARNING
    assert len(logger.handlers) == 1


def test_instrumented_client_logs_each_call(caplog) -> None:
    class Request:
        method = "GET"
        url = "https://graph.microsoft.com/v1.0/servicePrincipals/x"

    class Response:
        request = Request()
        status_code = 200

    class Client:
        event_hooks = {"request": [], "response": []}

    client = instrument_http_client(Client())
    (hook,) = client.event_hooks["response"]

    with caplog.at_level(logging.DEBUG, logger="spyglass.http"):
        asyncio.run(hook(Response()))

    assert (
        "GET https://graph.microsoft.com/v1.0/servicePrincipals/x -> 200" in caplog.text
    )
