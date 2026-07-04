"""Tiered, colorful logging to stderr (issue tiers: error/warn/info/debug).

Messages are stamped with the current Service Principal's object id via a
`ContextVar`, so concurrently collected SPs stay attributable. HTTP-level
DEBUG logging hooks into the Graph SDK's httpx client; ARG (`az`) calls log
without an SP in context.
"""

from __future__ import annotations

import logging
import os
import sys
from contextvars import ContextVar
from typing import Any

current_sp: ContextVar[str | None] = ContextVar("current_sp", default=None)

LEVELS = {
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

_COLORS = {
    logging.ERROR: "\x1b[31m",
    logging.WARNING: "\x1b[33m",
    logging.INFO: "\x1b[32m",
    logging.DEBUG: "\x1b[34m",
}
_RESET = "\x1b[0m"

_LEVEL_NAMES = {
    logging.ERROR: "ERROR",
    logging.WARNING: "WARN",
    logging.INFO: "INFO",
    logging.DEBUG: "DEBUG",
}

_THIRD_PARTY = ("azure", "httpx", "httpcore", "kiota", "msgraph", "urllib3")


class ColorFormatter(logging.Formatter):
    def __init__(self, *, color: bool) -> None:
        super().__init__()
        self._color = color

    def format(self, record: logging.LogRecord) -> str:
        level = _LEVEL_NAMES.get(record.levelno, record.levelname)
        if self._color:
            color = _COLORS.get(record.levelno, "")
            level = f"{color}{level}{_RESET}"
        sp = getattr(record, "sp", None) or current_sp.get()
        prefix = f"sp={sp} " if sp else ""
        timestamp = self.formatTime(record, "%H:%M:%S")
        return f"{timestamp} {level} {prefix}{record.getMessage()}"


def use_color() -> bool:
    return sys.stderr.isatty() and "NO_COLOR" not in os.environ


def configure_logging(level_name: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter(color=use_color()))
    logger = logging.getLogger("spyglass")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(LEVELS[level_name])
    logger.propagate = False
    for name in _THIRD_PARTY:
        logging.getLogger(name).setLevel(logging.WARNING)


async def _log_response(response: Any) -> None:
    request = response.request
    logging.getLogger("spyglass.http").debug(
        "%s %s -> %s", request.method, request.url, response.status_code
    )


def instrument_http_client(client: Any) -> Any:
    client.event_hooks["response"].append(_log_response)
    return client
