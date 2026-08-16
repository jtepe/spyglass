"""Tests for the command-line interface."""

from __future__ import annotations

import pytest

from spyglass.cli import _parse_args


def test_audit_subcommand_accepts_audit_options() -> None:
    args = _parse_args(["audit", "--object-id", "sp-id", "--html", "--db", "out.db"])

    assert args.command == "audit"
    assert args.object_ids == ["sp-id"]
    assert args.html is True
    assert args.db == "out.db"


def test_audit_options_are_rejected_without_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse_args(["--object-id", "sp-id"])

    assert exc_info.value.code != 0
    assert "usage: spyglass" in capsys.readouterr().err


def test_audit_requires_a_selection(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _parse_args(["audit"])

    assert exc_info.value.code != 0
    assert "usage: spyglass audit" in capsys.readouterr().err
