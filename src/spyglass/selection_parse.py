"""Pure parsing of the Service Principal selection surface."""

from __future__ import annotations

import json
from collections.abc import Iterable


def parse_ids_file(content: str) -> list[str]:
    """Parse ids-file contents: either a JSON array or a newline list.

    A leading `[` (after stripping surrounding whitespace) selects JSON-array
    parsing; otherwise the content is read as one object id per line. Blank or
    whitespace-only entries are ignored and every id is stripped.
    """
    stripped = content.strip()
    if not stripped:
        return []
    if stripped[0] == "[":
        data = json.loads(stripped)
        return [s for item in data if (s := str(item).strip())]
    return [s for line in content.splitlines() if (s := line.strip())]


def merge_object_ids(*sources: Iterable[str]) -> list[str]:
    """Merge id sources into one list, deduped, preserving first-seen order.

    Used to fold repeated `--object-id` values together with the ids parsed
    from `--ids-file` into a single selection set. Blank ids are dropped.
    """
    seen: set[str] = set()
    merged: list[str] = []
    for source in sources:
        for raw in source:
            oid = raw.strip()
            if oid and oid not in seen:
                seen.add(oid)
                merged.append(oid)
    return merged
