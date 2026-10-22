from __future__ import annotations

import json
from pathlib import Path


class ZeekLogError(ValueError):
    """Raised when a Zeek log cannot be read or parsed safely."""


def _decode_separator(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ZeekLogError(f"Unsupported Zeek field separator: {value!r}") from exc


def read_zeek_log(path: str | Path) -> list[dict[str, str]]:
    """Read a Zeek TSV log or JSON-lines log without executing external commands."""
    file_path = Path(path)
    separator = "\t"
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ZeekLogError(f"Could not read {file_path}: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if line.startswith("#separator "):
            separator = _decode_separator(line[len("#separator ") :])
            continue
        if line.startswith("#fields"):
            parts = line.split(separator)
            fields = parts[1:]
            if not fields or any(not field for field in fields):
                raise ZeekLogError(f"Invalid #fields header at {file_path}:{line_number}")
            continue
        if line.startswith("#"):
            continue
        if line.lstrip().startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ZeekLogError(f"Invalid JSON at {file_path}:{line_number}") from exc
            if not isinstance(record, dict):
                raise ZeekLogError(f"Expected a JSON object at {file_path}:{line_number}")
            rows.append({str(key): str(value) for key, value in record.items()})
            continue
        if fields is None:
            raise ZeekLogError(f"Missing #fields header at {file_path}:{line_number}")
        values = line.split(separator)
        if len(values) != len(fields):
            raise ZeekLogError(
                f"Expected {len(fields)} fields, found {len(values)} "
                f"at {file_path}:{line_number}"
            )
        rows.append(dict(zip(fields, values)))

    return rows
