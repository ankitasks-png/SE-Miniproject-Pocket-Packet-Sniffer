
"""Safely export selected session artifacts for offline analysis."""
from __future__ import annotations

import shutil
from pathlib import Path


class SessionExportError(ValueError):
    """Raised when session artifacts cannot be exported safely."""


SUPPORTED_PCAP = {".pcap", ".pcapng"}
SUPPORTED_ZEEK_LOGS = {
    "conn.log",
    "notice.log",
    "dns.log",
    "http.log",
    "ssl.log",
    "weird.log",
    "files.log",
    "packet_filter.log",
    "reporter.log",
}


def export_session(
    session_dir: str | Path,
    destination: str | Path,
    *,
    include_pcap: bool = True,
    include_zeek_logs: bool = True,
    overwrite: bool = False,
) -> list[Path]:
    """Copy selected PCAP and/or Zeek log files to a destination folder."""
    source = Path(session_dir).expanduser().resolve()
    target = Path(destination).expanduser().resolve()

    if not source.is_dir():
        raise SessionExportError(f"Session directory does not exist: {source}")
    if source == target or source in target.parents:
        raise SessionExportError(
            "Destination must not be the session directory or inside it"
        )
    if not include_pcap and not include_zeek_logs:
        raise SessionExportError("Select PCAP files, Zeek logs, or both")

    selected: list[Path] = []
    for item in sorted(source.iterdir()):
        if not item.is_file():
            continue
        if include_pcap and item.suffix.lower() in SUPPORTED_PCAP:
            selected.append(item)
        elif include_zeek_logs and item.name in SUPPORTED_ZEEK_LOGS:
            selected.append(item)

    if not selected:
        raise SessionExportError(
            "No files matching the requested export types were found"
        )

    # Validate all conflicts before copying anything.
    conflicts = [target / item.name for item in selected if (target / item.name).exists()]
    if conflicts and not overwrite:
        names = ", ".join(path.name for path in conflicts)
        raise SessionExportError(
            f"Destination already contains: {names}. Use overwrite to replace them."
        )

    try:
        target.mkdir(parents=True, exist_ok=True)
        exported: list[Path] = []
        for item in selected:
            destination_file = target / item.name
            shutil.copy2(item, destination_file)
            exported.append(destination_file)
    except OSError as exc:
        raise SessionExportError(f"Could not export session files: {exc}") from exc

    return exported
