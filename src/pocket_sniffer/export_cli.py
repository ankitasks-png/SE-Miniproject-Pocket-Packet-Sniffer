
"""Command-line interface for exporting saved capture sessions."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pocket_sniffer.services.export_service import (
    SessionExportError,
    export_session,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pocket-sniffer-export",
        description="Export PCAP files and/or Zeek logs from a saved session.",
    )
    parser.add_argument(
        "--session-dir",
        required=True,
        type=Path,
        help="folder containing the saved session files",
    )
    parser.add_argument(
        "--destination",
        required=True,
        type=Path,
        help="directory to export the selected files into",
    )
    parser.add_argument(
        "--type",
        choices=("pcap", "zeek", "all"),
        default="all",
        help="file types to export (default: all)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow replacing files with matching names",
    )
    args = parser.parse_args(argv)

    try:
        exported = export_session(
            args.session_dir,
            args.destination,
            include_pcap=args.type in {"pcap", "all"},
            include_zeek_logs=args.type in {"zeek", "all"},
            overwrite=args.overwrite,
        )
    except (SessionExportError, OSError) as exc:
        print(f"Export error: {exc}", file=sys.stderr)
        return 2

    print(f"Exported {len(exported)} file(s) to {args.destination.expanduser().resolve()}:")
    for path in exported:
        print(f"  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
