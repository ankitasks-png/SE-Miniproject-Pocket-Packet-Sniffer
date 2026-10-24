
"""Browse and select indexed packet-capture sessions."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pocket_sniffer.services.session_store import (
    SessionStore,
    SessionStoreError,
)


def _default_database() -> Path:
    return Path(
        os.environ.get(
            "POCKET_SNIFFER_SESSION_DB",
            "~/.pocket_packet_sniffer/sessions.sqlite3",
        )
    ).expanduser()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pocket-sniffer-sessions",
        description="Index, browse, and select saved capture sessions.",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=_default_database(),
        help="SQLite session index location",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    index_parser = commands.add_parser(
        "index", help="Add a saved session folder to the index"
    )
    index_parser.add_argument("directory", type=Path)

    commands.add_parser("list", help="Browse indexed sessions")

    show_parser = commands.add_parser(
        "show", help="Select a session by its index ID"
    )
    show_parser.add_argument("session_id", type=int)

    args = parser.parse_args(argv)

    try:
        store = SessionStore(args.database)

        if args.command == "index":
            session = store.index_session(args.directory)
            print(f"Indexed session #{session.id}: {session.name}")
            print(f"Path: {session.path}")

        elif args.command == "list":
            sessions = store.list_sessions()
            if not sessions:
                print("No sessions indexed yet.")
                return 0

            print("Saved capture sessions:")
            for session in sessions:
                print(
                    f"  #{session.id}  {session.name} "
                    f"| {session.created_at} | {session.path}"
                )

        elif args.command == "show":
            session = store.get_session(args.session_id)
            print(f"Selected session #{session.id}: {session.name}")
            print(f"Path: {session.path}")
            print(f"Indexed session timestamp: {session.created_at}")
            print("Available files:")
            for item in sorted(Path(session.path).iterdir()):
                if item.is_file():
                    print(f"  {item.name}")

        return 0

    except (SessionStoreError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
