from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pocket_sniffer.services.alert_service import build_alerts
from pocket_sniffer.services.log_reader import ZeekLogError, read_zeek_log
from pocket_sniffer.services.summary_service import summarize_connections


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pocket-sniffer",
        description="Summarize local Zeek logs and review Zeek notices.",
    )
    parser.add_argument(
        "--log-dir",
        required=True,
        type=Path,
        help="directory containing Zeek conn.log and/or notice.log",
    )
    parser.add_argument(
        "--top", type=int, default=5, help="number of talkers to show (default: 5)"
    )
    parser.add_argument(
        "--no-alerts", action="store_true", help="disable alert display for this report"
    )
    return parser


def _render_report(log_dir: Path, top: int, alerts_enabled: bool) -> str:
    if not log_dir.is_dir():
        raise ZeekLogError(f"Log directory does not exist: {log_dir}")
    conn_path = log_dir / "conn.log"
    notice_path = log_dir / "notice.log"
    if not conn_path.is_file() and not notice_path.is_file():
        raise ZeekLogError(f"No conn.log or notice.log found in {log_dir}")

    connections = read_zeek_log(conn_path) if conn_path.is_file() else []
    notices = (
        read_zeek_log(notice_path)
        if alerts_enabled and notice_path.is_file()
        else []
    )
    summary = summarize_connections(connections, top_limit=top)
    alerts = build_alerts(notices, enabled=alerts_enabled)

    lines = ["Pocket Packet Sniffer — local Zeek report", f"Log directory: {log_dir}", ""]
    lines.append(f"Connections: {summary.connection_count}")
    lines.append("Protocol breakdown:")
    if summary.protocol_breakdown:
        lines.extend(f"  {protocol}: {count}" for protocol, count in summary.protocol_breakdown.items())
    else:
        lines.append("  No connection records")
    lines.append("Top talkers (observed bytes, then connections):")
    if summary.top_talkers:
        lines.extend(
            f"  {talker.host}: {_format_bytes(talker.byte_count)}, "
            f"{talker.connection_count} connections"
            for talker in summary.top_talkers
        )
    else:
        lines.append("  No host records")

    lines.append("Alerts:")
    if not alerts_enabled:
        lines.append("  Disabled for this report")
    elif alerts:
        lines.extend(
            f"  [{alert.priority}] {alert.timestamp} | {alert.source} | "
            f"{alert.reason}"
            for alert in alerts
        )
    else:
        lines.append("  No Zeek notices found")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error("--top must be at least 1")
    try:
        print(_render_report(args.log_dir, args.top, not args.no_alerts))
    except ZeekLogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
