from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping

from pocket_sniffer.core.types import Summary, Talker


def _integer(value: str | None) -> int:
    if not value or value in {"-", "(empty)"}:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _host(value: str | None) -> str | None:
    if not value or value in {"-", "(empty)"}:
        return None
    return value


def summarize_connections(
    rows: Iterable[Mapping[str, str]], top_limit: int = 5
) -> Summary:
    """Aggregate protocol totals and per-host bytes/connections from conn.log rows."""
    if top_limit < 1:
        raise ValueError("top_limit must be at least 1")

    protocol_counts: Counter[str] = Counter()
    talker_bytes: Counter[str] = Counter()
    talker_connections: Counter[str] = Counter()
    connection_count = 0

    for row in rows:
        connection_count += 1
        raw_protocol = row.get("proto", "").strip()
        if not raw_protocol or raw_protocol in {"-", "(empty)"}:
            raw_protocol = "unknown"
        protocol_counts[raw_protocol.upper()] += 1

        origin = _host(row.get("id.orig_h"))
        responder = _host(row.get("id.resp_h"))
        if origin:
            talker_connections[origin] += 1
            talker_bytes[origin] += _integer(row.get("orig_bytes"))
        if responder:
            talker_connections[responder] += 1
            talker_bytes[responder] += _integer(row.get("resp_bytes"))

    ranked_hosts = sorted(
        talker_connections,
        key=lambda host: (-talker_bytes[host], -talker_connections[host], host),
    )[:top_limit]
    talkers = tuple(
        Talker(
            host=host,
            connection_count=talker_connections[host],
            byte_count=talker_bytes[host],
        )
        for host in ranked_hosts
    )
    return Summary(
        protocol_breakdown=dict(sorted(protocol_counts.items())),
        top_talkers=talkers,
        connection_count=connection_count,
    )
