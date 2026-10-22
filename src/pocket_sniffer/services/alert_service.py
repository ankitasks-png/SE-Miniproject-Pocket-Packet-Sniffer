from __future__ import annotations

from collections.abc import Iterable, Mapping

from pocket_sniffer.core.types import Alert

# These priorities apply only to notices already emitted by Zeek; the app does
# not probe networks or infer unsupported attack types.
_NOTICE_PRIORITIES = {
    "Scan::Port_Scan": "HIGH",
    "Scan::Address_Scan": "HIGH",
}
_PRIORITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _timestamp_number(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_alerts(
    notices: Iterable[Mapping[str, str]], enabled: bool = True
) -> list[Alert]:
    """Convert Zeek notice.log records into a readable, prioritized alert list."""
    if not enabled:
        return []

    alerts: list[Alert] = []
    for notice in notices:
        note = notice.get("note", "").strip()
        if not note or note in {"-", "(empty)"}:
            continue
        timestamp = notice.get("ts", "").strip()
        source = (
            notice.get("src", "").strip()
            or notice.get("id.orig_h", "").strip()
            or "unknown"
        )
        reason = notice.get("msg", "").strip()
        if not reason or reason in {"-", "(empty)"}:
            reason = note
        alerts.append(
            Alert(
                timestamp=timestamp or "unknown time",
                source=source,
                reason=reason,
                priority=_NOTICE_PRIORITIES.get(note, "LOW"),
            )
        )

    return sorted(
        alerts,
        key=lambda alert: (
            _PRIORITY_RANK[alert.priority],
            _timestamp_number(alert.timestamp),
            alert.source,
        ),
        reverse=True,
    )
