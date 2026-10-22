from pocket_sniffer.services.alert_service import build_alerts
from pocket_sniffer.services.summary_service import summarize_connections


def test_summary_counts_protocols_and_ranks_talkers():
    summary = summarize_connections(
        [
            {"proto": "tcp", "id.orig_h": "192.0.2.1", "orig_bytes": "100", "id.resp_h": "192.0.2.2", "resp_bytes": "900"},
            {"proto": "udp", "id.orig_h": "192.0.2.1", "orig_bytes": "50", "id.resp_h": "192.0.2.3", "resp_bytes": "10"},
        ]
    )
    assert summary.connection_count == 2
    assert summary.protocol_breakdown == {"TCP": 1, "UDP": 1}
    assert summary.top_talkers[0].host == "192.0.2.2"
    assert summary.top_talkers[0].byte_count == 900
    assert summary.top_talkers[0].connection_count == 1


def test_summary_handles_missing_values_and_top_limit():
    summary = summarize_connections(
        [{"proto": "-", "id.orig_h": "-", "id.resp_h": "192.0.2.3", "resp_bytes": "bad"}],
        top_limit=1,
    )
    assert summary.protocol_breakdown == {"UNKNOWN": 1}
    assert summary.top_talkers[0].host == "192.0.2.3"
    assert summary.top_talkers[0].byte_count == 0


def test_summary_rejects_nonpositive_top_limit():
    try:
        summarize_connections([], top_limit=0)
    except ValueError as exc:
        assert "at least 1" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_alerts_sort_priority_then_newest_and_keep_required_fields():
    alerts = build_alerts(
        [
            {"ts": "10", "note": "Example::Notice", "msg": "low", "src": "192.0.2.1"},
            {"ts": "8", "note": "Scan::Port_Scan", "msg": "scan", "src": "192.0.2.2"},
            {"ts": "9", "note": "Scan::Port_Scan", "msg": "newer scan", "src": "192.0.2.3"},
        ]
    )
    assert [a.priority for a in alerts] == ["HIGH", "HIGH", "LOW"]
    assert alerts[0].timestamp == "9"
    assert (alerts[0].source, alerts[0].reason) == ("192.0.2.3", "newer scan")


def test_alerts_can_be_disabled_and_empty_notes_are_ignored():
    notices = [{"note": "Scan::Port_Scan", "src": "192.0.2.1"}, {"note": "-"}]
    assert build_alerts(notices, enabled=False) == []
    alerts = build_alerts(notices)
    assert len(alerts) == 1
    assert alerts[0].timestamp == "unknown time"
    assert alerts[0].reason == "Scan::Port_Scan"
