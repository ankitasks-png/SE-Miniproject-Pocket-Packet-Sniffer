
import pytest

from pocket_sniffer.services.export_service import (
    SessionExportError,
    export_session,
)


def make_session(path):
    path.mkdir()
    (path / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (path / "conn.log").write_text("connection data", encoding="utf-8")
    (path / "notice.log").write_text("alert data", encoding="utf-8")
    (path / "notes.txt").write_text("not an export artifact", encoding="utf-8")
    return path


def test_exports_pcap_and_zeek_logs(tmp_path):
    source = make_session(tmp_path / "session")
    destination = tmp_path / "export"

    exported = export_session(source, destination)

    assert {path.name for path in exported} == {
        "capture.pcap", "conn.log", "notice.log"
    }
    assert (destination / "capture.pcap").read_bytes() == b"\xd4\xc3\xb2\xa1"
    assert (destination / "conn.log").read_text() == "connection data"
    assert not (destination / "notes.txt").exists()


def test_exports_only_pcap(tmp_path):
    source = make_session(tmp_path / "session")

    exported = export_session(
        source, tmp_path / "export",
        include_pcap=True, include_zeek_logs=False,
    )

    assert [path.name for path in exported] == ["capture.pcap"]


def test_exports_only_zeek_logs(tmp_path):
    source = make_session(tmp_path / "session")

    exported = export_session(
        source, tmp_path / "export",
        include_pcap=False, include_zeek_logs=True,
    )

    assert {path.name for path in exported} == {"conn.log", "notice.log"}


def test_rejects_missing_session(tmp_path):
    with pytest.raises(SessionExportError, match="does not exist"):
        export_session(tmp_path / "missing", tmp_path / "export")


def test_rejects_empty_export_selection(tmp_path):
    source = make_session(tmp_path / "session")

    with pytest.raises(SessionExportError, match="Select PCAP"):
        export_session(
            source, tmp_path / "export",
            include_pcap=False, include_zeek_logs=False,
        )


def test_rejects_no_matching_files(tmp_path):
    source = tmp_path / "session"
    source.mkdir()
    (source / "notes.txt").write_text("nothing to export")

    with pytest.raises(SessionExportError, match="No files matching"):
        export_session(source, tmp_path / "export")


def test_prevents_overwriting_existing_files(tmp_path):
    source = make_session(tmp_path / "session")
    destination = tmp_path / "export"
    destination.mkdir()
    (destination / "capture.pcap").write_bytes(b"existing")

    with pytest.raises(SessionExportError, match="already contains"):
        export_session(source, destination)

    assert (destination / "capture.pcap").read_bytes() == b"existing"


def test_allows_overwrite_when_explicitly_enabled(tmp_path):
    source = make_session(tmp_path / "session")
    destination = tmp_path / "export"
    destination.mkdir()
    (destination / "capture.pcap").write_bytes(b"existing")

    export_session(source, destination, overwrite=True)

    assert (destination / "capture.pcap").read_bytes() == b"\xd4\xc3\xb2\xa1"


def test_rejects_destination_inside_source(tmp_path):
    source = make_session(tmp_path / "session")

    with pytest.raises(SessionExportError, match="inside it"):
        export_session(source, source / "exports")
