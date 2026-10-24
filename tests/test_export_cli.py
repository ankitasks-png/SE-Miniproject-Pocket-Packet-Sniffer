
from pocket_sniffer.export_cli import main


def create_session(path):
    path.mkdir()
    (path / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (path / "conn.log").write_text("connection data", encoding="utf-8")
    (path / "notes.txt").write_text("not exportable", encoding="utf-8")
    return path


def test_cli_exports_all_supported_files(tmp_path, capsys):
    source = create_session(tmp_path / "session")
    destination = tmp_path / "export"

    result = main([
        "--session-dir", str(source),
        "--destination", str(destination),
    ])

    output = capsys.readouterr().out
    assert result == 0
    assert "Exported 2 file(s)" in output
    assert (destination / "capture.pcap").exists()
    assert (destination / "conn.log").exists()
    assert not (destination / "notes.txt").exists()


def test_cli_exports_only_pcap(tmp_path, capsys):
    source = create_session(tmp_path / "session")
    destination = tmp_path / "export"

    result = main([
        "--session-dir", str(source),
        "--destination", str(destination),
        "--type", "pcap",
    ])

    assert result == 0
    assert (destination / "capture.pcap").exists()
    assert not (destination / "conn.log").exists()
    assert "Exported 1 file(s)" in capsys.readouterr().out


def test_cli_exports_only_zeek_logs(tmp_path, capsys):
    source = create_session(tmp_path / "session")
    destination = tmp_path / "export"

    result = main([
        "--session-dir", str(source),
        "--destination", str(destination),
        "--type", "zeek",
    ])

    assert result == 0
    assert (destination / "conn.log").exists()
    assert not (destination / "capture.pcap").exists()


def test_cli_reports_export_error(tmp_path, capsys):
    result = main([
        "--session-dir", str(tmp_path / "missing"),
        "--destination", str(tmp_path / "export"),
    ])

    assert result == 2
    assert "Export error:" in capsys.readouterr().err


def test_cli_prevents_overwrite_without_flag(tmp_path, capsys):
    source = create_session(tmp_path / "session")
    destination = tmp_path / "export"
    destination.mkdir()
    (destination / "capture.pcap").write_bytes(b"keep existing file")

    result = main([
        "--session-dir", str(source),
        "--destination", str(destination),
    ])

    assert result == 2
    assert (destination / "capture.pcap").read_bytes() == b"keep existing file"
    assert "already contains" in capsys.readouterr().err


def test_cli_allows_explicit_overwrite(tmp_path, capsys):
    source = create_session(tmp_path / "session")
    destination = tmp_path / "export"
    destination.mkdir()
    (destination / "capture.pcap").write_bytes(b"old data")

    result = main([
        "--session-dir", str(source),
        "--destination", str(destination),
        "--overwrite",
    ])

    assert result == 0
    assert (destination / "capture.pcap").read_bytes() == b"\xd4\xc3\xb2\xa1"


def test_cli_help(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "--session-dir" in capsys.readouterr().out
