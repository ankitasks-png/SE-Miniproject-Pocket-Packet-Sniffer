
from pocket_sniffer.session_cli import main


def test_cli_shows_help(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0


def test_cli_lists_empty_index(tmp_path, capsys):
    database = tmp_path / "sessions.sqlite3"

    result = main(["--database", str(database), "list"])

    assert result == 0
    assert "No sessions indexed yet." in capsys.readouterr().out


def test_cli_indexes_and_lists_session(tmp_path, capsys):
    database = tmp_path / "sessions.sqlite3"
    session_dir = tmp_path / "capture-001"
    session_dir.mkdir()
    (session_dir / "conn.log").write_text(
        "#fields\tts\tproto\n1.0\ttcp\n",
        encoding="utf-8",
    )

    result = main([
        "--database", str(database),
        "index", str(session_dir),
    ])
    assert result == 0
    assert "Indexed session #1: capture-001" in capsys.readouterr().out

    result = main(["--database", str(database), "list"])
    output = capsys.readouterr().out

    assert result == 0
    assert "Saved capture sessions:" in output
    assert "capture-001" in output
    assert str(session_dir.resolve()) in output


def test_cli_shows_selected_session_files(tmp_path, capsys):
    database = tmp_path / "sessions.sqlite3"
    session_dir = tmp_path / "capture-002"
    session_dir.mkdir()
    (session_dir / "traffic.pcap").write_bytes(
        b"\xd4\xc3\xb2\xa1"
    )

    assert main([
        "--database", str(database),
        "index", str(session_dir),
    ]) == 0
    capsys.readouterr()

    result = main(["--database", str(database), "show", "1"])
    output = capsys.readouterr().out

    assert result == 0
    assert "Selected session #1: capture-002" in output
    assert "traffic.pcap" in output


def test_cli_handles_invalid_session_directory(tmp_path, capsys):
    database = tmp_path / "sessions.sqlite3"

    result = main([
        "--database", str(database),
        "index", str(tmp_path / "missing"),
    ])

    assert result == 2
    assert "Session directory does not exist" in capsys.readouterr().err


def test_cli_handles_unknown_session_id(tmp_path, capsys):
    database = tmp_path / "sessions.sqlite3"

    result = main(["--database", str(database), "show", "999"])

    assert result == 2
    assert "No session found with ID 999" in capsys.readouterr().err
