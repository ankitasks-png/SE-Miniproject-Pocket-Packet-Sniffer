from pathlib import Path

from pocket_sniffer.cli import main


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "zeek"


def test_cli_renders_summary_and_alerts(capsys):
    assert main(["--log-dir", str(FIXTURE_DIR)]) == 0
    output = capsys.readouterr().out
    assert "Connections: 3" in output
    assert "TCP: 2" in output
    assert "192.0.2.10" in output
    assert "[HIGH]" in output


def test_cli_can_disable_alerts(capsys):
    assert main(["--log-dir", str(FIXTURE_DIR), "--no-alerts"]) == 0
    output = capsys.readouterr().out
    assert "Disabled for this report" in output
    assert "[HIGH]" not in output


def test_cli_reports_missing_directory(capsys, tmp_path):
    assert main(["--log-dir", str(tmp_path / "missing")]) == 2
    assert "Log directory does not exist" in capsys.readouterr().err


def test_cli_reports_directory_without_zeek_logs(capsys, tmp_path):
    assert main(["--log-dir", str(tmp_path)]) == 2
    assert "No conn.log or notice.log" in capsys.readouterr().err
