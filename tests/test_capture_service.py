
from unittest.mock import MagicMock, patch

import pytest

from pocket_sniffer.services.capture_service import (
    CaptureError,
    ZeekCapture,
)


def test_starts_zeek_without_shell_and_stops_cleanly(tmp_path):
    process = MagicMock()
    process.poll.return_value = None
    process.returncode = 0
    process.stderr = None

    with (
        patch(
            "pocket_sniffer.services.capture_service.subprocess.Popen",
            return_value=process,
        ) as popen,
        patch("pocket_sniffer.services.capture_service.time.sleep"),
    ):
        capture = ZeekCapture(
            "en0",
            tmp_path / "session",
            zeek_path="/usr/local/bin/zeek",
        )
        capture.start()

        args, kwargs = popen.call_args
        assert args[0][:3] == [
            "/usr/local/bin/zeek",
            "-i",
            "en0",
        ]
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == (tmp_path / "session").resolve()

        assert capture.stop() == 0


def test_rejects_invalid_interface(tmp_path):
    with pytest.raises(ValueError):
        ZeekCapture("-i", tmp_path / "session")


def test_missing_zeek_is_reported(tmp_path):
    with patch(
        "pocket_sniffer.services.capture_service.shutil.which",
        return_value=None,
    ):
        capture = ZeekCapture("en0", tmp_path / "session")
        with pytest.raises(CaptureError, match="Zeek was not found"):
            capture.start()


def test_permission_error_has_actionable_message(tmp_path):
    from unittest.mock import patch

    from pocket_sniffer.services.capture_service import CaptureError, ZeekCapture

    with patch(
        "pocket_sniffer.services.capture_service.subprocess.Popen",
        side_effect=PermissionError("denied"),
    ):
        capture = ZeekCapture("en0", tmp_path, zeek_path="/usr/bin/zeek")
        with pytest.raises(CaptureError, match="Permission denied"):
            capture.start()


def test_immediate_zeek_failure_includes_stderr(tmp_path):
    from unittest.mock import MagicMock, patch

    from pocket_sniffer.services.capture_service import CaptureError, ZeekCapture

    process = MagicMock()
    process.poll.return_value = 2
    process.stderr.read.return_value = b"unknown interface"

    with (
        patch(
            "pocket_sniffer.services.capture_service.subprocess.Popen",
            return_value=process,
        ),
        patch("pocket_sniffer.services.capture_service.time.sleep"),
    ):
        capture = ZeekCapture("bad0", tmp_path, zeek_path="/usr/bin/zeek")
        with pytest.raises(CaptureError, match="unknown interface"):
            capture.start()



def test_capture_cli_success(tmp_path):
    from unittest.mock import MagicMock, patch
    from pocket_sniffer.capture import main

    fake_capture = MagicMock()
    fake_capture.output_dir = tmp_path
    fake_capture.process.poll.side_effect = [None, 0]
    fake_capture.stop.return_value = 0
    fake_capture.last_stderr = ""

    (tmp_path / "conn.log").write_text("sample log\n")

    with patch("pocket_sniffer.capture.ZeekCapture", return_value=fake_capture), \
         patch("pocket_sniffer.capture.time.sleep"):
        result = main([
            "--interface", "en0",
            "--output-dir", str(tmp_path),
        ])

    assert result == 0
    fake_capture.start.assert_called_once()
    fake_capture.stop.assert_called_once()


def test_capture_cli_start_error(tmp_path):
    from unittest.mock import patch
    from pocket_sniffer.capture import main
    from pocket_sniffer.services.capture_service import CaptureError

    with patch(
        "pocket_sniffer.capture.ZeekCapture"
    ) as capture_class:
        capture_class.return_value.start.side_effect = CaptureError(
            "Zeek unavailable"
        )

        result = main([
            "--interface", "en0",
            "--output-dir", str(tmp_path),
        ])

    assert result == 2


def test_capture_cli_reports_unexpected_exit(tmp_path):
    from unittest.mock import MagicMock, patch
    from pocket_sniffer.capture import main

    fake_capture = MagicMock()
    fake_capture.output_dir = tmp_path
    fake_capture.process.poll.return_value = 1
    fake_capture.stop.return_value = 1
    fake_capture.last_stderr = "capture failed"

    with patch(
        "pocket_sniffer.capture.ZeekCapture",
        return_value=fake_capture,
    ):
        result = main([
            "--interface", "en0",
            "--output-dir", str(tmp_path),
        ])

    assert result == 1
