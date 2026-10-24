
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
