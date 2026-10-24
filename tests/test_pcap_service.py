
from unittest.mock import MagicMock, patch

import pytest

from pocket_sniffer.services.pcap_service import (
    PcapCapture,
    PcapCaptureError,
)


def test_rejects_invalid_interface(tmp_path):
    with pytest.raises(ValueError):
        PcapCapture("-i en0", tmp_path / "capture.pcap")


def test_tcpdump_missing_is_reported(tmp_path):
    capture = PcapCapture("en0", tmp_path / "capture.pcap")
    capture.tcpdump_path = None

    with pytest.raises(PcapCaptureError, match="not found"):
        capture.start()


def test_starts_with_pcap_output_and_stops(tmp_path):
    process = MagicMock()
    process.poll.side_effect = [None, None]
    process.returncode = 0
    process.stderr = None

    with (
        patch(
            "pocket_sniffer.services.pcap_service.subprocess.Popen",
            return_value=process,
        ) as popen,
        patch("pocket_sniffer.services.pcap_service.time.sleep"),
    ):
        capture = PcapCapture(
            "en0", tmp_path / "session" / "capture.pcap",
            tcpdump_path="/usr/sbin/tcpdump",
        )
        capture.start()

        args, kwargs = popen.call_args
        assert "-w" in args[0]
        assert str(capture.output_file) in args[0]
        assert kwargs["shell"] is False
        assert capture.stop() == 0

    process.send_signal.assert_called_once()


def test_permission_error_is_actionable(tmp_path):
    with patch(
        "pocket_sniffer.services.pcap_service.subprocess.Popen",
        side_effect=PermissionError("denied"),
    ):
        capture = PcapCapture(
            "en0", tmp_path / "capture.pcap",
            tcpdump_path="/usr/sbin/tcpdump",
        )
        with pytest.raises(PcapCaptureError, match="Permission denied"):
            capture.start()


def test_immediate_failure_includes_stderr(tmp_path):
    process = MagicMock()
    process.poll.return_value = 2
    process.stderr.read.return_value = b"unknown interface"

    with (
        patch(
            "pocket_sniffer.services.pcap_service.subprocess.Popen",
            return_value=process,
        ),
        patch("pocket_sniffer.services.pcap_service.time.sleep"),
    ):
        capture = PcapCapture(
            "bad0", tmp_path / "capture.pcap",
            tcpdump_path="/usr/sbin/tcpdump",
        )
        with pytest.raises(PcapCaptureError, match="unknown interface"):
            capture.start()


def test_sudo_prefixes_command(tmp_path):
    process = MagicMock()
    process.poll.side_effect = [None, None]
    process.returncode = 0
    process.stderr = None

    with (
        patch(
            "pocket_sniffer.services.pcap_service.shutil.which",
            return_value="/usr/bin/sudo",
        ),
        patch(
            "pocket_sniffer.services.pcap_service.subprocess.Popen",
            return_value=process,
        ) as popen,
        patch("pocket_sniffer.services.pcap_service.time.sleep"),
    ):
        capture = PcapCapture(
            "en0", tmp_path / "capture.pcap",
            tcpdump_path="/usr/sbin/tcpdump",
            use_sudo=True,
        )
        capture.start()

        args, kwargs = popen.call_args
        assert args[0][:2] == ["/usr/bin/sudo", "/usr/sbin/tcpdump"]
        assert kwargs["stdin"] is None
        capture.stop()
