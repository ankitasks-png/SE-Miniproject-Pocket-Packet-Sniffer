
from unittest.mock import MagicMock, patch

from pocket_sniffer.pcap_cli import main


def test_pcap_cli_starts_and_stops(tmp_path):
    output = tmp_path / "capture.pcap"
    output.write_bytes(b"\xd4\xc3\xb2\xa1")

    fake = MagicMock()
    fake.output_file = output
    fake.process.poll.side_effect = [None, 0]
    fake.stop.return_value = 0
    fake.last_stderr = ""

    with (
        patch("pocket_sniffer.pcap_cli.PcapCapture", return_value=fake),
        patch("pocket_sniffer.pcap_cli.time.sleep"),
    ):
        assert main(["--interface", "en0", "--output", str(output)]) == 0

    fake.start.assert_called_once()
    fake.stop.assert_called_once()


def test_pcap_cli_rejects_non_pcap_output(tmp_path):
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["--interface", "en0", "--output", str(tmp_path / "capture.txt")])

    assert exc.value.code == 2


def test_pcap_cli_capture_error(tmp_path):
    from pocket_sniffer.services.pcap_service import PcapCaptureError

    with patch(
        "pocket_sniffer.pcap_cli.PcapCapture"
    ) as capture_class:
        capture_class.return_value.start.side_effect = PcapCaptureError("no permission")
        result = main([
            "--interface", "en0",
            "--output", str(tmp_path / "capture.pcap"),
        ])

    assert result == 2
