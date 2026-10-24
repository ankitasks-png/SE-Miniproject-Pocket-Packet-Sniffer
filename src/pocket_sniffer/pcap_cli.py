
"""Command-line interface for raw PCAP capture."""
from __future__ import annotations

import argparse
import sys
import time
import signal
from pathlib import Path

from pocket_sniffer.services.pcap_service import (
    PcapCapture,
    PcapCaptureError,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pocket-sniffer-pcap",
        description="Capture raw network packets to a PCAP file.",
    )
    parser.add_argument(
        "--interface", required=True, help="Network interface, e.g. en0"
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Destination .pcap file",
    )
    parser.add_argument(
        "--sudo", action="store_true",
        help="Use sudo if capture permissions require it",
    )
    args = parser.parse_args(argv)

    if args.output.suffix.lower() != ".pcap":
        parser.error("--output must end with .pcap")

    capture = PcapCapture(
        args.interface, args.output, use_sudo=args.sudo
    )

    try:
        capture.start()
        print(f"Capturing on {args.interface}")
        print(f"PCAP output: {capture.output_file}")
        print("Press Ctrl+C to stop and finalize the capture.")

        while capture.process is not None and capture.process.poll() is None:
            time.sleep(0.25)

        code = capture.stop()
        if code not in (0, -signal.SIGINT, 130, None):
            print(f"tcpdump exited with code {code}", file=sys.stderr)
            if capture.last_stderr:
                print(capture.last_stderr, file=sys.stderr)
            return 1

        if capture.output_file.is_file():
            print(
                f"Capture saved: {capture.output_file} "
                f"({capture.output_file.stat().st_size} bytes)"
            )
        else:
            print("Capture ended, but no PCAP file was created.", file=sys.stderr)
            return 1
        return 0

    except KeyboardInterrupt:
        capture.stop()
        print("\nCapture stopped.")
        return 0
    except PcapCaptureError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
