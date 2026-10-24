
"""CLI for a live Zeek capture session."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from pocket_sniffer.services.capture_service import CaptureError, ZeekCapture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pocket-sniffer-capture",
        description="Capture traffic with Zeek into a local session directory.",
    )
    parser.add_argument(
        "--interface", required=True, help="Network interface, e.g. en0"
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True,
        help="Directory for Zeek logs"
    )
    parser.add_argument(
        "--sudo", action="store_true",
        help="Run Zeek through sudo when capture permissions require it"
    )
    args = parser.parse_args(argv)

    capture = ZeekCapture(
        args.interface, args.output_dir, use_sudo=args.sudo
    )

    try:
        capture.start()
        print(f"Capture running on {args.interface}")
        print(f"Logs directory: {capture.output_dir}")
        print("Press Ctrl+C to stop and flush logs.")

        while capture.process is not None and capture.process.poll() is None:
            time.sleep(0.25)

        code = capture.stop()

        if code not in (0, -2, 130, None):
            print(f"Zeek exited with code {code}", file=sys.stderr)
            if capture.last_stderr:
                print(capture.last_stderr, file=sys.stderr)
            return 1

        print("Capture stopped. Files created:")
        for path in sorted(capture.output_dir.glob("*.log")):
            print(f"  {path.name}: {path.stat().st_size} bytes")
        return 0

    except KeyboardInterrupt:
        capture.stop()
        print("\nCapture stopped.")
        return 0

    except CaptureError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
