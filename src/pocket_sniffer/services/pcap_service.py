
"""Capture raw network packets to a standard PCAP file."""
from __future__ import annotations

import shutil
import signal
import subprocess
import time
from pathlib import Path


class PcapCaptureError(RuntimeError):
    """Raised when a PCAP capture cannot start or stop."""


class PcapCapture:
    """Manage a tcpdump process that writes packets to a PCAP file."""

    def __init__(
        self,
        interface: str,
        output_file: str | Path,
        *,
        tcpdump_path: str | None = None,
        use_sudo: bool = False,
    ) -> None:
        interface = interface.strip()
        if not interface or interface.startswith("-") or any(
            char.isspace() for char in interface
        ):
            raise ValueError("interface must be a valid interface name")

        self.interface = interface
        self.output_file = Path(output_file).expanduser().resolve()
        self.tcpdump_path = tcpdump_path or shutil.which("tcpdump")
        self.use_sudo = use_sudo
        self.process: subprocess.Popen | None = None
        self.last_stderr = ""

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            raise PcapCaptureError("Capture is already running")
        if not self.tcpdump_path:
            raise PcapCaptureError("tcpdump was not found on PATH")

        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.tcpdump_path,
            "-i", self.interface,
            "-n",
            "-U",
            "-w", str(self.output_file),
        ]

        if self.use_sudo:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise PcapCaptureError("sudo was requested but was not found")
            command.insert(0, sudo_path)

        try:
            self.process = subprocess.Popen(
                command,
                stdin=None if self.use_sudo else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            self.process = None
            if isinstance(exc, PermissionError):
                raise PcapCaptureError(
                    "Permission denied starting tcpdump. Try --sudo if authorized."
                ) from exc
            raise PcapCaptureError(f"Could not start tcpdump: {exc}") from exc

        time.sleep(0.2)
        code = self.process.poll()
        if code is not None:
            stderr = ""
            if self.process.stderr:
                stderr = self.process.stderr.read().decode(
                    "utf-8", "replace"
                ).strip()
            self.process = None
            detail = f": {stderr}" if stderr else ""
            raise PcapCaptureError(
                f"tcpdump exited during startup (code {code}){detail}"
            )

    def stop(self, *, timeout: float = 5.0) -> int | None:
        """Stop tcpdump and let it finalize the PCAP file."""
        process = self.process
        if process is None:
            return None

        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

        result = process.returncode
        if process.stderr:
            try:
                self.last_stderr = process.stderr.read().decode(
                    "utf-8", "replace"
                ).strip()
            except (OSError, ValueError):
                self.last_stderr = ""

        self.process = None
        return result

    def __enter__(self) -> "PcapCapture":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
