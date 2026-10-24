
"""Manage a live Zeek capture process without a shell."""
from __future__ import annotations

import shutil
import signal
import subprocess
import time
from pathlib import Path


class CaptureError(RuntimeError):
    """Raised when a live Zeek capture cannot be started or stopped."""


class ZeekCapture:
    """Run Zeek on an interface and save logs in a session directory."""

    def __init__(
        self,
        interface: str,
        output_dir: str | Path,
        *,
        zeek_path: str | None = None,
        use_sudo: bool = False,
    ):
        interface = interface.strip()
        if (
            not interface
            or interface.startswith("-")
            or any(c.isspace() for c in interface)
        ):
            raise ValueError("interface must be a valid interface name")

        self.interface = interface
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.zeek_path = zeek_path or shutil.which("zeek")
        self.use_sudo = use_sudo
        self.last_stderr = ""
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            raise CaptureError("Capture is already running")

        if not self.zeek_path:
            raise CaptureError(
                "Zeek was not found on PATH. Install Zeek and retry."
            )

        self.output_dir.mkdir(parents=True, exist_ok=True)

        command = [
            self.zeek_path,
            "-i",
            self.interface,
            f"Log::default_logdir={self.output_dir}",
        ]

        if self.use_sudo:
            sudo_path = shutil.which("sudo")
            if not sudo_path:
                raise CaptureError("sudo was requested but was not found")
            command.insert(0, sudo_path)

        try:
            self.process = subprocess.Popen(
                command,
                cwd=self.output_dir,
                stdin=None if self.use_sudo else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError as exc:
            self.process = None
            if isinstance(exc, PermissionError):
                raise CaptureError(
                    "Permission denied starting Zeek. Try the --sudo option "
                    "if your account is authorized to capture packets."
                ) from exc
            raise CaptureError(f"Could not start Zeek: {exc}") from exc

        # Detect startup failures quickly.
        time.sleep(0.3)
        code = self.process.poll()

        if code is not None:
            stderr = ""
            if self.process.stderr:
                stderr = self.process.stderr.read().decode(
                    "utf-8", "replace"
                ).strip()

            self.process = None
            detail = f": {stderr}" if stderr else ""
            raise CaptureError(
                f"Zeek exited during startup (code {code}){detail}"
            )

    def stop(self, *, timeout: float = 5.0) -> int | None:
        """Stop Zeek gracefully so it can flush its logs."""
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

    def __enter__(self) -> "ZeekCapture":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
