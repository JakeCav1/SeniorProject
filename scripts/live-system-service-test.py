"""Disposable Linux CI host only: verify actual system services and crash recovery."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

SPEC = importlib.util.spec_from_file_location("system_installer", Path(__file__).with_name("install-system-linux.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def wait_for(check, message, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise RuntimeError(message)


def active(name):
    return command("systemctl", "is-active", "--quiet", name, check=False).returncode == 0


def pid(name):
    return int(command("systemctl", "show", "-p", "MainPID", "--value", name).stdout.strip() or "0")


def alerts(name):
    output = command("journalctl", "-u", name, "--no-pager", "-o", "cat").stdout
    rows = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and "rule_id" in row:
            rows.append(row)
    return rows


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Requires root on a disposable Linux systemd test host")
    binary = Path(sys.argv[1]).resolve(strict=True)
    units = [INSTALLER.UNIT_DIR / name for name in [*INSTALLER.SERVICES, "chompedr.target"]]
    if any(p.exists() or p.is_symlink() for p in [INSTALLER.BINARY_PATH, Path("/var/lib/chomp-edr"), *units]):
        raise RuntimeError("Refusing to overwrite an existing system installation or checkpoint")
    written = []
    child = None
    with tempfile.TemporaryDirectory(prefix="chomp-system-live-", dir="/tmp") as folder:
        folder = Path(folder)
        watched = folder / "watched"
        watched.write_text("baseline")
        executable = folder / "demo-sleep"
        shutil.copy2(shutil.which("sleep"), executable)
        try:
            written = INSTALLER.install(binary, [str(watched)])
            command("systemctl", "daemon-reload")
            command("systemctl", "enable", "--now", "chompedr.target")
            command("systemctl", "is-enabled", "chompedr.target")
            wait_for(lambda: all(active(name) for name in INSTALLER.SERVICES), "Collectors did not start")
            # Wait for both polling baselines before changing the test host.
            def baseline(name):
                return "Baseline ready" in command("journalctl", "-u", name, "--no-pager", "-o", "cat").stdout
            wait_for(lambda: baseline("chompedr-files") and baseline("chompedr-processes"), "Missing baselines")
            watched.write_text("modified test configuration")
            wait_for(lambda: any(a["rule_id"] == "CHOMP-FILE-001" and
                                a["event"]["file"]["path"] == str(watched)
                                for a in alerts("chompedr-files")), "Missing file alert")
            child = subprocess.Popen([str(executable), "120"])
            wait_for(lambda: any(a["rule_id"] == "CHOMP-PROC-001" and
                                a["event"]["process"]["pid"] == child.pid
                                for a in alerts("chompedr-processes")), "Missing process alert")
            for name in INSTALLER.SERVICES:
                previous = pid(name)
                if previous <= 0:
                    raise RuntimeError(f"No main PID for {name}")
                command("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", name)
                wait_for(lambda: active(name) and pid(name) > 0 and pid(name) != previous,
                         f"Crash recovery failed: {name}")
            command("systemctl", "stop", "chompedr.target")
            wait_for(lambda: not any(active(name) for name in INSTALLER.SERVICES), "Target did not stop collectors")
            print("PASS: boot enablement, all collectors, file/process alerts, crash restarts and target stop")
        finally:
            command("systemctl", "disable", "--now", "chompedr.target", check=False)
            for name in INSTALLER.SERVICES:
                command("systemctl", "stop", name, check=False)
            if child is not None and child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            for path in written:
                path.unlink(missing_ok=True)
            if written:
                shutil.rmtree("/var/lib/chomp-edr", ignore_errors=True)
            command("systemctl", "daemon-reload", check=False)
            command("systemctl", "reset-failed", check=False)


if __name__ == "__main__":
    main()
