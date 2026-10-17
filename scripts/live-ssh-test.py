"""CI-only loopback SSH/journal integration check. Requires Linux, systemd, and root.

Creates an ephemeral SSH server with its own host key and configuration. It never
changes the host SSH service or creates users. All login attempts target 127.0.0.1.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid


def run(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30, **kwargs)


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run only on a Linux test host with root privileges and systemd")
    binary = Path(sys.argv[1]).resolve(strict=True)
    repo = Path(__file__).resolve().parents[1]
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not Path(sshd).is_file():
        raise RuntimeError("Install openssh-server on the test host first")
    username = "chomp-test-" + uuid.uuid4().hex[:12]
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise RuntimeError("Test username unexpectedly exists")
    unit = "chomp-ci-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="chomp-live-") as temp:
        folder = Path(temp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(folder / "host"))
        askpass = folder / "askpass"
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' 'chomp-ci-invalid-password'\n")
        askpass.chmod(0o700)
        client_env = dict(os.environ, SSH_ASKPASS=str(askpass),
                          SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
        config = folder / "sshd_config"
        config.write_text(f"""ListenAddress 127.0.0.1
Port {port}
HostKey {folder / 'host'}
PidFile {folder / 'pid'}
AuthorizedKeysFile none
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM no
PermitRootLogin no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
LogLevel VERBOSE
""")
        # Standard privilege-separation runtime directory; no host SSH config changes.
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        journal = scanner = None
        live_output = (folder / "alerts.jsonl").open("w")
        live_errors = (folder / "scan-errors.txt").open("w")
        try:
            run("systemd-run", "--unit", unit, "--property=RuntimeMaxSec=60",
                "--property=StandardOutput=journal", "--property=StandardError=journal",
                sshd, "-D", "-e", "-f", str(config))
            for _ in range(40):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Loopback SSH server did not start")
            # Keep stdin open: an alert must be observable before the stream ends.
            journal = subprocess.Popen(
                ["journalctl", "-u", unit, "--no-pager", "-o", "json", "-n", "all", "-f"],
                stdout=subprocess.PIPE, stderr=live_errors)
            scanner = subprocess.Popen(
                [str(binary), "scan", "-r", str(repo / "rules/ssh.yaml"),
                 "--input-format", "journal"],
                stdin=journal.stdout, stdout=live_output, stderr=live_errors)
            journal.stdout.close()
            for _ in range(6):
                result = run("ssh", "-F", "/dev/null", "-p", str(port),
                    "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1", "-o", "IdentityAgent=none",
                    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ConnectTimeout=3", "-o", "PreferredAuthentications=password",
                    f"{username}@127.0.0.1", "true", check=False,
                    env=client_env, stdin=subprocess.DEVNULL, start_new_session=True)
                if result.returncode != 255 or "Permission denied" not in result.stderr:
                    raise RuntimeError(f"Expected rejected loopback login: {result.stderr}")
            for _ in range(50):
                live = (folder / "alerts.jsonl").read_text()
                if live.endswith("\n"):
                    break
                if scanner.poll() is not None or journal.poll() is not None:
                    raise RuntimeError("Live pipeline exited: " + (folder / "scan-errors.txt").read_text())
                time.sleep(0.1)
            else:
                raise RuntimeError("No alert emitted while journal input remained open")
            if scanner.poll() is not None or journal.poll() is not None:
                raise RuntimeError("Live pipeline did not remain running")
            live_alerts = [json.loads(line) for line in live.splitlines()]
            if len(live_alerts) != 1 or live_alerts[0]["rule_id"] != "CHOMP-SSH-001":
                raise RuntimeError(f"Unexpected live alerts: {live}")
            raw = ""
            for _ in range(20):
                run("journalctl", "--sync")
                raw = run("journalctl", "-u", unit, "--no-pager", "-o", "json").stdout
                records = [json.loads(line) for line in raw.splitlines() if line.strip()]
                failures = [r for r in records if isinstance(r.get("MESSAGE"), str) and r["MESSAGE"].startswith("Failed password")]
                if len(failures) >= 5:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"Missing real SSH failure records in journal: {raw}")
            output = run(str(binary), "scan", "-r", str(repo / "rules/ssh.yaml"),
                "--input-format", "journal", input=raw)
            alerts = [json.loads(line) for line in output.stdout.splitlines()]
            if len(alerts) != 1 or alerts[0]["rule_id"] != "CHOMP-SSH-001":
                raise RuntimeError(f"Expected exactly one threshold alert: {output.stdout} {output.stderr}")
            if alerts[0]["event"]["source"]["ip"] != "127.0.0.1":
                raise RuntimeError("Alert did not originate from loopback")
            # Restart between the fourth and fifth actual failure, preserving the window.
            failures_seen = 0
            prefix = []
            for record in records:
                prefix.append(json.dumps(record))
                if str(record.get("MESSAGE", "")).startswith("Failed password"):
                    failures_seen += 1
                if failures_seen == 4:
                    break
            checkpoint_args = [str(binary), "scan", "-r", str(repo / "rules/ssh.yaml"),
                               "--input-format", "journal", "--checkpoint", str(folder / "state")]
            first = run(*checkpoint_args, input="\n".join(prefix) + "\n")
            resumed = run(*checkpoint_args, input=raw)
            repeated = run(*checkpoint_args, input=raw)
            resumed_alerts = [json.loads(line) for line in resumed.stdout.splitlines()]
            if first.stdout or repeated.stdout or len(resumed_alerts) != 1:
                raise RuntimeError("Checkpoint restart lost the window or duplicated an alert")
            if resumed_alerts[0]["rule_id"] != "CHOMP-SSH-001" or not resumed_alerts[0].get("alert_id"):
                raise RuntimeError("Checkpoint alert missing expected identity")
            print(f"PASS: {len(failures)} real rejected SSH logins -> journal JSON -> one grouped alert")
            print("PASS: journal follow pipeline emitted an alert before EOF and remained running")
            print("PASS: restart after four failures preserved the window; replay did not duplicate alerts")
        finally:
            if journal is not None:
                journal.terminate()
                journal.wait(timeout=10)
            if scanner is not None:
                try:
                    scanner.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    scanner.kill()
                    scanner.wait(timeout=10)
            live_output.close()
            live_errors.close()
            run("systemctl", "stop", unit, check=False)
            run("systemctl", "reset-failed", unit, check=False)


if __name__ == "__main__":
    main()
