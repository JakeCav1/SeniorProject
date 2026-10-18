"""Observe a harmless copied sleep process; no elevated privileges required."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

binary = Path(sys.argv[1]).resolve(strict=True)
repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="chomp-proc-", dir="/tmp") as folder:
    folder = Path(folder)
    executable = folder / "demo-sleep"
    shutil.copy2(shutil.which("sleep"), executable)
    child = watcher = None
    with (folder / "alerts").open("w") as output, (folder / "diagnostics").open("w") as errors:
        try:
            watcher = subprocess.Popen([str(binary), "watch-processes", "--interval-ms", "100", "--samples", "40"], stdout=output, stderr=errors)
            for _ in range(100):
                if "Baseline ready" in (folder / "diagnostics").read_text():
                    break
                if watcher.poll() is not None:
                    raise RuntimeError("Process collector exited before baseline")
                time.sleep(0.02)
            else:
                raise RuntimeError("Process collector did not establish baseline")
            child = subprocess.Popen([str(executable), "15"])
            watcher.wait(timeout=15)
            if watcher.returncode != 0:
                raise RuntimeError((folder / "diagnostics").read_text())
            alerts = [json.loads(line) for line in (folder / "alerts").read_text().splitlines()]
            target = [a for a in alerts if a["event"]["process"]["pid"] == child.pid]
            if len(target) != 1 or target[0]["rule_id"] != "CHOMP-PROC-001":
                raise RuntimeError(f"Expected one alert for copied sleep, got {target}")
            raw = subprocess.run([str(binary), "watch-processes", "--events", "--include-existing", "--interval-ms", "100", "--samples", "3"], capture_output=True, text=True, timeout=10, check=True)
            events = [json.loads(line) for line in raw.stdout.splitlines()]
            target = [e for e in events if e["process"]["pid"] == child.pid]
            if len(target) != 1 or target[0]["process"]["executable"] != str(executable):
                raise RuntimeError("Raw collection did not preserve process identity/deduplication")
            if "cmdline" in target[0]["process"] or "environment" in target[0]["process"]:
                raise RuntimeError("Collector unexpectedly included command arguments or environment")
            scan = subprocess.run([str(binary), "scan", "-r", str(repo / "rules/processes.yaml")], input=json.dumps(target[0])+"\n", capture_output=True, text=True, timeout=10, check=True)
            if json.loads(scan.stdout)["rule_id"] != "CHOMP-PROC-001":
                raise RuntimeError("Collected event did not work through scan")
            print("PASS: new process observed once; include-existing/raw output and scan detection verified")
        finally:
            for process in (watcher, child):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
