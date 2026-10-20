"""Verify metadata polling using only disposable files; no system files are changed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

binary = Path(sys.argv[1]).resolve(strict=True)
repo = Path(__file__).resolve().parents[1]


def wait_for(check, message):
    for _ in range(150):
        if check():
            return
        time.sleep(0.02)
    raise RuntimeError(message)


with tempfile.TemporaryDirectory(prefix="chomp-files-") as folder:
    folder = Path(folder)
    selected = folder / "selected"
    for raw in (False, True):
        if selected.exists() or selected.is_symlink():
            selected.unlink()
        output_path = folder / ("raw" if raw else "alerts")
        diagnostics = folder / ("raw-errors" if raw else "errors")
        with output_path.open("w") as output, diagnostics.open("w") as errors:
            args = [str(binary), "watch-files", "--path", str(selected), "--interval-ms", "100"]
            if raw:
                args.append("--events")
            watcher = subprocess.Popen(args, stdout=output, stderr=errors)
            try:
                wait_for(lambda: "Baseline ready" in diagnostics.read_text(), "Missing file baseline")
                def rows():
                    text = output_path.read_text()
                    return [json.loads(line) for line in text.splitlines(keepends=True) if line.endswith("\n")]
                def event(row):
                    return row if raw else row["event"]
                def expect(count, action):
                    wait_for(lambda: len(rows()) >= count, f"Missing {action} observation")
                    current = rows()
                    if len(current) != count or event(current[-1])["event"]["action"] != action:
                        raise RuntimeError(f"Unexpected observations: {current}")
                selected.write_text("PRIVATE_FILE_CONTENT_MUST_NOT_APPEAR")
                expect(1, "created")
                selected.chmod(0o000)
                expect(2, "changed")
                replacement = folder / "replacement"
                replacement.write_text("replacement")
                os.replace(replacement, selected)
                expect(3, "changed")
                selected.unlink()
                expect(4, "removed")
                target = folder / "target"
                target.write_text("target before")
                selected.symlink_to(target)
                expect(5, "created")
                target.write_text("target after, with new size")
                time.sleep(0.3)
                if len(rows()) != 5:
                    raise RuntimeError("Final symlink target was followed or unchanged metadata repeated")
                if "PRIVATE_FILE_CONTENT_MUST_NOT_APPEAR" in output_path.read_text():
                    raise RuntimeError("File content appeared in output")
                if raw:
                    replay = subprocess.run([str(binary), "scan", "-r", str(repo / "rules/file-watch.yaml")],
                        input=output_path.read_text(), capture_output=True, text=True, check=True, timeout=10)
                    if len(replay.stdout.splitlines()) != 5:
                        raise RuntimeError("File observations did not replay through scan")
                elif any(row["rule_id"] != "CHOMP-FILE-001" for row in rows()):
                    raise RuntimeError("Unexpected rule ID")
                if watcher.poll() is not None:
                    raise RuntimeError("Watcher stopped unexpectedly")
            finally:
                if watcher.poll() is None:
                    watcher.terminate()
                watcher.wait(timeout=10)
    for path in ("relative", str(folder / ".." / "bad")):
        result = subprocess.run([str(binary), "watch-files", "--path", path, "--samples", "1"],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 2:
            raise RuntimeError("Invalid file selection accepted")
    print("PASS: creation, chmod, replacement, removal, symlink semantics, raw replay, and no repeated unchanged events")


with tempfile.TemporaryDirectory(prefix="chomp-recursive-") as folder:
    folder = Path(folder)
    root = folder / "watched"
    nested = root / "existing"
    nested.mkdir(parents=True)
    existing = nested / "original"
    existing.write_text("baseline")
    output_path = folder / "events"
    diagnostics = folder / "diagnostics"
    with output_path.open("w") as output, diagnostics.open("w") as errors:
        watcher = subprocess.Popen([str(binary), "watch-files", "--path", str(root),
            "--path", str(existing), "--interval-ms", "100", "--events"], stdout=output, stderr=errors)
        try:
            wait_for(lambda: "Baseline ready" in diagnostics.read_text(), "Missing recursive baseline")
            def rows():
                return [json.loads(line) for line in output_path.read_text().splitlines(keepends=True) if line.endswith("\n")]
            def expect_recursive(count, path, action):
                wait_for(lambda: len(rows()) >= count, f"Missing recursive {action}: {path}")
                current = rows()
                if len(current) != count or current[-1]["file"]["path"] != str(path) or current[-1]["event"]["action"] != action:
                    raise RuntimeError(f"Unexpected recursive observations: {current}")
            if rows():
                raise RuntimeError("Baseline emitted alerts")
            replacement = folder / "replacement"
            replacement.write_text("updated baseline file")
            os.replace(replacement, existing)
            expect_recursive(1, existing, "changed")
            # Publish a complete subtree between samples.
            staged = folder / "staged"
            (staged / "deeper").mkdir(parents=True)
            (staged / "deeper" / "new").write_text("new file")
            added = root / "added"
            os.replace(staged, added)
            new_file = added / "deeper" / "new"
            expect_recursive(2, new_file, "created")
            os.replace(added, folder / "removed-subtree")
            expect_recursive(3, new_file, "removed")
            loop = root / "loop"
            loop.symlink_to(root, target_is_directory=True)
            expect_recursive(4, loop, "created")
            outside = folder / "outside"
            outside.mkdir()
            outside_file = outside / "private"
            outside_file.write_text("before")
            link = root / "external-link"
            link.symlink_to(outside, target_is_directory=True)
            expect_recursive(5, link, "created")
            outside_file.write_text("after with a different size")
            os.mkfifo(root / "pipe")
            time.sleep(0.4)
            if len(rows()) != 5 or watcher.poll() is not None:
                raise RuntimeError("Symlink traversal, duplicate events, or special-file blocking")
            replay = subprocess.run([str(binary), "scan", str(repo / "rules/file-watch.yaml")],
                input=output_path.read_text(), capture_output=True, text=True, check=True, timeout=10)
            if len(replay.stdout.splitlines()) != 5:
                raise RuntimeError("Recursive observations failed replay")
            # The CI watcher runs as an ordinary user: unreadable subdirectories
            # must stop the scan, not masquerade as mass file removals.
            nested.chmod(0o000)
            wait_for(lambda: watcher.poll() is not None, "Unreadable directory did not stop monitoring")
            if watcher.returncode != 2 or len(rows()) != 5:
                raise RuntimeError("Partial recursive snapshot emitted misleading removals")
        finally:
            nested.chmod(0o700)
            if watcher.poll() is None:
                watcher.terminate()
            watcher.wait(timeout=10)
    print("PASS: recursive baseline, overlapping roots, nested changes, subtree creation/removal, symlink loops, special files, and permission errors")
