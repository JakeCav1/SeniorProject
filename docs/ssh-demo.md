# SSH detection demo

## Run it

From the repository root, build with `cargo build --release --locked`. Use `cargo run --` instead of `chompedr` if the installed executable has not been updated.

```sh
chompedr scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text
```

Inside the interactive `chompedr>` prompt, omit the executable name. Expected alerts: one `CHOMP-SSH-001` alert on the fifth failure from `198.51.100.20`, and one `CHOMP-SSH-002` alert for a root login. The example uses documentation IP addresses and synthetic records, not captured production activity. One unrelated PAM line is skipped and counted on stderr. `--fail-on-alert` returns code 1 when alerts occur; errors return code 2.

Normalization is also available independently:

```sh
chompedr normalize-ssh -i examples/ssh-demo.log > events.jsonl
chompedr scan -r rules/ssh.yaml -i events.jsonl
```

In PowerShell versions that redirect native output as UTF-16, use direct `--input-format ssh` scanning or explicitly save normalized output as UTF-8 without a BOM.

## Linux input

Supported input is an OpenSSH log record with an explicit ISO date, numeric UTC offset (or `Z`), hostname, and `sshd[pid]` or `sshd-session[pid]` prefix:

```text
2026-10-16T12:00:01+00:00 host sshd[101]: Failed password for invalid user admin from 198.51.100.20 port 50001 ssh2
```

Supported outcomes are `Failed` and `Accepted`; supported methods are `password`, `publickey`, and `keyboard-interactive/pam`. IPv4 and IPv6 addresses are validated and canonicalized. Port and PID must be valid unsigned values. The normalized object includes timestamp, host, event type/outcome, user, source IP/port, process, and authentication method.

If an existing Linux log file uses this format, scan it directly. To process new appended lines using an external collector:

```sh
tail -n 0 -F /path/to/iso-dated-auth.log | chompedr scan -r rules/ssh.yaml --input-format ssh -f text
```

Run this pipeline in the system shell, not the interactive Chomp prompt. Use an account that already has permission to read the log. `tail` is the external collector; Chomp does not configure logging, install a service, manage rotation, or maintain state across restarts. This command is an integration example, not evidence of a live-host test.

Yearless traditional syslog (`Oct 16 12:00:00 ...`) is not supported. Target authentication records with unsupported headers/methods or invalid fields stop the command with a line-numbered error. Unrelated lines are skipped; their count is reported on stderr at EOF. Blank scan lines are ignored.

## Linux journal input

`--input-format journal` accepts one JSON object per line from `journalctl -o json`. It reads `MESSAGE`, `_COMM`, `_HOSTNAME`, `_PID`, and `__REALTIME_TIMESTAMP` (microseconds since the Unix epoch). Records from `sshd`, `sshd-session`, and `sshd-auth` are supported. Missing or non-string message fields in SSH records are errors; binary/array message values are not supported. Required timestamp, host, and PID fields are checked for target authentication messages.

The adapter checks `_COMM`, not the user-supplied `SYSLOG_IDENTIFIER`. A record from another process merely labeling itself `sshd` is skipped. This relies on genuine journald metadata; an edited JSON file is not authenticated by Chomp.

From a Linux system shell with permission to read the journal:

```sh
set -o pipefail
journalctl --no-pager -o json -n 0 -f _COMM=sshd _COMM=sshd-session _COMM=sshd-auth | chompedr scan -r rules/ssh.yaml --input-format journal -f text
```

Repeated matches on the same journal field are alternatives. `-n 0 -f` starts with new records; remove those options and add an appropriate `--since` value for historical scanning. Run from the project folder or provide an absolute rule path. Chomp flushes alerts as it processes events. Stop the system-shell pipeline with Ctrl+C. This is an external journal pipeline, not a background service installed by Chomp. System clock corrections or combined logs can still cause the documented out-of-order timestamp error.

To inspect normalized journal events separately:

```sh
journalctl --no-pager -o json _COMM=sshd _COMM=sshd-session _COMM=sshd-auth | chompedr normalize-ssh --input-format journal
```

Use JSON Lines (`-o json`), not `json-pretty` or `json-seq`. Do not pass unfiltered arbitrary binary journal records as normalized event input.

## Isolated Linux integration test

The Linux CI job runs `sudo python3 scripts/live-ssh-test.py target/debug/chompedr`. It requires systemd and OpenSSH server on a disposable test host. The script creates its own temporary SSH keys/configuration and a transient service restricted to a random loopback port. Six public-key login attempts use a randomly generated nonexistent username; every login must be rejected. It reads that service's actual journal records and requires exactly one repeated-failure alert.

The transient service has a 60-second runtime limit and is stopped in cleanup. The script never modifies the host SSH service or creates users. This test verifies a real OpenSSH/journald pipeline; it does not establish detection accuracy across distributions or production workloads. See the latest GitHub Actions run for the result.

## Threshold rules

```yaml
threshold:
  count: 5
  window_seconds: 60
  group_by: [host, source.ip]
```

The optional top-level `threshold` applies after a rule's normal `all`, `any`, and `none` conditions. Only matching events count. Grouping by both host and IP avoids combining failures on separate endpoints. Successful logins do not reset failure counts.

- Time comes from the event's RFC3339 `timestamp`, not the wall clock. Every event in a scan with an enabled threshold rule must have a valid timestamp, even if it does not match that rule.
- Events must be globally nondecreasing by timestamp; equal times are allowed. Older timestamps are errors. Sort combined logs before scanning. There is no late-event buffer.
- The window is inclusive: events exactly 60 seconds apart can count together. Millisecond precision is used.
- An alert fires when a group reaches the threshold. While it stays at or above that threshold, subsequent matches are suppressed. It can alert again after expiration reduces the active count below the threshold.
- Each scan starts fresh. The interactive CLI does not retain correlation state between commands. Replayed/duplicate records count again; no event deduplication is implemented.
- `count` must be 2..1000; `window_seconds` must be 1..86400. There must be 1..8 dotted `group_by` paths. Each matching event must supply nonempty string group values of at most 256 bytes.
- At most 4096 active rule/group pairs are retained, each with at most `count` timestamps. Expired pairs are removed as event time advances. Exceeding capacity stops with an error rather than silently evicting detection history.
- JSON correlation alerts include `count` (the threshold), `window_seconds`, group paths/values, and the first contributing timestamp in milliseconds. The attached original event is the event that reached the threshold, not the entire history.

For library users, `Session::process` applies both stateless and threshold rules. `Engine::evaluate` handles only stateless rules; it never emits a threshold rule on a single event. Rules are validated before selection, so invalid configuration cannot be hidden with `--rule`.

## Verification and limitations

Tests cover normalization, invalid log formats, group isolation, boundary times, burst suppression/rearming, out-of-order events, malformed data, capacity/expiration, and equivalence between direct scans and normalization followed by JSON scanning. The SSH fixture also runs through the same cross-platform CI suite as the original engine.

These are review heuristics, not proof of compromise. Legitimate password mistakes and authorized root access can trigger them. Use local policy and representative real logs to tune rules before enabling any future responses. Automated endpoint actions are not implemented.

Implementation references: [OpenSSH authentication logging](https://github.com/openssh/openssh-portable/blob/master/auth.c), [Chrono timestamp parsing](https://docs.rs/chrono/latest/chrono/struct.DateTime.html), [systemd journal fields](https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml), and [journal JSON format](https://github.com/systemd/systemd/blob/main/docs/JOURNAL_EXPORT_FORMATS.md).
