# Selected-file metadata monitoring

On Linux, explicitly select the files you want to watch:

```sh
chompedr watch-files --path /etc/passwd --path /etc/shadow
```

This is read-only monitoring: Chomp does not open watched files for content access, hash their contents, or change permissions. The default embedded rule emits a medium-severity review alert for every observed metadata transition on a selected path. Legitimate account management and software updates also match.

## Commands

```sh
# Faster polling, stopping after ten snapshots including the baseline.
chompedr watch-files --path /absolute/path/to/config --interval-ms 500 --samples 10

# Export normalized events instead of alerts.
chompedr watch-files --path /absolute/path/to/config --events > file-events.jsonl

# Evaluate exported observations on any supported platform.
chompedr scan -r rules/file-watch.yaml -i file-events.jsonl
```

Repeat `--path` to select 1..64 absolute paths. Parent (`..`) components are rejected; paths are not canonicalized through symlinks. Duplicate identical paths are watched once. Files can be absent at startup; their later creation is detected. Existing directories and device files are rejected; no recursive scanning occurs. Other metadata-access errors stop monitoring rather than being misreported as removal.

`--interval-ms` is 100..60000 ms, default 1000. The delay is between snapshots and excludes scan time. `--samples` includes the initial baseline, which never emits alerts. `--events` conflicts with custom `-r` rules; pipe or save raw events for custom scanning. Stop foreground monitoring with Ctrl+C. Use the system terminal rather than the interactive Chomp prompt.

## Event meaning

Normalized events use `event.type: file_metadata_changed` and action `created`, `removed`, or `changed`. Their timestamp is observation time. `file.path` identifies the selected path. `file.before` and `file.after` contain size, numeric mode bits, owner/group IDs, inode/device numbers, modification/change timestamps in seconds and nanoseconds, and a symlink flag. Absent metadata is null. No contents or content hashes appear in events.

A final-component symlink is watched as a link; changes to its target file are not followed. To watch that target's metadata, select the target path separately. Symlinks in parent directories still participate in normal OS path resolution. Replacing the selected path can change the inode even if its size is unchanged. Access timestamps are omitted, so merely reading a file does not trigger an alert from an atime update.

## Limits and deployment

Polling can miss changes between observations, including transient create/remove sequences or changes that leave the compared metadata unchanged. There is no cryptographic content validation, process attribution, write interception, or blocking. Reads across multiple paths are not atomic. Namespaces and path permissions affect visibility; monitoring does not elevate privileges. Metadata may still be visible even when file contents are unreadable.

Baselines and rule correlation are in memory only. Restarting establishes a new baseline and does not report changes made while stopped. This is separate from SSH journal checkpoints, `watch-processes`, and the optional SSH service. File monitoring is not automatically installed as a background service.

The Linux CI check uses disposable files only. It tests creation, chmod on an unreadable file, atomic replacement, removal, final-symlink behavior, suppression of unchanged snapshots, and raw-event replay through `scan`. Production-scale polling, filesystem-specific timestamp behavior, and permission arrangements still need target-host validation.
