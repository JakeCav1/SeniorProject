//! Selected-path metadata polling. Never reads watched file contents.
use serde_json::Value;
use std::path::PathBuf;

#[cfg(not(target_os = "linux"))]
pub fn watch(
    _: Vec<PathBuf>,
    _: u64,
    _: Option<u64>,
    _: impl FnMut(&Value) -> crate::Result<()>,
) -> crate::Result<()> {
    Err("file metadata monitoring requires Linux; use scan for exported events".into())
}

#[cfg(target_os = "linux")]
pub fn watch(
    paths: Vec<PathBuf>,
    interval_ms: u64,
    samples: Option<u64>,
    mut emit: impl FnMut(&Value) -> crate::Result<()>,
) -> crate::Result<()> {
    use std::{
        collections::BTreeSet,
        fs,
        path::Component,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    if paths.is_empty() || paths.len() > 64 {
        return Err("select 1..64 file or directory paths".into());
    }
    if !(100..=60000).contains(&interval_ms) || samples == Some(0) {
        return Err("invalid polling interval or sample count".into());
    }
    for path in &paths {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(
                "watched paths must be absolute and contain no dot/parent components".into(),
            );
        }
    }
    let paths: Vec<_> = paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .map_err(|e| e.to_string())?
        .trim()
        .to_owned();
    let mut previous: Option<std::collections::BTreeMap<PathBuf, Value>> = None;
    let mut sample = 0;
    loop {
        let current = snapshot(&paths, 100_000, 128)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?;
        let timestamp = chrono::DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
            .ok_or("observation time out of range")?
            .to_rfc3339();
        if let Some(before) = &previous {
            let all_paths: BTreeSet<_> = before.keys().chain(current.keys()).collect();
            for path in all_paths {
                let old = before.get(path).unwrap_or(&Value::Null);
                let new = current.get(path).unwrap_or(&Value::Null);
                if old != new {
                    let change = if old.is_null() {
                        "created"
                    } else if new.is_null() {
                        "removed"
                    } else {
                        "changed"
                    };
                    emit(&serde_json::json!({"timestamp":timestamp,"host":host,
                        "event":{"type":"file_metadata_changed","action":change},
                        "collector":{"method":"metadata_poll","interval_ms":interval_ms},
                        "file":{"path":path,"before":old,"after":new}}))?;
                }
            }
        }
        let file_count = current.len();
        previous = Some(current);
        sample += 1;
        eprintln!(
            "File snapshot {sample}: {} selected paths, {file_count} files/symlinks.{}",
            paths.len(),
            if sample == 1 { " Baseline ready." } else { "" }
        );
        if samples.is_some_and(|n| sample >= n) {
            break;
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    Ok(())
}

/// Rescan roots each time so newly created subdirectories are included.
/// Build the whole snapshot before emitting changes; errors never imply removals.
#[cfg(target_os = "linux")]
fn snapshot(
    roots: &[PathBuf],
    max_entries: usize,
    max_depth: usize,
) -> crate::Result<std::collections::BTreeMap<PathBuf, Value>> {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::ErrorKind,
        os::unix::fs::MetadataExt,
    };
    let mut result = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut pending: Vec<_> = roots.iter().cloned().map(|p| (p, 0usize, true)).collect();
    let mut discovered = pending.len();
    while let Some((path, depth, explicit)) = pending.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        if visited.len() > max_entries || depth > max_depth {
            return Err("recursive file watch limit exceeded (100000 entries / 128 directory levels); choose a smaller directory".into());
        }
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: metadata unavailable: {e}", path.display())),
        };
        if m.is_dir() {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: directory unavailable: {e}", path.display())),
            };
            for entry in entries {
                let entry = entry
                    .map_err(|e| format!("{}: directory entry unavailable: {e}", path.display()))?;
                discovered += 1;
                if discovered > max_entries {
                    return Err("recursive file watch limit exceeded (100000 entries); choose a smaller directory".into());
                }
                pending.push((entry.path(), depth + 1, false));
            }
        } else if m.is_file() || m.file_type().is_symlink() {
            result.insert(path, serde_json::json!({"size":m.len(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),
                "inode":m.ino(),"device":m.dev(),"modified_seconds":m.mtime(),"modified_nanoseconds":m.mtime_nsec(),
                "changed_seconds":m.ctime(),"changed_nanoseconds":m.ctime_nsec(),"symlink":m.file_type().is_symlink()}));
        } else if explicit {
            return Err(format!(
                "{}: select a regular file, symlink, or directory, not a device/socket/FIFO",
                path.display()
            ));
        }
        // Descendant devices, sockets and FIFOs are skipped without opening them.
    }
    Ok(result)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn recursive_snapshot_deduplicates_roots_and_enforces_bounds() {
        let root =
            std::env::temp_dir().join(format!("chomp-recursive-unit-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/file"), "test").unwrap();
        let rows = snapshot(&[root.clone(), root.join("nested/file")], 100, 128).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(snapshot(std::slice::from_ref(&root), 2, 128).is_err());
        assert!(snapshot(std::slice::from_ref(&root), 100, 0).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
