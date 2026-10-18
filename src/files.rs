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
        io::ErrorKind,
        os::unix::fs::MetadataExt,
        path::{Component, Path},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    fn inspect(path: &Path) -> crate::Result<Value> {
        match fs::symlink_metadata(path) {
            Ok(m) => {
                if !m.is_file() && !m.file_type().is_symlink() {
                    return Err(format!(
                        "{}: select a file or symlink, not a directory/device",
                        path.display()
                    ));
                }
                Ok(
                    serde_json::json!({"size":m.len(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),
                    "inode":m.ino(),"device":m.dev(),"modified_seconds":m.mtime(),"modified_nanoseconds":m.mtime_nsec(),
                    "changed_seconds":m.ctime(),"changed_nanoseconds":m.ctime_nsec(),"symlink":m.file_type().is_symlink()}),
                )
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Value::Null),
            Err(e) => Err(format!("{}: metadata unavailable: {e}", path.display())),
        }
    }
    if paths.is_empty() || paths.len() > 64 {
        return Err("select 1..64 file paths".into());
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
    let mut previous: Option<Vec<Value>> = None;
    let mut sample = 0;
    loop {
        let current = paths
            .iter()
            .map(|p| inspect(p))
            .collect::<crate::Result<Vec<_>>>()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?;
        let timestamp = chrono::DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
            .ok_or("observation time out of range")?
            .to_rfc3339();
        if let Some(before) = &previous {
            for ((path, old), new) in paths.iter().zip(before).zip(&current) {
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
        previous = Some(current);
        sample += 1;
        eprintln!(
            "File snapshot {sample}: {} selected paths.{}",
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
