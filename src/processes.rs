//! Best-effort /proc polling, not an audit or exec tracing facility.
use serde_json::Value;

#[cfg(not(target_os = "linux"))]
pub fn collect(
    _: u64,
    _: Option<u64>,
    _: bool,
    _: impl FnMut(&Value) -> crate::Result<()>,
) -> crate::Result<()> {
    Err("process collection requires Linux /proc; use scan for exported events".into())
}

#[cfg(any(target_os = "linux", test))]
fn stat_fields(stat: &str) -> crate::Result<(u32, u64)> {
    // comm may contain whitespace and parentheses; split after its final ')'.
    let (_, tail) = stat.rsplit_once(')').ok_or("invalid process stat")?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    let ppid = fields
        .get(1)
        .ok_or("missing parent pid")?
        .parse()
        .map_err(|_| "invalid parent pid")?;
    let start = fields
        .get(19)
        .ok_or("missing start ticks")?
        .parse()
        .map_err(|_| "invalid start ticks")?;
    Ok((ppid, start))
}

#[cfg(target_os = "linux")]
pub fn collect(
    interval_ms: u64,
    samples: Option<u64>,
    include_existing: bool,
    mut emit: impl FnMut(&Value) -> crate::Result<()>,
) -> crate::Result<()> {
    use std::{
        collections::HashSet,
        fs,
        io::Read,
        path::Path,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    fn read(path: &Path, max: u64) -> crate::Result<String> {
        let mut text = String::new();
        fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(max + 1)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        if text.len() as u64 > max {
            return Err("process metadata exceeds limit".into());
        }
        Ok(text)
    }
    fn inspect(path: &Path) -> crate::Result<(u32, u64, String, u32)> {
        let before = stat_fields(&read(&path.join("stat"), 8192)?)?;
        let exe = fs::read_link(path.join("exe")).map_err(|e| e.to_string())?;
        let status = read(&path.join("status"), 65536)?;
        let uid: u32 = status
            .lines()
            .find_map(|s| s.strip_prefix("Uid:"))
            .and_then(|s| s.split_whitespace().nth(1))
            .ok_or("missing effective UID")?
            .parse()
            .map_err(|_| "invalid effective UID")?;
        let after = stat_fields(&read(&path.join("stat"), 8192)?)?;
        if before != after || fs::read_link(path.join("exe")).map_err(|e| e.to_string())? != exe {
            return Err("process changed while reading".into());
        }
        Ok((before.0, before.1, exe.to_string_lossy().into_owned(), uid))
    }
    if !(100..=60000).contains(&interval_ms) || samples == Some(0) {
        return Err("interval must be 100..60000 ms and sample count must be positive".into());
    }
    let host = read(Path::new("/proc/sys/kernel/hostname"), 256)?
        .trim()
        .to_owned();
    let boot = read(Path::new("/proc/sys/kernel/random/boot_id"), 128)?
        .trim()
        .to_owned();
    let mut previous = HashSet::new();
    let mut sample = 0;
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?;
        let timestamp = chrono::DateTime::from_timestamp(now.as_secs() as i64, now.subsec_nanos())
            .ok_or("observation timestamp out of range")?
            .to_rfc3339();
        let mut current = HashSet::new();
        let mut skipped = 0;
        let mut seen = 0;
        for entry in fs::read_dir("/proc").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            seen += 1;
            if seen > 131072 {
                return Err("process snapshot exceeds 131072 entries".into());
            }
            match inspect(&entry.path()) {
                Ok((ppid, start, exe, uid)) => {
                    let key = (pid, start, exe.clone());
                    if !previous.contains(&key) && (sample > 0 || include_existing) {
                        emit(&serde_json::json!({"timestamp":timestamp,"host":host,
                            "event":{"type":"process_observed"},"collector":{"method":"proc_poll","boot_id":boot,"interval_ms":interval_ms},
                            "process":{"pid":pid,"ppid":ppid,"start_ticks":start,"executable":exe},
                            "user":{"effective_uid":uid}}))?;
                    }
                    current.insert(key);
                }
                Err(_) => skipped += 1,
            }
        }
        previous = current;
        sample += 1;
        eprintln!(
            "Process snapshot {sample}: {} readable; {skipped} unavailable/changing.{}",
            previous.len(),
            if sample == 1 { " Baseline ready." } else { "" }
        );
        if samples.is_some_and(|n| sample >= n) {
            break;
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_parser_handles_parentheses_and_spaces_in_names() {
        let fields = [
            "S", "42", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "1", "0", "98765",
        ];
        assert_eq!(
            stat_fields(&format!("123 (odd ) name) {}", fields.join(" "))).unwrap(),
            (42, 98765)
        );
        assert!(stat_fields("broken").is_err());
        assert!(stat_fields("1 (x) S 2").is_err());
    }
}
