//! Restartable journal replay. Checkpoints are local trusted state, not portable input.
use crate::{
    session::{SavedSession, Session},
    ssh, Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_STATE: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    rules: Value,
    cursor: String,
    session: SavedSession,
    pending: Vec<Value>,
}

fn save(dir: &Path, state: &Snapshot) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() as u64 > MAX_STATE {
        return Err("checkpoint exceeds 64 MiB".into());
    }
    let next = dir.join("snapshot.next");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&next)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(next, dir.join("snapshot.json"))?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn deliver(dir: &Path, state: &mut Snapshot, output: &mut impl Write) -> Result<bool> {
    if state.pending.is_empty() {
        return Ok(false);
    }
    for alert in &state.pending {
        serde_json::to_writer(&mut *output, alert)?;
        writeln!(output)?;
    }
    output.flush()?;
    state.pending.clear();
    save(dir, state)?;
    Ok(true)
}

/// Input must replay through the saved journal cursor before supplying new records.
/// Pending alerts are committed before output; a crash may repeat their stable IDs.
pub fn scan(
    engine: Engine,
    dir: &Path,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<bool> {
    fs::create_dir_all(dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("lock"))?;
    lock.try_lock()
        .map_err(|e| format!("checkpoint is in use or cannot be locked: {e}"))?;
    let identity = engine.checkpoint_identity();
    let mut saved = match File::open(dir.join("snapshot.json")) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_STATE {
                return Err("checkpoint exceeds 64 MiB".into());
            }
            let state: Snapshot = serde_json::from_slice(&bytes)?;
            if state.version != 1 || state.rules != identity {
                return Err(
                    "checkpoint version or rules changed; use a new checkpoint directory".into(),
                );
            }
            if state.cursor.is_empty() || state.cursor.len() > 8192 {
                return Err("invalid checkpoint cursor".into());
            }
            for alert in &state.pending {
                let rule = alert["rule_id"].as_str().ok_or("invalid pending alert")?;
                if !engine.rules().any(|r| r.id == rule)
                    || alert["alert_id"] != serde_json::to_string(&(&state.cursor, rule))?
                {
                    return Err("invalid pending alert identity".into());
                }
            }
            Some(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let mut seeking = saved.as_ref().map(|s| s.cursor.clone());
    let mut pending = Vec::new();
    let mut session = if let Some(state) = saved.take() {
        pending = state.pending;
        Session::restore(engine, state.session)?
    } else {
        Session::new(engine)
    };
    let mut found = false;
    let mut line = String::new();
    let mut number = 0;
    loop {
        line.clear();
        let bytes = input.by_ref().take(1024 * 1024 + 1).read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        number += 1;
        if bytes > 1024 * 1024 {
            return Err(format!("journal line {number} exceeds 1 MiB").into());
        }
        if line.trim().is_empty() {
            continue;
        }
        let record: Value =
            serde_json::from_str(&line).map_err(|e| format!("journal line {number}: {e}"))?;
        let cursor = record
            .get("__CURSOR")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 8192 && !s.chars().any(char::is_control))
            .ok_or_else(|| format!("journal line {number}: checkpoint input requires __CURSOR"))?;
        if let Some(anchor) = &seeking {
            if anchor == cursor {
                seeking = None;
                let mut state = Snapshot {
                    version: 1,
                    rules: identity.clone(),
                    cursor: cursor.into(),
                    session: session.save(),
                    pending: std::mem::take(&mut pending),
                };
                found |= deliver(dir, &mut state, &mut output)?;
            }
            continue;
        }
        let event = ssh::parse_journal(&line).map_err(|e| format!("journal line {number}: {e}"))?;
        let mut alerts = match event {
            Some(event) => session
                .process(&event)
                .map_err(|e| format!("journal line {number}: {e}"))?,
            None => Vec::new(),
        };
        for alert in &mut alerts {
            // An encoded tuple is unambiguous even when rule IDs contain punctuation.
            alert["alert_id"] = Value::String(serde_json::to_string(&(cursor, &alert["rule_id"]))?);
        }
        let mut state = Snapshot {
            version: 1,
            rules: identity.clone(),
            cursor: cursor.into(),
            session: session.save(),
            pending: alerts,
        };
        save(dir, &state)?;
        found |= deliver(dir, &mut state, &mut output)?;
    }
    if seeking.is_some() {
        return Err("saved journal cursor was not found; replay retained journal history through that cursor (do not use --after-cursor or -n 0); checkpoint unchanged".into());
    }
    Ok(found)
}
