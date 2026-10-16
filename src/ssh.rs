//! Normalization of ISO-dated OpenSSH authentication log records.
use regex::Regex;
use serde_json::{json, Value};
use std::{net::IpAddr, sync::OnceLock};

pub fn parse(line: &str) -> Result<Option<Value>, String> {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    let header = HEADER
        .get_or_init(|| Regex::new(r"^(\S+)\s+(\S+)\s+sshd(?:-session)?\[(\d+)\]: (.*)$").unwrap());
    let Some(h) = header.captures(line.trim_end()) else {
        if line.contains("sshd") && (line.contains(": Failed ") || line.contains(": Accepted ")) {
            return Err(
                "unsupported SSH log header; use an ISO timestamp with year and UTC offset".into(),
            );
        }
        return Ok(None);
    };
    if !h[4].starts_with("Failed ") && !h[4].starts_with("Accepted ") {
        return Ok(None);
    }
    let time = chrono::DateTime::parse_from_rfc3339(&h[1])
        .or_else(|_| chrono::DateTime::parse_from_str(&h[1], "%Y-%m-%dT%H:%M:%S%.f%z"))
        .map_err(|_| "invalid SSH timestamp; expected ISO date and UTC offset")?;
    let pid: u32 = h[3].parse().map_err(|_| "invalid SSH process ID")?;
    normalize(&time.to_rfc3339(), &h[2], pid, &h[4])
}

fn normalize(
    timestamp: &str,
    host: &str,
    pid: u32,
    message: &str,
) -> Result<Option<Value>, String> {
    static AUTH: OnceLock<Regex> = OnceLock::new();
    let auth = AUTH.get_or_init(|| Regex::new(r"^(Failed|Accepted) (password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port (\d+) ssh2(?:[: ].*)?$").unwrap());
    if !message.starts_with("Failed ") && !message.starts_with("Accepted ") {
        return Ok(None);
    }
    let c = auth
        .captures(message)
        .ok_or("unsupported SSH authentication record")?;
    let ip: IpAddr = c[5].parse().map_err(|_| "invalid SSH source IP")?;
    let port: u16 = c[6].parse().map_err(|_| "invalid SSH source port")?;
    Ok(Some(json!({"timestamp":timestamp, "host":host,
        "event":{"type":"ssh_auth", "outcome":if &c[1] == "Failed" {"failure"} else {"success"}},
        "user":{"name":c[4].to_owned(), "invalid":c.get(3).is_some()},
        "source":{"ip":ip.to_string(),"port":port},
        "process":{"name":"sshd","pid":pid}, "auth":{"method":c[2].to_owned()}})))
}

/// Read one journalctl -o json record. Use journald's process metadata, never
/// SYSLOG_IDENTIFIER alone, to decide whether the record belongs to OpenSSH.
pub fn parse_journal(line: &str) -> Result<Option<Value>, String> {
    let event: Value =
        serde_json::from_str(line).map_err(|e| format!("invalid journal JSON: {e}"))?;
    if !event.is_object() {
        return Err("journal record must be a JSON object".into());
    }
    if !matches!(
        event.get("_COMM").and_then(Value::as_str),
        Some("sshd" | "sshd-session" | "sshd-auth")
    ) {
        return Ok(None);
    }
    let message = event
        .get("MESSAGE")
        .and_then(Value::as_str)
        .ok_or("SSH journal MESSAGE must be a string")?;
    if !message.starts_with("Failed ") && !message.starts_with("Accepted ") {
        return Ok(None);
    }
    let micros = event
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .ok_or("SSH journal record requires __REALTIME_TIMESTAMP")?
        .parse::<u64>()
        .map_err(|_| "invalid journal timestamp")?;
    let time = i64::try_from(micros)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_micros)
        .ok_or("journal timestamp out of range")?;
    let host = event
        .get("_HOSTNAME")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_whitespace))
        .ok_or("SSH journal record requires a valid _HOSTNAME")?;
    let pid = event
        .get("_PID")
        .and_then(Value::as_str)
        .ok_or("SSH journal record requires _PID")?
        .parse::<u32>()
        .map_err(|_| "invalid journal process ID")?;
    normalize(&time.to_rfc3339(), host, pid, message)
}
