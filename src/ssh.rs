//! Normalization of ISO-dated OpenSSH authentication log records.
use regex::Regex;
use serde_json::{json, Value};
use std::{net::IpAddr, sync::OnceLock};

pub fn parse(line: &str) -> Result<Option<Value>, String> {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static AUTH: OnceLock<Regex> = OnceLock::new();
    let header = HEADER
        .get_or_init(|| Regex::new(r"^(\S+)\s+(\S+)\s+sshd(?:-session)?\[(\d+)\]: (.*)$").unwrap());
    let auth = AUTH.get_or_init(|| Regex::new(r"^(Failed|Accepted) (password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port (\d+) ssh2(?:[: ].*)?$").unwrap());
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
    let c = auth
        .captures(&h[4])
        .ok_or("unsupported SSH authentication record")?;
    let time = chrono::DateTime::parse_from_rfc3339(&h[1])
        .or_else(|_| chrono::DateTime::parse_from_str(&h[1], "%Y-%m-%dT%H:%M:%S%.f%z"))
        .map_err(|_| "invalid SSH timestamp; expected ISO date and UTC offset")?;
    let ip: IpAddr = c[5].parse().map_err(|_| "invalid SSH source IP")?;
    let port: u16 = c[6].parse().map_err(|_| "invalid SSH source port")?;
    let pid: u32 = h[3].parse().map_err(|_| "invalid SSH process ID")?;
    Ok(Some(
        json!({"timestamp":time.to_rfc3339(), "host":h[2].to_owned(),
        "event":{"type":"ssh_auth", "outcome":if &c[1] == "Failed" {"failure"} else {"success"}},
        "user":{"name":c[4].to_owned(), "invalid":c.get(3).is_some()},
        "source":{"ip":ip.to_string(),"port":port},
        "process":{"name":"sshd","pid":pid}, "auth":{"method":c[2].to_owned()}}),
    ))
}
