use chomp_edr::ssh;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn record() -> Value {
    json!({"_COMM":"sshd", "_HOSTNAME":"lab", "_PID":"123",
        "__REALTIME_TIMESTAMP":"1792152000000000",
        "MESSAGE":"Failed password for root from 192.0.2.1 port 1234 ssh2"})
}

#[test]
fn journal_normalizes_microseconds_and_process_variants() {
    for name in ["sshd", "sshd-session", "sshd-auth"] {
        let mut r = record();
        r["_COMM"] = json!(name);
        let e = ssh::parse_journal(&r.to_string()).unwrap().unwrap();
        assert_eq!(e["timestamp"], "2026-10-16T12:00:00+00:00");
        assert_eq!(e["source"]["ip"], "192.0.2.1");
        assert_eq!(e["process"]["pid"], 123);
    }
    let mut r = record();
    r["__REALTIME_TIMESTAMP"] = json!("1792152000123456");
    assert_eq!(
        ssh::parse_journal(&r.to_string()).unwrap().unwrap()["timestamp"],
        "2026-10-16T12:00:00.123456+00:00"
    );
}

#[test]
fn untrusted_syslog_label_does_not_impersonate_sshd() {
    let mut r = record();
    r["_COMM"] = json!("logger");
    r["SYSLOG_IDENTIFIER"] = json!("sshd");
    assert!(ssh::parse_journal(&r.to_string()).unwrap().is_none());
    r.as_object_mut().unwrap().remove("_COMM");
    assert!(ssh::parse_journal(&r.to_string()).unwrap().is_none());
}

#[test]
fn malformed_journal_fields_are_errors() {
    for (key, value) in [
        ("MESSAGE", json!([65, 66])),
        ("_PID", json!("invalid")),
        ("_HOSTNAME", json!("")),
        ("__REALTIME_TIMESTAMP", json!("18446744073709551615")),
        ("__REALTIME_TIMESTAMP", json!("-1")),
        ("__REALTIME_TIMESTAMP", json!(0)),
    ] {
        let mut r = record();
        r[key] = value;
        assert!(ssh::parse_journal(&r.to_string()).is_err(), "{key}");
    }
    for key in ["MESSAGE", "_PID", "_HOSTNAME", "__REALTIME_TIMESTAMP"] {
        let mut r = record();
        r.as_object_mut().unwrap().remove(key);
        assert!(ssh::parse_journal(&r.to_string()).is_err(), "{key}");
    }
    assert!(ssh::parse_journal("[]").is_err());
    assert!(ssh::parse_journal("bad JSON").is_err());
}

#[test]
fn unrelated_journal_messages_are_skipped() {
    let mut r = record();
    r["MESSAGE"] = json!("Connection closed by client");
    r.as_object_mut().unwrap().remove("__REALTIME_TIMESTAMP");
    assert!(ssh::parse_journal(&r.to_string()).unwrap().is_none());
}

fn run(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn journal_stdin_scan_and_normalization_agree() {
    let mut input = String::new();
    for n in 0..6 {
        let mut r = record();
        r["__REALTIME_TIMESTAMP"] = json!((1792152000000000u64 + n * 1000000).to_string());
        input.push_str(&format!("{r}\n"));
    }
    let direct = run(
        &["scan", "-r", "rules/ssh.yaml", "--input-format", "journal"],
        &input,
    );
    assert!(direct.status.success());
    assert_eq!(
        String::from_utf8(direct.stdout.clone())
            .unwrap()
            .lines()
            .count(),
        1
    );
    let normal = run(&["normalize-ssh", "--input-format", "journal"], &input);
    assert!(normal.status.success());
    let scan = run(
        &["scan", "-r", "rules/ssh.yaml"],
        &String::from_utf8(normal.stdout).unwrap(),
    );
    assert!(scan.status.success());
    assert_eq!(scan.stdout, direct.stdout);
}
