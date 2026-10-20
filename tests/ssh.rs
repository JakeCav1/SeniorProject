use chomp_edr::{session::Session, ssh, Engine};
use serde_json::{json, Value};
use std::process::Command;

fn engine() -> Engine {
    Engine::from_yaml(include_str!("../rules/ssh.yaml")).unwrap()
}
fn event(second: u32, ip: &str) -> Value {
    json!({"timestamp":format!("2026-10-16T12:{:02}:{:02}Z", second/60, second%60),"host":"lab",
        "source":{"ip":ip},"event":{"type":"ssh_auth","outcome":"failure"},"user":{"name":"alice"}})
}

#[test]
fn ssh_parser_preserves_auth_fields_and_canonicalizes_ipv6() {
    let e = ssh::parse("2026-10-16T12:00:00+0200 lab sshd-session[42]: Failed password for invalid user admin from 2001:0db8::1 port 2222 ssh2").unwrap().unwrap();
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["source"]["ip"], "2001:db8::1");
    assert_eq!(e["source"]["port"], 2222);
    assert_eq!(e["user"]["invalid"], true);
    assert_eq!(e["timestamp"], "2026-10-16T12:00:00+02:00");
    assert!(
        ssh::parse("2026-10-16T12:00:00Z lab sshd[42]: Connection closed")
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_target_logs_error_instead_of_silently_skipping() {
    for line in [
        "Oct 16 12:00:00 lab sshd[42]: Failed password for root from 192.0.2.1 port 2222 ssh2",
        "bad-time lab sshd[42]: Failed password for root from 192.0.2.1 port 2222 ssh2",
        "2026-10-16T12:00:00Z lab sshd[42]: Failed password for root from nope port 2222 ssh2",
        "2026-10-16T12:00:00Z lab sshd[42]: Accepted unsupported for root from 192.0.2.1 port 2222 ssh2",
        "2026-10-16T12:00:00Z lab sshd[42]: Failed password for root from 192.0.2.1 port 99999 ssh2",
    ] { assert!(ssh::parse(line).is_err(), "{line}"); }
}

#[test]
fn threshold_has_inclusive_window_and_suppresses_continuing_burst() {
    let mut s = Session::new(engine());
    for t in [0, 10, 20, 30] {
        assert!(s.process(&event(t, "ip-a")).unwrap().is_empty());
    }
    let a = s.process(&event(60, "ip-a")).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0]["correlation"]["count"], 5);
    assert!(s.process(&event(60, "ip-a")).unwrap().is_empty());
    // A new burst after old events expire can alert again.
    for t in [121, 122, 123, 124] {
        assert!(s.process(&event(t, "ip-a")).unwrap().is_empty());
    }
    assert_eq!(s.process(&event(125, "ip-a")).unwrap().len(), 1);
}

#[test]
fn groups_do_not_mix_hosts_or_ips_and_old_events_expire() {
    let mut s = Session::new(engine());
    for t in 0..4 {
        s.process(&event(t, "a")).unwrap();
    }
    assert!(s.process(&event(4, "b")).unwrap().is_empty());
    let mut other_host = event(5, "a");
    other_host["host"] = json!("other");
    assert!(s.process(&other_host).unwrap().is_empty());
    assert!(s.process(&event(64, "a")).unwrap().is_empty());
}

#[test]
fn invalid_events_do_not_advance_correlation_state() {
    let mut s = Session::new(engine());
    for t in 0..4 {
        s.process(&event(t, "a")).unwrap();
    }
    let mut bad = event(50, "a");
    bad.as_object_mut().unwrap().remove("host");
    assert!(s.process(&bad).is_err());
    assert_eq!(s.process(&event(4, "a")).unwrap().len(), 1);
    assert!(s.process(&event(3, "a")).is_err());
    assert!(s.process(&json!({})).is_err());
}

#[test]
fn threshold_config_validation_and_stateless_api() {
    let source = include_str!("../rules/ssh.yaml");
    for bad in [
        source.replace("count: 5", "count: 0"),
        source.replace("window_seconds: 60", "window_seconds: 0"),
        source.replace("[host, source.ip]", "[]"),
    ] {
        assert!(Engine::from_yaml(&bad).is_err());
    }
    assert!(engine().evaluate(&event(0, "a")).is_empty());
    let mut e = event(0, "a");
    e["event"]["outcome"] = json!("success");
    e["user"]["name"] = json!("root");
    assert_eq!(
        Session::new(engine()).process(&e).unwrap()[0]["rule_id"],
        "CHOMP-SSH-002"
    );
}

#[test]
fn state_capacity_is_bounded_and_expired_groups_are_reclaimed() {
    let mut s = Session::new(engine());
    for n in 0..4096 {
        s.process(&event(0, &format!("ip-{n}"))).unwrap();
    }
    assert!(s
        .process(&event(0, "overflow"))
        .unwrap_err()
        .contains("capacity"));
    assert!(s.process(&event(61, "new")).is_ok());
}

#[test]
fn demo_emits_exactly_two_alerts() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args([
            "scan",
            "-r",
            "rules/ssh.yaml",
            "-i",
            "examples/ssh-demo.log",
            "--input-format",
            "ssh",
            "--fail-on-alert",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    let alerts: Vec<Value> = text
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["rule_id"], "CHOMP-SSH-001");
    assert_eq!(alerts[1]["rule_id"], "CHOMP-SSH-002");
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("Skipped 1"));
}
