use chomp_edr::ssh;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
struct Scenario {
    name: String,
    lines: Vec<String>,
    expected_rules: Vec<String>,
}

// The same labeled scenarios exercise each public input path and the CLI exit contract.
fn verify(format: &str) {
    let cases: Vec<Scenario> =
        serde_json::from_str(include_str!("fixtures/ssh-scenarios.json")).unwrap();
    for case in cases {
        let input: Vec<String> = case
            .lines
            .iter()
            .map(|line| match format {
                "ssh" => line.clone(),
                "json" => ssh::parse(line).unwrap().unwrap().to_string(),
                "journal" => {
                    let parts: Vec<_> = line.splitn(4, ' ').collect();
                    let time = chrono::DateTime::parse_from_rfc3339(parts[0]).unwrap();
                    json!({"_COMM":"sshd", "_HOSTNAME":parts[1], "_PID":"123",
                    "__REALTIME_TIMESTAMP":time.timestamp_micros().to_string(),
                    "MESSAGE":parts[3]})
                    .to_string()
                }
                _ => unreachable!(),
            })
            .collect();
        let mut child = Command::new(env!("CARGO_BIN_EXE_chompedr"))
            .args([
                "scan",
                "-r",
                "rules/ssh.yaml",
                "--input-format",
                format,
                "--fail-on-alert",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all((input.join("\n") + "\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(i32::from(!case.expected_rules.is_empty())),
            "{} ({format}): {}",
            case.name,
            String::from_utf8_lossy(&output.stderr)
        );
        let alerts: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let ids: Vec<_> = alerts
            .iter()
            .map(|a| a["rule_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, case.expected_rules, "{} ({format})", case.name);
        for alert in alerts {
            if alert["rule_id"] == "CHOMP-SSH-001" {
                assert_eq!(alert["correlation"]["count"], 5, "{}", case.name);
                assert_eq!(alert["correlation"]["window_seconds"], 60, "{}", case.name);
            }
        }
    }
}

#[test]
fn labeled_ssh_scenarios() {
    verify("ssh");
}

#[test]
fn labeled_json_scenarios() {
    verify("json");
}

#[test]
fn labeled_journal_scenarios() {
    verify("journal");
}
