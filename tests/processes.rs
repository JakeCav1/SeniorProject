use chomp_edr::Engine;
use serde_json::json;
use std::process::Command;

#[test]
fn process_rules_separate_review_paths_from_benign_paths() {
    let engine = Engine::from_yaml(include_str!("../rules/processes.yaml")).unwrap();
    for (path, expected) in [
        ("/usr/bin/sleep", None),
        ("/tmp/demo", Some("CHOMP-PROC-001")),
        ("/var/tmp/demo (deleted)", Some("CHOMP-PROC-001")),
        ("/dev/shm/demo", Some("CHOMP-PROC-002")),
        ("/tmpish/demo", None),
        ("/home/alice/demo", None),
    ] {
        let event = json!({"event":{"type":"process_observed"},"process":{"executable":path}});
        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.first().map(|a| a.rule_id), expected, "{path}");
        assert_eq!(alerts.len(), usize::from(expected.is_some()));
    }
    assert!(engine
        .evaluate(&json!({"event":{"type":"process_start"},"process":{"executable":"/tmp/x"}}))
        .is_empty());
}

#[test]
fn process_cli_bounds_and_conflicting_modes_are_rejected() {
    for args in [
        vec!["--interval-ms", "0"],
        vec!["--interval-ms", "60001"],
        vec!["--samples", "0"],
        vec!["--events", "-r", "rules/processes.yaml"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
            .arg("watch-processes")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn process_collection_explains_linux_requirement() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args(["watch-processes", "--samples", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("requires Linux"));
}
