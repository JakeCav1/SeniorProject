use chomp_edr::Engine;
use serde_json::json;
use std::process::Command;

#[test]
fn selected_file_rule_matches_observations_only() {
    let engine = Engine::from_yaml(include_str!("../rules/file-watch.yaml")).unwrap();
    for action in ["created", "removed", "changed"] {
        let e = json!({"event":{"type":"file_metadata_changed","action":action},"file":{"path":"/etc/passwd"}});
        assert_eq!(engine.evaluate(&e)[0].rule_id, "CHOMP-FILE-001");
    }
    assert!(engine
        .evaluate(&json!({"event":{"type":"file_write"}}))
        .is_empty());
}
#[test]
fn file_watch_requires_selection_and_valid_options() {
    for args in [
        vec![],
        vec!["--path", "/tmp/a", "--interval-ms", "0"],
        vec!["--path", "/tmp/a", "--samples", "0"],
        vec![
            "--path",
            "/tmp/a",
            "--events",
            "-r",
            "rules/file-watch.yaml",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
            .arg("watch-files")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}
#[cfg(not(target_os = "linux"))]
#[test]
fn file_watch_explains_linux_requirement() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args(["watch-files", "--path", "/tmp/a", "--samples", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("requires Linux"));
}
