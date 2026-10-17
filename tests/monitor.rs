use std::process::Command;

#[test]
fn monitor_help_exposes_defaults_without_required_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args(["monitor", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--checkpoint") && help.contains("--once"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_explains_exported_log_alternative() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .arg("monitor")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("requires Linux"));
    assert!(output.stdout.is_empty());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Temp(PathBuf);
    impl Temp {
        fn new(script: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "chomp-monitor-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            let text = format!("#!/bin/sh\n{script}\n");
            std::fs::write(p.join("journalctl"), text).unwrap();
            std::fs::set_permissions(p.join("journalctl"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let records: Vec<_> = (0..5).map(|n| serde_json::json!({"__CURSOR":format!("c{n}"),"_COMM":"sshd","_PID":"1","_HOSTNAME":"lab",
                "__REALTIME_TIMESTAMP":(1792152000000000_u64+n*1000000).to_string(),
                "MESSAGE":"Failed password for alice from 192.0.2.1 port 1234 ssh2"}).to_string()).collect();
            std::fs::write(p.join("events"), records.join("\n") + "\n").unwrap();
            Self(p)
        }
        fn command(&self) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_chompedr"));
            cmd.arg("monitor")
                .env("PATH", &self.0)
                .env("XDG_STATE_HOME", &self.0)
                .env("EVENTS", self.0.join("events"));
            cmd
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn monitor_defaults_catch_up_and_resume_without_duplicates() {
        let t=Temp::new("case \"$*\" in *--cursor=*) /usr/bin/tail -n 1 \"$EVENTS\";; *) /bin/cat \"$EVENTS\";; esac");
        let first = t.command().arg("--once").output().unwrap();
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(String::from_utf8(first.stdout).unwrap().lines().count(), 1);
        let second = t.command().arg("--once").output().unwrap();
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert!(second.stdout.is_empty());
        assert!(t.0.join("chomp-edr/ssh/snapshot.json").is_file());
    }
    #[test]
    fn monitor_rejects_missing_saved_cursor_without_state_change() {
        let t = Temp::new("/bin/cat \"$EVENTS\"");
        assert!(t.command().arg("--once").output().unwrap().status.success());
        let path = t.0.join("chomp-edr/ssh/snapshot.json");
        let before = std::fs::read(&path).unwrap();
        let second = t.command().arg("--once").output().unwrap();
        assert_eq!(second.status.code(), Some(2));
        assert!(String::from_utf8(second.stderr)
            .unwrap()
            .contains("cursor is unavailable"));
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
    #[test]
    fn monitor_reports_collector_failure_and_unexpected_eof() {
        for (script, expected) in [
            ("exit 3", "journalctl exited"),
            ("exit 0", "ended unexpectedly"),
        ] {
            let t = Temp::new(script);
            let output = t.command().output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8(output.stderr).unwrap().contains(expected));
        }
    }
}
