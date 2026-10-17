//! Managed Linux journal collection. Alerts go to stdout, lifecycle messages to stderr.
use crate::Engine;
use std::io::Write;
use std::path::PathBuf;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn state_directory(dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = match dir {
        Some(dir) => dir,
        None => {
            #[cfg(target_os = "windows")]
            let base = std::env::var_os("LOCALAPPDATA")
                .map(|p| PathBuf::from(p).join("ChompEDR/state"))
                .ok_or("set LOCALAPPDATA or provide --checkpoint DIRECTORY")?;
            #[cfg(not(target_os = "windows"))]
            let base = std::env::var_os("XDG_STATE_HOME")
                .filter(|v| PathBuf::from(v).is_absolute())
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
                .ok_or("set HOME/XDG_STATE_HOME or provide --checkpoint DIRECTORY")?;
            base.join("chomp-edr/ssh")
        }
    };
    Ok(dir)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_: Engine, _: Option<PathBuf>, _: bool, _: impl Write) -> Result<()> {
    Err("live monitoring requires Linux with systemd journal access; use scan for exported logs on this platform".into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdout, Command, Stdio};

    pub struct Collector {
        child: Child,
        reader: BufReader<ChildStdout>,
    }
    impl Read for Collector {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.reader.read(b)
        }
    }
    impl BufRead for Collector {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.reader.fill_buf()?.is_empty() {
                let status = self.child.wait()?;
                if !status.success() {
                    return Err(std::io::Error::other(format!("journalctl exited with {status}; check journal permissions and diagnostics above")));
                }
            }
            self.reader.fill_buf()
        }
        fn consume(&mut self, n: usize) {
            self.reader.consume(n)
        }
    }

    impl Drop for Collector {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn command(cursor: Option<&str>, follow: bool) -> Command {
        let mut cmd = Command::new("journalctl");
        cmd.args(["--no-pager", "--output=json", "--no-tail"]);
        if let Some(cursor) = cursor {
            cmd.arg(format!("--cursor={cursor}"));
        } else {
            cmd.arg("--since=-60s");
        }
        if follow {
            cmd.arg("--follow");
        }
        cmd.args(["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth"]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // Linux sends SIGTERM to the collector if its parent exits, including Ctrl+C
        // and SIGKILL. Check getppid as well to close the fork/prctl race.
        let parent = std::process::id() as i32;
        unsafe {
            cmd.pre_exec(move || {
                unsafe extern "C" {
                    fn prctl(option: i32, ...) -> i32;
                    fn getppid() -> i32;
                }
                if prctl(1, 15usize, 0usize, 0usize, 0usize) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if getppid() != parent {
                    return Err(std::io::Error::other("monitor parent exited"));
                }
                Ok(())
            });
        }
        cmd
    }

    fn open(cursor: Option<&str>, follow: bool) -> Result<Collector> {
        let mut child = command(cursor, follow)
            .spawn()
            .map_err(|e| format!("could not start journalctl: {e}"))?;
        let reader = BufReader::new(child.stdout.take().ok_or("collector stdout unavailable")?);
        Ok(Collector { child, reader })
    }

    pub fn run(engine: Engine, dir: Option<PathBuf>, once: bool, output: impl Write) -> Result<()> {
        let dir = state_directory(dir)?;
        eprintln!("Chomp SSH monitor | checkpoint: {}", dir.display());
        crate::checkpoint::scan_from(
            engine,
            &dir,
            |cursor| {
                if let Some(cursor) = cursor {
                    // A finite probe detects a missing cursor even when follow would wait forever.
                    let mut probe = open(Some(cursor), false)?;
                    let mut line = String::new();
                    probe.by_ref().take(1024 * 1024 + 1).read_line(&mut line)?;
                    if line.len() > 1024 * 1024 {
                        return Err("journal record exceeds 1 MiB".into());
                    }
                    let first: serde_json::Value = serde_json::from_str(&line).map_err(|_| {
                        "saved journal cursor is unavailable or unreadable; checkpoint unchanged"
                    })?;
                    if first["__CURSOR"].as_str() != Some(cursor) {
                        return Err("saved journal cursor is unavailable; checkpoint unchanged; check retention and journal access".into());
                    }
                    eprintln!("Resuming saved journal position and detection window.");
                } else {
                    eprintln!("Starting with the last 60 seconds of accessible SSH records; older history is not scanned.");
                }
                eprintln!(
                    "Collecting SSH journal records. Alerts are JSON on stdout.{}",
                    if once {
                        " Catch-up only."
                    } else {
                        " Stop with Ctrl+C."
                    }
                );
                open(cursor, !once)
            },
            output,
            true,
        )?;
        if !once {
            return Err(
                "journal collector ended unexpectedly; monitoring stopped; restart to resume"
                    .into(),
            );
        }
        eprintln!("Journal catch-up complete.");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::run;
