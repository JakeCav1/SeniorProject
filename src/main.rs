use chomp_edr::Engine;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "chompedr",
    version,
    about = "Chomp EDR: YAML rules and JSON event detection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch selected Linux file paths for metadata changes without reading contents.
    WatchFiles {
        /// Absolute file path; repeat to select up to 64 paths. Not recursive.
        #[arg(long = "path", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
        interval_ms: u64,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        samples: Option<u64>,
        /// Emit raw observation events instead of alerts.
        #[arg(long, conflicts_with = "rules")]
        events: bool,
        #[arg(short, long)]
        rules: Vec<PathBuf>,
    },
    /// Poll Linux processes and emit review alerts (or raw observation events).
    WatchProcesses {
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
        interval_ms: u64,
        /// Stop after this many snapshots, including the initial baseline.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        samples: Option<u64>,
        /// Emit observations for processes already present in the first snapshot.
        #[arg(long)]
        include_existing: bool,
        /// Emit raw JSON events instead of alerts; pipe them to scan for custom processing.
        #[arg(long, conflicts_with = "rules")]
        events: bool,
        /// Override the embedded process review rules.
        #[arg(short, long)]
        rules: Vec<PathBuf>,
    },
    /// Monitor Linux SSH journal records with automatic checkpoint recovery.
    Monitor {
        /// YAML sources; omit to use the built-in SSH rules.
        #[arg(short, long)]
        rules: Vec<PathBuf>,
        /// Checkpoint directory; defaults to your user state directory.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Inspect saved progress without starting a collector (JSON output).
        #[arg(long, conflicts_with = "once")]
        status: bool,
        /// Process available records and exit instead of following new records.
        #[arg(long)]
        once: bool,
    },
    /// Convert OpenSSH text logs or journal JSON into normalized JSON Lines.
    NormalizeSsh {
        #[arg(long, value_enum, default_value = "ssh")]
        input_format: LogFormat,
        #[arg(short, long, default_value = "-")]
        input: PathBuf,
    },
    /// Validate the YAML schema and compile every detection rule.
    Validate {
        #[command(flatten)]
        source: RuleSource,
    },
    /// List validated rule IDs, severity, and enabled status.
    ListRules {
        #[command(flatten)]
        source: RuleSource,
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Evaluate JSON Lines events from a file or stdin; emit matching alerts.
    Scan {
        #[arg(long, value_enum, default_value = "json")]
        input_format: InputFormat,
        #[command(flatten)]
        source: RuleSource,
        /// Select an exact rule ID; repeat to select multiple rules.
        #[arg(long = "rule")]
        rule_ids: Vec<String>,
        /// JSON Lines input path; '-' reads stdin.
        #[arg(short, long, default_value = "-")]
        input: PathBuf,
        #[arg(short, long, value_enum, default_value = "json")]
        format: Format,
        /// Return exit code 1 when at least one alert is emitted.
        #[arg(long)]
        fail_on_alert: bool,
        /// Save journal progress and correlation in this directory; replay input through the saved cursor on restart.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
    },
}

#[derive(Args)]
struct RuleSource {
    /// YAML file or directory (nonrecursive); repeat to load multiple sources.
    #[arg(short, long, required = true)]
    rules: Vec<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Text,
}

#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Json,
    Ssh,
    Journal,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Ssh,
    Journal,
}

fn normalize_ssh(input: PathBuf, format: LogFormat) -> Result<u8, Box<dyn std::error::Error>> {
    let mut reader: Box<dyn BufRead> = if input.as_os_str() == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(input)?))
    };
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut line = String::new();
    let mut number = 0;
    let mut skipped = 0;
    loop {
        line.clear();
        let bytes = reader
            .by_ref()
            .take((MAX_BYTES + 1) as u64)
            .read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        number += 1;
        if bytes > MAX_BYTES {
            return Err(format!("log line {number} exceeds 1 MiB").into());
        }
        if line.trim().is_empty() {
            continue;
        }
        let parsed = match format {
            LogFormat::Ssh => chomp_edr::ssh::parse(&line),
            LogFormat::Journal => chomp_edr::ssh::parse_journal(&line),
        };
        match parsed.map_err(|e| format!("log line {number}: {e}"))? {
            Some(event) => {
                serde_json::to_writer(&mut out, &event)?;
                writeln!(out)?;
                out.flush()?;
            }
            None => skipped += 1,
        }
    }
    eprintln!("Skipped {skipped} unrelated log line(s).");
    Ok(0)
}

fn load_file(path: PathBuf) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut source = String::new();
    File::open(&path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_string(&mut source)?;
    if source.len() > MAX_BYTES {
        return Err("rule file exceeds 1 MiB".into());
    }
    Engine::from_yaml(&source).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn load(source: RuleSource) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for path in source.rules {
        let mut files = if path.is_dir() {
            let mut files = Vec::new();
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if entry.file_type()?.is_file()
                    && p.extension().and_then(|s| s.to_str()).is_some_and(|s| {
                        s.eq_ignore_ascii_case("yaml") || s.eq_ignore_ascii_case("yml")
                    })
                {
                    files.push(p);
                }
            }
            if files.is_empty() {
                return Err(format!("{}: no YAML rule files", path.display()).into());
            }
            files.sort();
            files
        } else {
            vec![path]
        };
        for file in files.drain(..) {
            let canonical = file.canonicalize()?;
            if seen.insert(canonical) {
                paths.push(file);
            }
        }
    }
    let mut engines = Vec::new();
    for path in paths {
        engines.push(load_file(path)?);
    }
    Engine::combine(engines).map_err(Into::into)
}

fn run(cli: Cli) -> Result<u8, Box<dyn std::error::Error>> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match cli.command {
        Command::WatchFiles {
            paths,
            interval_ms,
            samples,
            events,
            rules,
        } => {
            let engine = if rules.is_empty() {
                Engine::from_yaml(include_str!("../rules/file-watch.yaml"))?
            } else {
                load(RuleSource { rules })?
            };
            let mut session = chomp_edr::session::Session::new(engine);
            chomp_edr::files::watch(paths, interval_ms, samples, |event| {
                let rows = if events {
                    vec![event.clone()]
                } else {
                    session.process(event)?
                };
                for row in rows {
                    serde_json::to_writer(&mut out, &row).map_err(|e| e.to_string())?;
                    writeln!(out).map_err(|e| e.to_string())?;
                }
                out.flush().map_err(|e| e.to_string())
            })?;
        }

        Command::WatchProcesses {
            interval_ms,
            samples,
            include_existing,
            events,
            rules,
        } => {
            let engine = if rules.is_empty() {
                Engine::from_yaml(include_str!("../rules/processes.yaml"))?
            } else {
                load(RuleSource { rules })?
            };
            let mut session = chomp_edr::session::Session::new(engine);
            chomp_edr::processes::collect(interval_ms, samples, include_existing, |event| {
                let rows = if events {
                    vec![event.clone()]
                } else {
                    session.process(event)?
                };
                for row in rows {
                    serde_json::to_writer(&mut out, &row).map_err(|e| e.to_string())?;
                    writeln!(out).map_err(|e| e.to_string())?;
                }
                out.flush().map_err(|e| e.to_string())
            })?;
        }

        Command::Monitor {
            rules,
            checkpoint,
            once,
            status,
        } => {
            let engine = if rules.is_empty() {
                Engine::from_yaml(include_str!("../rules/ssh.yaml"))?
            } else {
                load(RuleSource { rules })?
            };
            if status {
                let dir = chomp_edr::monitor::state_directory(checkpoint)?;
                let state = chomp_edr::checkpoint::status(engine, &dir)?;
                serde_json::to_writer(&mut out, &state)?;
                writeln!(out)?;
            } else {
                chomp_edr::monitor::run(engine, checkpoint, once, &mut out)
                    .map_err(|e| format!("monitor: {e}"))?;
            }
        }
        Command::NormalizeSsh {
            input,
            input_format,
        } => return normalize_ssh(input, input_format),
        Command::Validate { source } => {
            let engine = load(source)?;
            writeln!(out, "Valid: {} rule(s)", engine.rules().count())?;
        }
        Command::ListRules { source, format } => {
            let engine = load(source)?;
            for r in engine.rules() {
                if matches!(format, Format::Json) {
                    serde_json::to_writer(
                        &mut out,
                        &serde_json::json!({
                            "id": r.id, "name": r.name, "description": r.description,
                            "severity": r.severity, "enabled": r.enabled
                        }),
                    )?;
                    writeln!(out)?;
                    continue;
                }
                writeln!(
                    out,
                    "{}\t{:?}\t{}\t{}",
                    serde_json::to_string(&r.id)?,
                    r.severity,
                    if r.enabled { "enabled" } else { "disabled" },
                    serde_json::to_string(&r.name)?
                )?;
            }
        }
        Command::Scan {
            input_format,
            source,
            rule_ids,
            input,
            format,
            fail_on_alert,
            checkpoint,
        } => {
            let mut engine = load(source)?;
            engine.select(&rule_ids)?;
            if let Some(path) = checkpoint {
                if !matches!(input_format, InputFormat::Journal) || !matches!(format, Format::Json)
                {
                    return Err(
                        "--checkpoint requires --input-format journal and JSON output".into(),
                    );
                }
                let reader: Box<dyn BufRead> = if input.as_os_str() == "-" {
                    Box::new(BufReader::new(io::stdin()))
                } else {
                    Box::new(BufReader::new(File::open(&input)?))
                };
                let found = chomp_edr::checkpoint::scan(engine, &path, reader, &mut out)
                    .map_err(|e| format!("checkpoint scan: {e}"))?;
                return Ok(u8::from(found && fail_on_alert));
            }
            let mut session = chomp_edr::session::Session::new(engine);
            let mut skipped = 0;
            let mut reader: Box<dyn BufRead> = if input.as_os_str() == "-" {
                Box::new(BufReader::new(io::stdin()))
            } else {
                Box::new(BufReader::new(File::open(&input)?))
            };
            let mut line = String::new();
            let mut number = 0;
            let mut found = false;
            loop {
                line.clear();
                let bytes = reader
                    .by_ref()
                    .take((MAX_BYTES + 1) as u64)
                    .read_line(&mut line)?;
                if bytes == 0 {
                    break;
                }
                number += 1;
                if bytes > MAX_BYTES {
                    return Err(format!("event line {number} exceeds 1 MiB").into());
                }
                if line.trim().is_empty() {
                    continue;
                }
                let event: serde_json::Value = match input_format {
                    InputFormat::Json => serde_json::from_str(&line)
                        .map_err(|e| format!("event line {number}: {e}"))?,
                    InputFormat::Ssh | InputFormat::Journal => match (match input_format {
                        InputFormat::Journal => chomp_edr::ssh::parse_journal(&line),
                        _ => chomp_edr::ssh::parse(&line),
                    })
                    .map_err(|e| format!("log line {number}: {e}"))?
                    {
                        Some(event) => event,
                        None => {
                            skipped += 1;
                            continue;
                        }
                    },
                };
                if !event.is_object() {
                    return Err(format!("event line {number}: expected JSON object").into());
                }
                for alert in session
                    .process(&event)
                    .map_err(|e| format!("event line {number}: {e}"))?
                {
                    found = true;
                    match format {
                        Format::Json => {
                            serde_json::to_writer(&mut out, &alert)?;
                            writeln!(out)?;
                        }
                        // JSON quoting escapes untrusted control characters for terminal output.
                        Format::Text => writeln!(
                            out,
                            "[{}] {} {} (line {})",
                            alert["severity"].as_str().unwrap_or("unknown"),
                            alert["rule_id"],
                            alert["rule_name"],
                            number
                        )?,
                    }
                }
                out.flush()?;
            }
            out.flush()?;
            if !matches!(input_format, InputFormat::Json) {
                eprintln!("Skipped {skipped} unrelated log line(s).");
            }
            return Ok(u8::from(found && fail_on_alert));
        }
    }
    out.flush()?;
    Ok(0)
}

fn main() -> std::process::ExitCode {
    let result = if std::env::args_os().len() == 1 {
        interactive()
    } else {
        run(Cli::parse())
    };
    match result {
        Ok(code) => code.into(),
        Err(e) => {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return std::process::ExitCode::SUCCESS;
            }
            eprintln!("chompedr: {e}");
            2.into()
        }
    }
}

fn welcome() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = io::stdout().lock();
    write!(out, "{}", include_str!("banner.txt"))?;
    writeln!(
        out,
        "Version {} | Ready to scan supplied events.",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(out, "Live endpoint monitoring is not enabled.\n")?;
    Cli::command().write_help(&mut out)?;
    writeln!(out, "\n\nInteractive commands: help, exit, quit")?;
    writeln!(out, "Scans in this prompt require an input file (-i FILE).")?;
    writeln!(out, "Example (from the project folder):")?;
    writeln!(out, "  scan -r rules -i examples/events.jsonl -f text")?;
    out.flush()?;
    Ok(())
}

/// Split command arguments without invoking a shell. Backslashes remain literal
/// so Windows paths work; single and double quotes group arguments with spaces.
fn command_words(line: &str) -> Result<Vec<String>, &'static str> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    for ch in line.chars() {
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                word.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            started = true;
        } else if ch.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(ch);
            started = true;
        }
    }
    if quote.is_some() {
        return Err("unclosed quote; put paths containing spaces inside matching quotes");
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

fn interactive() -> Result<u8, Box<dyn std::error::Error>> {
    welcome()?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    loop {
        print!("\nchompedr> ");
        io::stdout().flush()?;
        line.clear();
        let size = input.by_ref().take(8193).read_line(&mut line)?;
        if size == 0 {
            println!();
            return Ok(0);
        }
        if size > 8192 {
            return Err("interactive command exceeds 8 KiB; session ended".into());
        }
        let words = match command_words(&line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("chompedr: {error}");
                continue;
            }
        };
        if words.is_empty() {
            continue;
        }
        if words.len() == 1 && matches!(words[0].as_str(), "exit" | "quit") {
            println!("Goodbye.");
            return Ok(0);
        }
        let cli = match Cli::try_parse_from(std::iter::once("chompedr".to_owned()).chain(words)) {
            Ok(cli) => cli,
            Err(error) => {
                error.print()?;
                continue;
            }
        };
        if matches!(
            &cli.command,
            Command::Monitor { status: false, .. }
                | Command::WatchProcesses { .. }
                | Command::WatchFiles { .. }
        ) {
            eprintln!(
                "chompedr: run live monitoring from your system terminal so Ctrl+C can stop it."
            );
            continue;
        }
        // The session owns stdin. Letting scans consume it would interpret later
        // commands as events and can deadlock while the stdin lock is held.
        if matches!(&cli.command, Command::Scan { input, .. } | Command::NormalizeSsh { input, .. } if input.as_os_str() == "-")
        {
            eprintln!("chompedr: interactive scans require -i FILE. For piped events, use chompedr scan from your system shell.");
            continue;
        }
        match run(cli) {
            Ok(1) => println!("Scan completed with matching alerts (status 1)."),
            Ok(_) => (),
            Err(error) => eprintln!("chompedr: {error}"),
        }
    }
}
