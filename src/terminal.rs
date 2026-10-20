//! Terminal presentation for newline-delimited monitor alerts.
use std::io::{self, Write};

pub struct AlertOutput<W> {
    output: W,
    terminal: bool,
    line_start: bool,
}

impl<W: Write> AlertOutput<W> {
    pub fn new(output: W, terminal: bool) -> Self {
        Self {
            output,
            terminal,
            line_start: true,
        }
    }
}

impl<W: Write> Write for AlertOutput<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.terminal {
            return self.output.write(bytes);
        }
        // Serde may write a JSON record in many chunks. Add a heading only at
        // the beginning of each record, including retried checkpoint alerts.
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            if part.is_empty() {
                continue;
            }
            if self.line_start {
                self.output.write_all(b"\x1b[1;31mALERT\x1b[0m\n")?;
            }
            self.output.write_all(part)?;
            self.line_start = part.ends_with(b"\n");
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_heading_occurs_once_per_record_despite_chunked_writes() {
        let mut output = AlertOutput::new(Vec::new(), true);
        output.write_all(b"").unwrap();
        output.write_all(b"{\"id\":").unwrap();
        output.write_all(b"1}\n{\"id\":2}\n").unwrap();
        assert_eq!(
            output.output,
            b"\x1b[1;31mALERT\x1b[0m\n{\"id\":1}\n\x1b[1;31mALERT\x1b[0m\n{\"id\":2}\n"
        );
    }

    #[test]
    fn redirected_output_remains_exact_json_lines() {
        let mut output = AlertOutput::new(Vec::new(), false);
        let record = serde_json::json!({"rule_id": "CHOMP-SSH-001"});
        serde_json::to_writer(&mut output, &record).unwrap();
        writeln!(output).unwrap();
        output.flush().unwrap();
        assert_eq!(output.output, b"{\"rule_id\":\"CHOMP-SSH-001\"}\n");
    }
}
