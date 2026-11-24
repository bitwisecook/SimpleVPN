// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use serde_json::Value;
use std::io::{self, BufRead, Read, Write};

const MAX_HEADER: usize = 4096;
const MAX_MESSAGE: usize = 1 << 20;

pub fn read(input: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut header = Vec::new();
    let mut length = None;
    loop {
        let start = header.len();
        let count = input
            .take((MAX_HEADER - start) as u64)
            .read_until(b'\n', &mut header)?;
        if count == 0 && start == 0 {
            return Ok(None);
        }
        let line = header[start..].strip_suffix(b"\r\n").ok_or_else(invalid)?;
        if line.is_empty() {
            break;
        }
        let (key, value) = std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.split_once(':'))
            .ok_or_else(invalid)?;
        if key.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() {
                return Err(invalid());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n <= MAX_MESSAGE)
                    .ok_or_else(invalid)?,
            );
        }
        if header.len() == MAX_HEADER {
            return Err(invalid());
        }
    }
    let mut body = vec![0; length.ok_or_else(invalid)?];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid LSP message header")
}

pub fn write(output: &mut impl Write, message: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(message)?;
    write!(output, "Content-Length: {}\r\n\r\n", body.len())?;
    output.write_all(&body)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn exact_framing() {
        let mut out = Vec::new();
        let x = serde_json::json!({"value":"雪"});
        write(&mut out, &x).unwrap();
        write(&mut out, &x).unwrap();
        let mut reader = Cursor::new(out);
        for _ in 0..2 {
            let body = read(&mut reader).unwrap().unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), x);
        }
        assert!(read(&mut reader).unwrap().is_none());
    }
    #[test]
    fn reject_ambiguous_or_oversized_input() {
        for data in [
            "Content-Length: 10000000\r\n\r\n",
            "Content-Length: 0\r\nContent-Length: 1\r\n\r\n",
            "x".repeat(4100).as_str(),
        ] {
            assert!(read(&mut Cursor::new(data)).is_err());
        }
    }
}
