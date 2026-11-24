// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//! Compiler and matcher for the line-oriented packet policy. Plans are bounded,
//! pointer-free records owned by the caller. Match only reads these records.
use std::{net::IpAddr, slice, str};

const EVENTS: [&str; 5] = [
    "tcp.syn",
    "udp.open",
    "tls.hello",
    "dns.query",
    "quic.initial",
];
const MAX_ROWS: usize = 128;

#[repr(C)]
#[derive(Clone)]
pub struct Row {
    address: [u8; 16],
    family: u8,
    prefix: u8,
    kind: u8,
    action: u8,
    port: u16,
    value: u16,
    id_len: u8,
    source_len: u8,
    name_len: u8,
    id: [u8; 80],
    source: [u8; 80],
    name: [u8; 253],
}

impl Default for Row {
    fn default() -> Self {
        Self {
            address: [0; 16],
            family: 0,
            prefix: 0,
            kind: 0,
            action: 0,
            port: 0,
            value: 0,
            id_len: 0,
            source_len: 0,
            name_len: 0,
            id: [0; 80],
            source: [0; 80],
            name: [0; 253],
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct Match {
    hits: [u64; 2],
    mss: u16,
    has_mss: u8,
    dscp: u8,
    has_dscp: u8,
    recursion: u8,
    has_recursion: u8,
    dropped: u8,
}

fn number(s: &str) -> Option<u16> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn alias(s: &str) -> bool {
    (1..=80).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn dns_label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn prefix_matches(a: &[u8; 16], b: &[u8; 16], width: u8) -> bool {
    let bytes = usize::from(width / 8);
    let extra = width % 8;
    a[..bytes] == b[..bytes] && (extra == 0 || (a[bytes] ^ b[bytes]) >> (8 - extra) == 0)
}

fn destination(row: &mut Row, s: &str) -> Result<(), &'static str> {
    let (address, width) = s.split_once('/').map_or((s, None), |(a, w)| (a, Some(w)));
    let ip: IpAddr = address.parse().map_err(|_| "invalid destination network")?;
    let bits = match ip {
        IpAddr::V4(ip) => {
            row.family = 4;
            row.address[..4].copy_from_slice(&ip.octets());
            32
        }
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() => {
            row.family = 6;
            row.address = ip.octets();
            128
        }
        _ => return Err("use a canonical destination network"),
    };
    row.prefix = match width {
        None => bits,
        Some(w) => {
            let n = number(w)
                .filter(|n| *n <= bits.into() && n.to_string() == w)
                .ok_or("invalid destination network")?;
            n as u8
        }
    };
    for bit in row.prefix..bits {
        if row.address[usize::from(bit / 8)] & (0x80 >> (bit % 8)) != 0 {
            return Err("use a canonical destination network");
        }
    }
    Ok(())
}

fn parse_line(mut words: str::SplitWhitespace<'_>, prior: &[Row]) -> Result<Row, &'static str> {
    let mut row = Row::default();
    let header = "expected on UNIQUE_ID EVENT [FIELD VALUE ...] => ACTION";
    if words.next() != Some("on") {
        return Err(header);
    }
    let id = words.next().ok_or(header)?;
    if !alias(id)
        || !id.as_bytes()[0].is_ascii_alphabetic()
        || prior
            .iter()
            .any(|r| &r.id[..usize::from(r.id_len)] == id.as_bytes())
    {
        return Err(header);
    }
    if prior.len() == MAX_ROWS {
        return Err("choose up to 128 event handlers");
    }
    row.id[..id.len()].copy_from_slice(id.as_bytes());
    row.id_len = id.len() as u8;
    let kind = words.next().ok_or(header)?;
    row.kind = EVENTS
        .iter()
        .position(|e| *e == kind)
        .ok_or("unknown event")? as u8;
    let mut seen = 0;
    loop {
        let key = words.next().ok_or("expected => and an action")?;
        if key == "=>" {
            break;
        }
        let val = words.next().ok_or("missing or duplicate predicate")?;
        let bit = match key {
            "port" => 1,
            "dst" => 2,
            "source" => 4,
            "name" => 8,
            _ => return Err("unknown predicate"),
        };
        if seen & bit != 0 {
            return Err("missing or duplicate predicate");
        }
        seen |= bit;
        match key {
            "port" => {
                row.port = number(val)
                    .filter(|n| *n != 0)
                    .ok_or("expected destination port 1–65535")?
            }
            "dst" => destination(&mut row, val)?,
            "source" => {
                if !alias(val) {
                    return Err("invalid source rule ID");
                }
                row.source[..val.len()].copy_from_slice(val.as_bytes());
                row.source_len = val.len() as u8;
            }
            "name" => {
                // Go's legacy grammar uses Unicode simple lowercase on input.
                let name: String = val
                    .strip_suffix('.')
                    .unwrap_or(val)
                    .chars()
                    .map(|c| c.to_lowercase().next().unwrap_or(c))
                    .collect();
                if !matches!(kind, "tls.hello" | "dns.query")
                    || name.len() > 253
                    || !name.split('.').all(dns_label)
                {
                    return Err("name requires a DNS question or visible TLS server name");
                }
                row.name_len = name.len() as u8;
                row.name[..name.len()].copy_from_slice(name.as_bytes());
            }
            _ => return Err("unknown predicate"),
        }
    }
    let action = words.next().ok_or("expected => and an action")?;
    let arg = words.next();
    if words.next().is_some() {
        return Err("unexpected action argument");
    }
    let value = arg.and_then(number);
    row.action = match action {
        "count" | "drop" if arg.is_none() => u8::from(action == "drop"),
        "mark-dscp" if value.is_some_and(|n| n <= 63) => 2,
        "clamp-mss" if kind == "tcp.syn" && value.is_some_and(|n| n >= 536) => 3,
        "set-dns-rd" if kind == "dns.query" && value.is_some_and(|n| n <= 1) => 4,
        "mark-dscp" => return Err("DSCP must be 0–63"),
        "clamp-mss" => return Err("clamp-mss requires tcp.syn and an MSS of 536–65535"),
        "set-dns-rd" => return Err("set-dns-rd requires dns.query and 0 or 1"),
        "count" | "drop" => return Err("unexpected action argument"),
        _ => return Err("unknown action"),
    };
    row.value = value.unwrap_or_default();
    Ok(row)
}

fn compile(text: &[u8]) -> Result<Vec<Row>, String> {
    if text.len() > 32768 || text.contains(&0) {
        return Err("event program exceeds 32 KiB or contains a NUL".into());
    }
    // Preserve legacy acceptance of arbitrary bytes in comments.
    let mut rows = Vec::new();
    for (index, line) in text.split(|b| *b == b'\n').enumerate() {
        let code = line.split(|b| *b == b'#').next().unwrap_or_default();
        let code =
            str::from_utf8(code).map_err(|_| format!("line {}: invalid UTF-8", index + 1))?;
        if code.trim().is_empty() {
            continue;
        }
        rows.push(
            parse_line(code.split_whitespace(), &rows)
                .map_err(|e| format!("line {}: {e}", index + 1))?,
        );
    }
    Ok(rows)
}

/// # Safety
/// The caller supplies nonoverlapping, aligned buffers of the stated lengths.
/// The buffers stay valid until this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn svp_compact_compile(
    text: *const u8,
    len: usize,
    out: *mut Row,
    cap: usize,
    error: *mut u8,
    size: usize,
) -> i32 {
    if text.is_null()
        || len > 32768
        || out.is_null()
        || cap > MAX_ROWS
        || error.is_null()
        || size == 0
    {
        return -1;
    }
    match compile(unsafe { slice::from_raw_parts(text, len) }) {
        Ok(rows) if rows.len() <= cap => {
            unsafe { std::ptr::copy_nonoverlapping(rows.as_ptr(), out, rows.len()) };
            rows.len() as i32
        }
        result => {
            let msg = result
                .err()
                .unwrap_or_else(|| "event plan exceeds output capacity".into());
            let n = msg.len().min(size - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr(), error, n);
                *error.add(n) = 0;
            }
            -1
        }
    }
}

fn evaluate(
    rows: &[Row],
    candidates: [u64; 2],
    ip: &[u8; 16],
    family: u8,
    source: &[u8],
    name: &[u8],
) -> Option<Match> {
    let mut result = Match::default();
    for (word, mut mask) in candidates.into_iter().enumerate() {
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let r = rows.get(word * 64 + bit)?;
            if r.family != 0
                && (r.family != family
                    || r.prefix > 128
                    || !prefix_matches(&r.address, ip, r.prefix))
            {
                continue;
            }
            if r.source_len != 0 && r.source.get(..usize::from(r.source_len))? != source {
                continue;
            }
            if r.name_len != 0
                && !r
                    .name
                    .get(..usize::from(r.name_len))?
                    .eq_ignore_ascii_case(name)
            {
                continue;
            }
            result.hits[word] |= 1 << bit;
            match r.action {
                0 => (),
                1 => {
                    result.dropped = 1;
                    return Some(result);
                }
                2 => {
                    result.has_dscp = 1;
                    result.dscp = r.value as u8;
                }
                3 => {
                    result.mss = if result.has_mss == 0 {
                        r.value
                    } else {
                        r.value.min(result.mss)
                    };
                    result.has_mss = 1;
                }
                4 => {
                    result.has_recursion = 1;
                    result.recursion = r.value as u8;
                }
                _ => return None,
            }
        }
    }
    Some(result)
}

/// # Safety
/// All nonempty buffers must be valid and correctly aligned for their type
/// throughout the call. The output must be exclusively writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn svp_compact_match(
    rows: *const Row,
    count: usize,
    low: u64,
    high: u64,
    address: *const [u8; 16],
    family: u8,
    source: *const u8,
    source_len: usize,
    name: *const u8,
    name_len: usize,
    result: *mut Match,
) -> i32 {
    if rows.is_null()
        || count > MAX_ROWS
        || address.is_null()
        || !matches!(family, 4 | 6)
        || result.is_null()
        || source_len > isize::MAX as usize
        || name_len > isize::MAX as usize
        || (source.is_null() && source_len != 0)
        || (name.is_null() && name_len != 0)
    {
        return -1;
    }
    let source = if source_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(source, source_len) }
    };
    let name = if name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(name, name_len) }
    };
    let Some(m) = evaluate(
        unsafe { slice::from_raw_parts(rows, count) },
        [low, high],
        unsafe { &*address },
        family,
        source,
        name,
    ) else {
        return -1;
    };
    unsafe { result.write(m) };
    0
}
