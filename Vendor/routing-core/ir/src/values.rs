// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//! Typed values and byte-work accounting shared by all general native handlers.
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

const MAX_STRING: usize = 4096;
const MAX_BYTES: usize = 65535;
const MAX_ARRAY: usize = 64;
const VALUE_COST: usize = 128;
const BOUNDS: &str = "value outside supported bounds";

#[derive(Debug, Clone)]
pub struct Blob {
    storage: Arc<[u8]>,
    start: usize,
    end: usize,
}
impl From<Vec<u8>> for Blob {
    fn from(value: Vec<u8>) -> Self {
        let end = value.len();
        Self {
            storage: value.into(),
            start: 0,
            end,
        }
    }
}
impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }
}
impl PartialEq for Blob {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl Eq for Blob {}
impl Hash for Blob {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.as_ref().hash(h);
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Text(Arc<str>),
    Dns(Arc<str>),
    Addr(IpAddr),
    Prefix(IpAddr, u8),
    Bytes(Blob),
    Array(u8, Arc<[Value]>),
}

fn address_valid(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v) => v.to_ipv4_mapped().is_none(),
    }
}

pub fn network(ip: IpAddr, bits: u8) -> Option<IpAddr> {
    let mask = |width: u32| u128::MAX.checked_shl(width - u32::from(bits)).unwrap_or(0);
    match ip {
        IpAddr::V4(a) if bits <= 32 => Some(IpAddr::V4((u32::from(a) & mask(32) as u32).into())),
        IpAddr::V6(a) if bits <= 128 => Some(IpAddr::V6((u128::from(a) & mask(128)).into())),
        _ => None,
    }
}

pub fn prefix_contains(net: IpAddr, width: u8, ip: IpAddr) -> bool {
    network(ip, width) == Some(net)
}

fn dns_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

impl Value {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Bool(_) => 1,
            Self::Int(_) => 2,
            Self::Text(_) => 3,
            Self::Dns(_) => 4,
            Self::Addr(_) => 5,
            Self::Prefix(..) => 6,
            Self::Bytes(_) => 7,
            Self::Array(t, _) => 0x80 | t,
        }
    }
    pub fn text_len(&self) -> usize {
        match self {
            Self::Text(s) | Self::Dns(s) => s.len(),
            _ => 0,
        }
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::Bool(_) | Self::Int(_) => true,
            Self::Text(s) => s.len() <= MAX_STRING,
            Self::Dns(s) => dns_valid(s),
            Self::Addr(ip) => address_valid(*ip),
            Self::Prefix(ip, n) => address_valid(*ip) && network(*ip, *n) == Some(*ip),
            Self::Bytes(b) => b.as_ref().len() <= MAX_BYTES,
            Self::Array(t, a) => {
                (1..=7).contains(t)
                    && a.len() <= MAX_ARRAY
                    && a.iter().all(|v| v.kind() == *t && v.valid())
            }
        }
    }
    fn text(&self) -> Result<&str, String> {
        match self {
            Self::Text(s) | Self::Dns(s) => Ok(s),
            _ => Err("expected text".into()),
        }
    }
    fn int(&self) -> Result<i64, String> {
        match self {
            Self::Int(n) => Ok(*n),
            _ => Err("expected integer".into()),
        }
    }
    fn blob(&self) -> Result<&Blob, String> {
        match self {
            Self::Bytes(b) => Ok(b),
            _ => Err("expected bytes".into()),
        }
    }
}

pub fn charge(budget: &mut usize, n: usize) -> Result<(), String> {
    *budget = budget
        .checked_sub(n)
        .ok_or("byte processing budget exceeded")?;
    Ok(())
}

fn equal(a: &Value, b: &Value, budget: &mut usize) -> Result<bool, String> {
    match (a, b) {
        (Value::Text(x), Value::Text(y)) | (Value::Dns(x), Value::Dns(y)) if x.len() == y.len() => {
            charge(budget, x.len())?
        }
        (Value::Bytes(x), Value::Bytes(y)) if x.as_ref().len() == y.as_ref().len() => {
            charge(budget, x.as_ref().len())?
        }
        _ => (),
    }
    Ok(a == b)
}

pub fn binary(op: &str, a: &Value, b: &Value, budget: &mut usize) -> Result<Value, String> {
    use Value::*;
    match op {
        "in" => {
            if let (Addr(ip), Prefix(net, bits)) = (a, b) {
                return Ok(Bool(prefix_contains(*net, *bits, *ip)));
            }
            if let Array(_, items) = b {
                for x in items.iter() {
                    if equal(a, x, budget)? {
                        return Ok(Bool(true));
                    }
                }
                return Ok(Bool(false));
            }
            Err("invalid membership operands".into())
        }
        "==" | "!=" => Ok(Bool(equal(a, b, budget)? == (op == "=="))),
        "<" | ">" | "<=" | ">=" => {
            let order = if let (Int(x), Int(y)) = (a, b) {
                x.cmp(y)
            } else {
                let (x, y) = (a.text()?, b.text()?);
                charge(budget, x.len().min(y.len()))?;
                x.cmp(y)
            };
            Ok(Bool(match op {
                "<" => order.is_lt(),
                ">" => order.is_gt(),
                "<=" => !order.is_gt(),
                _ => !order.is_lt(),
            }))
        }
        "+" if matches!((a, b), (Text(_), Text(_))) => {
            let (x, y) = (a.text()?, b.text()?);
            let n = x.len() + y.len();
            if n > MAX_STRING {
                return Err(BOUNDS.into());
            }
            charge(budget, n)?;
            Ok(Text(format!("{x}{y}").into()))
        }
        _ => {
            let (x, y) = (a.int()?, b.int()?);
            let n = match op {
                "+" => x.checked_add(y),
                "-" => x.checked_sub(y),
                "*" => x.checked_mul(y),
                "/" => x.checked_div(y),
                "%" => x.checked_rem(y),
                _ => return Err("invalid arithmetic".into()),
            };
            n.map(Int).ok_or_else(|| BOUNDS.into())
        }
    }
}

fn stringify(v: &Value, budget: &mut usize) -> Result<Value, String> {
    use Value::*;
    let text: Arc<str> = match v {
        Bool(b) => b.to_string().into(),
        Int(i) => i.to_string().into(),
        Dns(s) | Text(s) => s.clone(),
        Addr(ip) => ip.to_string().into(),
        Prefix(ip, n) => format!("{ip}/{n}").into(),
        Bytes(blob) if blob.as_ref().len() <= MAX_STRING / 2 => {
            let bytes = blob.as_ref();
            charge(budget, 2 * bytes.len())?;
            let mut s = std::string::String::with_capacity(2 * bytes.len());
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for &b in bytes {
                s.push(HEX[usize::from(b >> 4)] as char);
                s.push(HEX[usize::from(b & 15)] as char);
            }
            return Ok(Text(s.into()));
        }
        _ => return Err("value cannot be converted to a bounded string".into()),
    };
    charge(budget, text.len())?;
    Ok(Text(text))
}

fn canon_dns(s: &str) -> Result<Value, String> {
    if s.len() > 254 {
        return Err("DNS name exceeds 253 octets".into());
    }
    if !s.is_ascii() {
        return Err("DNS name requires ASCII labels".into());
    }
    let n = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    if n.is_empty() || n.len() > 253 {
        return Err("invalid DNS name".into());
    }
    for label in n.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err("invalid DNS label".into());
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err("invalid DNS character".into());
        }
    }
    Ok(Value::Dns(n.into()))
}

fn index(v: &Value) -> Result<usize, String> {
    usize::try_from(v.int()?).map_err(|_| BOUNDS.into())
}

pub fn builtin(name: &str, args: &[Value], budget: &mut usize) -> Result<Value, String> {
    use Value::*;
    let at = |i: usize| {
        args.get(i)
            .ok_or_else(|| std::string::String::from("missing argument"))
    };
    let v = at(0)?;
    if matches!(
        name,
        "contains" | "starts_with" | "ends_with" | "addr" | "prefix" | "int" | "dns" | "lower"
    ) {
        charge(budget, v.text_len())?;
    }
    match name {
        "string" => stringify(v, budget),
        "int" => match v {
            Bool(b) => Ok(Int(i64::from(*b))),
            Int(_) => Ok(v.clone()),
            _ => {
                let s = v.text()?;
                s.parse::<i64>()
                    .map(Int)
                    .map_err(|_| "expected a signed 64-bit decimal integer".into())
            }
        },
        "addr" => v
            .text()?
            .parse::<IpAddr>()
            .ok()
            .filter(|ip| address_valid(*ip))
            .map(Addr)
            .ok_or_else(|| "invalid IP address".into()),
        "prefix" => {
            let err = "invalid or noncanonical prefix";
            let (a, w) = v.text()?.split_once('/').ok_or(err)?;
            let ip = a.parse::<IpAddr>().map_err(|_| err)?;
            let n = w.parse::<u8>().map_err(|_| err)?;
            let p = Prefix(ip, n);
            if n.to_string() != w || !p.valid() {
                return Err(err.into());
            }
            Ok(p)
        }
        "dns" => canon_dns(v.text()?),
        "mask" => {
            let Addr(ip) = v else {
                return Err("expected address".into());
            };
            let width = u8::try_from(at(1)?.int()?).map_err(|_| BOUNDS)?;
            Ok(Prefix(network(*ip, width).ok_or(BOUNDS)?, width))
        }
        "bytes" => {
            let data = v.text()?.as_bytes();
            charge(budget, data.len() / 2)?;
            let mut out = Vec::with_capacity(data.len() / 2);
            let nibble = |c: u8| {
                (c as char)
                    .to_digit(16)
                    .map(|d| d as u8)
                    .ok_or("expected pairs of hexadecimal digits")
            };
            let mut pairs = data.chunks_exact(2);
            for pair in &mut pairs {
                out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
            }
            if let Some(last) = pairs.remainder().first() {
                nibble(*last)?;
                return Err("expected pairs of hexadecimal digits".into());
            }
            Ok(Bytes(out.into()))
        }
        "lower" => {
            let s: std::string::String = v
                .text()?
                .chars()
                .map(|c| c.to_lowercase().next().unwrap_or(c))
                .collect();
            if s.len() > MAX_STRING {
                return Err(BOUNDS.into());
            }
            Ok(Text(s.into()))
        }
        "contains" | "starts_with" | "ends_with" => {
            let (s, pattern) = (v.text()?, at(1)?.text()?);
            Ok(Bool(match name {
                "contains" => s.contains(pattern),
                "starts_with" => s.starts_with(pattern),
                _ => s.ends_with(pattern),
            }))
        }
        "len" => Ok(Int(match v {
            Array(_, a) => a.len(),
            Bytes(b) => b.as_ref().len(),
            _ => v.text()?.len(),
        } as i64)),
        "range" => {
            let (start, end) = (v.int()?, at(1)?.int()?);
            let n = end
                .checked_sub(start)
                .filter(|n| (0..=MAX_ARRAY as i64).contains(n))
                .ok_or(BOUNDS)? as usize;
            charge(budget, n * VALUE_COST)?;
            Ok(Array(2, (start..end).map(Int).collect::<Vec<_>>().into()))
        }
        "at" | "byte" | "u16be" | "write_u16be" => {
            let i = index(at(1)?)?;
            if let Array(_, a) = v {
                return a.get(i).cloned().ok_or_else(|| BOUNDS.into());
            }
            let b = v.blob()?.as_ref();
            if matches!(name, "at" | "byte") {
                return Ok(Int(i64::from(*b.get(i).ok_or(BOUNDS)?)));
            }
            let pair = b.get(i..).and_then(|s| s.get(..2)).ok_or(BOUNDS)?;
            if name == "u16be" {
                return Ok(Int(i64::from(u16::from_be_bytes([pair[0], pair[1]]))));
            }
            let value = u16::try_from(at(2)?.int()?).map_err(|_| BOUNDS)?;
            charge(budget, b.len())?;
            let mut out = b.to_vec();
            out[i..i + 2].copy_from_slice(&value.to_be_bytes());
            Ok(Bytes(out.into()))
        }
        "slice" | "replace" => {
            let b = v.blob()?;
            let (i, j) = (index(at(1)?)?, index(at(2)?)?);
            if i > j || j > b.as_ref().len() {
                return Err(BOUNDS.into());
            }
            if name == "slice" {
                return Ok(Bytes(Blob {
                    storage: b.storage.clone(),
                    start: b.start + i,
                    end: b.start + j,
                }));
            }
            let insert = at(3)?.blob()?.as_ref();
            let n = b.as_ref().len() - (j - i) + insert.len();
            if n > MAX_BYTES {
                return Err(BOUNDS.into());
            }
            charge(budget, n)?;
            let mut out = Vec::with_capacity(n);
            out.extend_from_slice(&b.as_ref()[..i]);
            out.extend_from_slice(insert);
            out.extend_from_slice(&b.as_ref()[j..]);
            Ok(Bytes(out.into()))
        }
        _ => Err("unknown operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Value::*;
    fn text(s: &str) -> Value {
        Text(s.into())
    }

    #[test]
    fn prefixes_match_only_their_own_family_and_width() {
        for s in ["0.0.0.0/0", "192.0.2.0/24", "2001:db8:abcd::/48", "::/0"] {
            let Prefix(net, n) = builtin("prefix", &[text(s)], &mut 4096).unwrap() else {
                panic!()
            };
            assert!(prefix_contains(net, n, net));
            let other = if net.is_ipv6() {
                "192.0.2.3"
            } else {
                "2001:db8::1"
            };
            assert!(!prefix_contains(net, n, other.parse().unwrap()));
        }
        for s in [
            "192.0.2.5/24",
            "2001:db8::1/64",
            "::ffff:1.2.3.4/128",
            "1.1.1.1/+32",
        ] {
            assert!(builtin("prefix", &[text(s)], &mut 4096).is_err());
        }
    }
    #[test]
    fn subviews_are_bounded_and_charged_by_visible_length() {
        let seq = Bytes(vec![9, 0, 0, 8].into());
        let part = builtin("slice", &[seq.clone(), Int(1), Int(3)], &mut 0).unwrap();
        assert!(binary("==", &part, &Bytes(vec![0, 0].into()), &mut 1).is_err());
        let changed = builtin("write_u16be", &[part, Int(0), Int(65535)], &mut 2).unwrap();
        assert_eq!(
            builtin("u16be", &[changed, Int(0)], &mut 0).unwrap(),
            Int(65535)
        );
        assert_eq!(builtin("u16be", &[seq, Int(1)], &mut 0).unwrap(), Int(0));
    }
    #[test]
    fn arithmetic_and_allocation_limits() {
        for (op, a, b) in [
            ("+", i64::MAX, 1),
            ("-", i64::MIN, 1),
            ("*", i64::MIN, -1),
            ("/", i64::MIN, -1),
            ("%", 0, 0),
        ] {
            assert!(binary(op, &Int(a), &Int(b), &mut 0).is_err());
        }
        assert!(builtin("range", &[Int(-1), Int(64)], &mut 65536).is_err());
        assert!(builtin("range", &[Int(0), Int(2)], &mut 255).is_err());
        assert_eq!(
            builtin("dns", &[text("EXAMPLE.Test.")], &mut 13).unwrap(),
            Dns("example.test".into())
        );
    }
}
