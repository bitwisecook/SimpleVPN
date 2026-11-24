// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use serde_json::{Value, json};

/// LSP columns are UTF-16 code units. Internal syntax spans are UTF-8 bytes.
/// CRLF is one line ending; positions cannot cut through a surrogate pair.
pub fn offset(text: &str, pos: &Value) -> Option<usize> {
    let target = usize::try_from(pos.get("line")?.as_u64()?).ok()?;
    let column = usize::try_from(pos.get("character")?.as_u64()?).ok()?;
    let start = if target == 0 {
        0
    } else {
        text.match_indices('\n').nth(target - 1)?.0 + 1
    };
    let line = text[start..].split('\n').next()?.trim_end_matches('\r');
    let mut units = 0;
    for (byte, c) in line.char_indices() {
        if units == column {
            return Some(start + byte);
        }
        units += c.len_utf16();
        if units > column {
            return None;
        }
    }
    (column == units).then_some(start + line.len())
}

pub fn position(text: &str, byte: usize) -> Value {
    let mut b = byte.min(text.len());
    while !text.is_char_boundary(b) {
        b -= 1;
    }
    let before = &text[..b];
    let column = before
        .rsplit('\n')
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .encode_utf16()
        .count();
    json!({"line":before.bytes().filter(|b|*b==b'\n').count(),"character":column})
}

pub fn range(text: &str, start: usize, end: usize) -> Value {
    json!({"start":position(text,start),"end":position(text,end.max(start))})
}

/// Changes within one LSP notification address the previous change's result.
/// Apply transactionally so a malformed edit cannot half-update a document.
pub fn changes(source: &str, edits: &[Value], limit: usize) -> Option<String> {
    if edits.is_empty() || edits.len() > 256 {
        return None;
    }
    let mut next = source.to_owned();
    for edit in edits {
        let replacement = edit.get("text")?.as_str()?;
        if let Some(r) = edit.get("range") {
            let a = offset(&next, r.get("start")?)?;
            let b = offset(&next, r.get("end")?)?;
            if a > b || next.len() - (b - a) + replacement.len() > limit {
                return None;
            }
            next.replace_range(a..b, replacement);
        } else {
            if replacement.len() > limit {
                return None;
            }
            next.clear();
            next.push_str(replacement);
        }
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utf16_edits_are_atomic() {
        let src = "a💡\r\n雪";
        let edit = json!({"range":range(src,1,5),"text":"ok"});
        assert_eq!(changes(src, &[edit], 80).as_deref(), Some("aok\r\n雪"));
        assert_eq!(offset(src, &json!({"line":0,"character":2})), None);
        assert_eq!(
            offset(src, &json!({"line":1,"character":1})),
            Some(src.len())
        );
    }
}
