// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//! Lossless editor tokens and source ranges. All offsets are UTF-8 byte
//! boundaries. An incomplete handler remains selectable while the user types.

mod expressions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub kind: &'static str,
    pub name: Option<String>,
    pub event: Option<String>,
    pub start: usize,
    pub end: usize,
    pub selection_start: usize,
    pub selection_end: usize,
    pub children: Vec<Node>,
    /// Present on declarations and statements, as opposed to expression details.
    pub header_end: Option<usize>,
    /// The interior of a matched pair of braces, including any trivia.
    pub body_range: Option<(usize, usize)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub start: usize,
    pub end: usize,
    pub message: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Document {
    pub tokens: Vec<Token>,
    pub declarations: Vec<Node>,
    pub diagnostics: Vec<Diagnostic>,
}

fn keyword(s: &str) -> bool {
    matches!(
        s,
        "on" | "fn"
            | "table"
            | "external"
            | "if"
            | "else"
            | "match"
            | "found"
            | "missing"
            | "for"
            | "in"
            | "let"
            | "var"
            | "return"
            | "true"
            | "false"
    )
}

fn lex(source: &str, doc: &mut Document) {
    let bytes = source.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        let b = bytes[pos];
        pos += 1;
        let kind = match b {
            b if b.is_ascii_whitespace() => {
                while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                "whitespace"
            }
            b'#' | b'/' if b == b'#' || bytes.get(pos) == Some(&b'/') => {
                pos += source[pos..].find('\n').unwrap_or(bytes.len() - pos);
                "comment"
            }
            b'"' => {
                let mut closed = false;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    match bytes[pos] {
                        b'"' => {
                            pos += 1;
                            closed = true;
                            break;
                        }
                        b'\\' if bytes.get(pos + 1).is_some_and(|c| *c != b'\n') => pos += 2,
                        _ => pos += 1,
                    }
                }
                if !closed {
                    doc.diagnostics.push(Diagnostic {
                        start,
                        end: pos,
                        message: "Unterminated string".into(),
                    });
                }
                "string"
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                while bytes
                    .get(pos)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.'))
                {
                    pos += 1;
                }
                if keyword(&source[start..pos]) {
                    "keyword"
                } else {
                    "identifier"
                }
            }
            b'0'..=b'9' => {
                while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                    pos += 1;
                }
                if bytes.get(pos) == Some(&b'.') {
                    while bytes
                        .get(pos)
                        .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'.' | b'/'))
                    {
                        pos += 1;
                    }
                    "address"
                } else {
                    "integer"
                }
            }
            _ => {
                if !b.is_ascii() {
                    pos = start
                        + source[start..]
                            .chars()
                            .next()
                            .expect("character boundary")
                            .len_utf8();
                } else if bytes.get(start..pos + 1).is_some_and(|pair| {
                    matches!(
                        pair,
                        b"->" | b"=>" | b"==" | b"!=" | b"&&" | b"||" | b"<=" | b">="
                    )
                }) {
                    pos += 1;
                }
                "operator"
            }
        };
        doc.tokens.push(Token {
            kind,
            start,
            end: pos,
        });
    }
}

struct Tree<'a> {
    source: &'a str,
    tokens: Vec<&'a Token>,
    pairs: Vec<Option<usize>>,
}

impl Tree<'_> {
    fn text(&self, i: usize) -> &str {
        self.tokens
            .get(i)
            .map_or("", |t| &self.source[t.start..t.end])
    }

    fn node(&self, kind: &'static str, first: usize, end: usize, name: Option<usize>) -> Node {
        let selected = self.tokens[name.unwrap_or(first)];
        Node {
            kind,
            name: name.map(|i| self.text(i).to_owned()),
            event: None,
            start: self.tokens[first].start,
            end: self.tokens[end - 1].end,
            selection_start: selected.start,
            selection_end: selected.end,
            children: Vec::new(),
            header_end: None,
            body_range: None,
        }
    }

    fn declarations(&self, first: usize, end: usize, nested: bool) -> Vec<Node> {
        let mut nodes = Vec::new();
        let mut i = first;
        while i < end {
            let word = self.text(i);
            let kind = match word {
                "on" => "handler",
                "fn" => "function",
                "table" => "table",
                "let" | "var" => "binding",
                "if" => "if",
                "else" if self.text(i + 1) == "if" => "elseIf",
                "else" => "else",
                "match" => "match",
                "for" => "for",
                "found" => "found",
                "missing" => "missing",
                "return" => "return",
                _ if nested && self.text(i + 1) == "=" => "assignment",
                _ if nested => "expression",
                _ => "statement",
            };
            let named = matches!(kind, "handler" | "function" | "table" | "binding" | "for");
            let name =
                (named && i + 1 < end && self.tokens[i + 1].kind == "identifier").then_some(i + 1);
            let compact = !nested
                && (word == "on" && self.text(i + 2) != ":"
                    || !matches!(word, "on" | "fn" | "table"));
            let mut j = i + 1;
            let mut body = None;
            while j < end {
                if compact
                    && self.source[self.tokens[j - 1].end..self.tokens[j].start].contains('\n')
                {
                    break;
                }
                let text = self.text(j);
                if text == ";" {
                    j += 1;
                    break;
                }
                if text == "{" {
                    let close = self.pairs[j].unwrap_or(end).min(end);
                    body = Some((j + 1, close));
                    j = (close + 1).min(end);
                    if j < end && self.text(j) == ";" {
                        j += 1;
                    }
                    break;
                }
                if j > i && !nested && matches!(text, "on" | "fn" | "table") {
                    break;
                }
                if matches!(text, "(" | "[") {
                    j = self.pairs[j].unwrap_or(j);
                }
                j += 1;
            }
            let mut node = self.node(kind, i, j, name);
            node.header_end = Some(body.map_or(node.end, |(first, _)| self.tokens[first - 1].start));
            node.body_range = body.and_then(|(first, last)| {
                (last < end).then(|| (self.tokens[first - 1].end, self.tokens[last].start))
            });
            if kind == "handler" {
                let event = i + if compact { 2 } else { 3 };
                if event < j && self.tokens[event].kind == "identifier" {
                    node.event = Some(self.text(event).into());
                }
            }
            self.describe(&mut node, i, j, body, compact);
            if let Some((first, last)) = body.filter(|(a, b)| kind != "table" && a < b) {
                node.children.extend(self.declarations(first, last, true));
            }
            nodes.push(node);
            i = j;
        }
        nodes
    }
}

pub fn parse(source: &str) -> Document {
    let mut doc = Document::default();
    if source.len() > 256 * 1024 {
        doc.diagnostics.push(Diagnostic {
            start: 0,
            end: source.len(),
            message: "Source exceeds 256 KiB".into(),
        });
        return doc;
    }
    lex(source, &mut doc);
    let tokens: Vec<_> = doc
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, "comment" | "whitespace"))
        .collect();
    let mut tree = Tree {
        source,
        pairs: vec![None; tokens.len()],
        tokens,
    };
    let mut stack = Vec::new();
    for (i, t) in tree.tokens.iter().enumerate() {
        match &source[t.start..t.end] {
            "(" | "[" | "{" => {
                if stack.len() >= 64 {
                    doc.diagnostics.push(Diagnostic {
                        start: t.start,
                        end: t.end,
                        message: "Nesting exceeds 64 delimiters".into(),
                    });
                    return doc;
                }
                stack.push(i);
            }
            closer @ (")" | "]" | "}") => {
                let opener = match closer {
                    ")" => "(",
                    "]" => "[",
                    _ => "{",
                };
                if stack.last().is_some_and(|&j| tree.text(j) == opener) {
                    let j = stack.pop().expect("matched opener");
                    tree.pairs[j] = Some(i);
                } else {
                    doc.diagnostics.push(Diagnostic {
                        start: t.start,
                        end: t.end,
                        message: format!("Unexpected {closer}"),
                    });
                }
            }
            _ => {}
        }
    }
    for j in stack {
        let t = tree.tokens[j];
        doc.diagnostics.push(Diagnostic {
            start: t.start,
            end: t.end,
            message: format!("Unclosed {}", tree.text(j)),
        });
    }
    doc.declarations = tree.declarations(0, tree.tokens.len(), false);
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gui_can_edit_typed_tables_branches_and_lookup_bindings() {
        let source = "table sites: prefix -> int = {10.0.0.0/8: 3};\n\
        on route: ip.packet { let tag: int = 6; match lookup(sites, ip.src) {\n\
        found(value) { if value > tag { count(); } else if !false && value == 3 { count(); } }\n\
        missing { drop(); } } }";
        let document = parse(source);
        assert!(document.diagnostics.is_empty());
        let table = &document.declarations[0];
        assert_eq!(
            table.children.iter().map(|n| n.kind).collect::<Vec<_>>(),
            ["keyType", "valueType", "entry"]
        );
        let handler = &document.declarations[1];
        assert_eq!(handler.children[0].children[0].name.as_deref(), Some("int"));
        let found = &handler.children[1].children[1];
        assert_eq!(found.kind, "found");
        assert_eq!(found.children[0].name.as_deref(), Some("value"));
        let else_if = &found.children[2];
        assert_eq!(else_if.kind, "elseIf");
        let condition = &else_if.children[0];
        assert_eq!(condition.name.as_deref(), Some("&&"));
        assert_eq!(condition.children[0].kind, "unary");
        assert_eq!(condition.children[1].name.as_deref(), Some("=="));
        // Every prefix is a possible editor state, including unfinished types or arms.
        for (end, _) in source.char_indices() {
            parse(&source[..end]);
        }
    }
    #[test]
    fn ranges_survive_comments_unicode_and_incomplete_edits() {
        let s = "# 🦀\non rule: dns.query { let a = \"é}\"; if true { drop(); } }\non later tcp.syn => drop";
        let d = parse(s);
        assert!(d.diagnostics.is_empty());
        assert_eq!(
            d.tokens
                .iter()
                .map(|t| &s[t.start..t.end])
                .collect::<String>(),
            s
        );
        assert_eq!(d.declarations.len(), 2);
        let n = &d.declarations[0];
        assert_eq!(&s[n.selection_start..n.selection_end], "rule");
        assert_eq!(n.children[1].children[1].children[0].kind, "call");
        assert_eq!(d.declarations[1].event.as_deref(), Some("tcp.syn"));
        assert!(!parse("on x: ip.packet {").diagnostics.is_empty());
    }
}
