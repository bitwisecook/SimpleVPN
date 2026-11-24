// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use crate::text;
use serde_json::{Value, json};
use simplevpn_routing_core::syntax::{self, Node};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct Document {
    pub text: String,
    pub version: i64,
    pub adapter: String,
    tree: syntax::Document,
}

pub fn checker(tool: &Path, args: &[&str], source: Option<&str>) -> Result<Vec<u8>, String> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "The routing checker is unavailable.".to_owned())?;
    if let Some(mut input) = child.stdin.take() {
        if let Some(source) = source {
            let _ = input.write_all(source.as_bytes());
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|_| "The routing checker stopped unexpectedly.".to_owned())?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(
            String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(2048)])
                .trim()
                .to_owned(),
        )
    }
}

impl Document {
    pub fn new(text: String, version: i64, adapter: String) -> Self {
        let tree = syntax::parse(&text);
        Self {
            text,
            version,
            adapter,
            tree,
        }
    }
    pub fn diagnostics(&self, tool: &Path) -> Vec<Value> {
        let result = checker(
            tool,
            &["--events-for", &self.adapter, "-"],
            Some(&self.text),
        );
        let mut diagnostics = Vec::new();
        if let Err(message) = result {
            // Compact and typed handlers share the editor. The activation checker
            // accepts both; its success supersedes a typed-only parser diagnostic.
            for d in self.tree.diagnostics.iter().take(48) {
                diagnostics.push(json!({"range":text::range(&self.text,d.start,d.end),"message":d.message,"severity":1,"source":"routing syntax"}));
            }
            if !diagnostics
                .iter()
                .any(|d| d["message"].as_str() == Some(&message))
            {
                let line = message
                    .split("line ")
                    .nth(1)
                    .and_then(|s| s.split(':').next()?.parse::<usize>().ok())
                    .unwrap_or(1)
                    .saturating_sub(1);
                let start = if line == 0 {
                    0
                } else {
                    self.text
                        .match_indices('\n')
                        .nth(line - 1)
                        .map_or(0, |(i, _)| i + 1)
                };
                let width = self.text[start..]
                    .split(['\n', '\r'])
                    .next()
                    .unwrap_or("")
                    .len();
                diagnostics.push(json!({"range":text::range(&self.text,start,start+width),"message":message,"severity":1,"source":"routecheck"}));
            }
        }
        diagnostics
    }
    pub fn symbols(&self) -> Vec<Value> {
        self.tree.declarations.iter().map(|n|json!({"name":n.name.as_deref().unwrap_or(n.kind),"detail":n.event,"kind":match n.kind{"function"=>12,"handler"=>24,"table"=>19,_=>13},"range":text::range(&self.text,n.start,n.end),"selectionRange":text::range(&self.text,n.selection_start,n.selection_end)})).collect()
    }
    /// The editor already has the versioned source. Half-open UTF-8 byte ranges
    /// address every byte including whitespace, comments and incomplete lexemes.
    pub fn concrete_syntax(&self, first: usize) -> Value {
        let start = first.min(self.tree.tokens.len());
        let end = (start + 512).min(self.tree.tokens.len());
        let tokens: Vec<_> = self.tree.tokens[start..end]
            .iter()
            .map(|t| json!({"kind":t.kind,"startByte":t.start,"endByte":t.end}))
            .collect();
        json!({"version":self.version,"tokens":tokens,"nextToken":(end<self.tree.tokens.len()).then_some(end)})
    }
    /// Stable preorder indices let GUI clients reconstruct even a very large
    /// partially typed tree without putting an unbounded reply on the pipe.
    pub fn syntax_page(&self, first: usize) -> Value {
        const PAGE_SIZE: usize = 512;
        let mut nodes = Vec::new();
        let mut next = None;
        let mut pending: Vec<_> = self
            .tree
            .declarations
            .iter()
            .rev()
            .map(|n| (n, None))
            .collect();
        let mut index = 0_usize;
        while let Some((node, parent)) = pending.pop() {
            if index >= first {
                if nodes.len() == PAGE_SIZE {
                    next = Some(index);
                    break;
                }
                nodes.push(json!({"index":index,"parent":parent,"kind":node.kind,"name":node.name,
                    "event":node.event,"startByte":node.start,"endByte":node.end,
                    "selectionStartByte":node.selection_start,"selectionEndByte":node.selection_end}));
            }
            pending.extend(node.children.iter().rev().map(|child| (child, Some(index))));
            index += 1;
        }
        json!({"version":self.version,"nodes":nodes,"nextNode":next})
    }

    pub fn diagram(&self) -> Value {
        fn branch(text: &str, n: &Node, left: &mut usize) -> Option<Value> {
            if *left == 0 {
                return None;
            }
            *left -= 1;
            let children: Vec<_> = n
                .children
                .iter()
                .filter_map(|c| branch(text, c, left))
                .collect();
            Some(
                json!({"kind":n.kind,"name":n.name,"event":n.event,"range":crate::text::range(text,n.start,n.end),"selectionRange":crate::text::range(text,n.selection_start,n.selection_end),"children":children}),
            )
        }
        let mut left = 1200;
        let nodes: Vec<_> = self
            .tree
            .declarations
            .iter()
            .filter_map(|n| branch(&self.text, n, &mut left))
            .collect();
        json!({"version":self.version,"nodes":nodes,"truncated":left==0})
    }

    pub fn events(&self, schema: &Value) -> Value {
        let events: Vec<_> = schema["events"].as_object().into_iter().flatten().map(|(id, _)| {
            let handlers: Vec<_> = self.tree.declarations.iter()
                .filter(|n| n.kind=="handler" && n.event.as_ref()==Some(id))
                .map(|n|json!({"name":n.name,"range":text::range(&self.text,n.selection_start,n.selection_end)})).collect();
            json!({"event":id,"handlers":handlers})
        }).collect();
        json!({"version":self.version,"events":events})
    }

    pub fn railroad(&self, schema: &Value) -> Value {
        fn block(source: &str, node: &Node, remaining: &mut usize) -> Option<Value> {
            if *remaining == 0 {
                return None;
            }
            *remaining -= 1;
            if *remaining == 0 {
                return None;
            }
            let children: Vec<_> = node.children.iter()
                .filter(|child| child.header_end.is_some() || matches!(child.kind, "predicate" | "action"))
                .filter_map(|child| block(source, child, remaining))
                .collect();
            let end = node.header_end.unwrap_or(node.end);
            let expression = match node.kind {
                "if" | "elseIf" | "assignment" | "binding" | "expression" | "return" | "for" | "match" =>
                    node.children.iter().find(|child| child.header_end.is_none() && child.kind != "type"),
                _ => None,
            };
            let expression_range = expression.map(|expr| text::range(source, expr.start, expr.end));
            Some(json!({
                "id": node.start, "kind": node.kind, "name": node.name, "event": node.event,
                "range": text::range(source, node.start, node.end),
                "header": text::range(source, node.start, end),
                "body": node.body_range.map(|(a,b)| text::range(source,a,b)),
                "condition": if matches!(node.kind, "if" | "elseIf") { expression_range.clone() } else { None },
                "expression": expression.map(|expr| json!({
                    "kind": expr.kind,
                    "name": expr.name,
                    "range": expression_range,
                    "operands": expr.children.iter().take(3).map(|operand| json!({
                        "kind": operand.kind, "range": text::range(source, operand.start, operand.end),
                    })).collect::<Vec<_>>(),
                })),
                "children": children,
                "call": node.kind == "expression" && node.children.first().is_some_and(|child| child.kind == "call"),
            }))
        }

        // The extra slot lets the response distinguish an exactly full diagram
        // from one where a declaration or statement had to be omitted.
        let mut remaining = 241;
        let declarations: Vec<_> = self.tree.declarations.iter()
            .filter_map(|node| block(&self.text, node, &mut remaining))
            .collect();
        let events: Vec<_> = schema["events"].as_object().into_iter().flatten()
            .map(|(name, _)| name).collect();
        json!({
            "version": self.version, "declarations": declarations, "events": events,
            "complete": self.tree.diagnostics.is_empty(), "limited": remaining == 0,
        })
    }

    pub fn add_handler(&self, event: &str, schema: &Value, tool: &Path) -> Result<Value, String> {
        if schema["events"].get(event).is_none() {
            return Err("This event is unavailable on the selected adapter.".into());
        }
        let base = format!("handle_{}", event.replace('.', "_"));
        let mut name = base.clone();
        let mut suffix = 2;
        while self
            .tree
            .declarations
            .iter()
            .any(|n| n.name.as_ref() == Some(&name))
        {
            name = format!("{base}_{suffix}");
            suffix += 1;
        }
        let compact = self.tree.declarations.first().is_some_and(|n| {
            n.kind == "handler"
                && self
                    .tree
                    .tokens
                    .iter()
                    .filter(|t| {
                        t.start >= n.start
                            && t.end <= n.end
                            && !matches!(t.kind, "whitespace" | "comment")
                    })
                    .nth(2)
                    .is_some_and(|t| &self.text[t.start..t.end] != ":")
        });
        let declaration = if compact {
            // The compact and typed forms cannot be combined. Ask the actual
            // adapter compiler whether this event has a compact spelling.
            let compact = format!("on {name} {event} => count\n");
            checker(tool,&["--events-for",&self.adapter,"-"],Some(&compact)).map_err(|_|"This event requires typed source. Convert the existing compact handlers before adding it.".to_string())?;
            compact
        } else {
            format!("on {name}: {event} {{\n    count();\n}}\n")
        };
        let padding = if self.text.is_empty() {
            ""
        } else if self.text.ends_with("\n") {
            "\n"
        } else {
            "\n\n"
        };
        let insert = format!("{padding}{declaration}");
        if self.text.len() + insert.len() > 32768 {
            return Err("This handler would exceed the 32 KiB source limit.".into());
        }
        let next = format!("{}{insert}", self.text);
        let tree = syntax::parse(&next);
        let node = tree
            .declarations
            .iter()
            .find(|n| n.name.as_ref() == Some(&name) && n.event.as_deref() == Some(event))
            .ok_or_else(|| {
                "Finish the current declaration before adding another handler.".to_owned()
            })?;
        Ok(
            json!({"version":self.version,"name":name,"edit":{"range":text::range(&self.text,self.text.len(),self.text.len()),"newText":insert},
            "selectionRange":text::range(&next,node.selection_start,node.selection_end)}),
        )
    }

    /// The syntax tree determines the enclosing event and declaration scope.
    fn vocabulary(&self, at: usize, schema: &Value) -> BTreeMap<String, (u8, String)> {
        let mut items = BTreeMap::new();
        if let Some(events) = schema["events"].as_object() {
            for (event, _) in events {
                items.insert(event.clone(), (23, format!("Event · {}", self.adapter)));
            }
            let scope = self
                .tree
                .declarations
                .iter()
                .find(|n| n.start <= at && at <= n.end)
                .and_then(|n| n.event.as_ref());
            if let Some(ev) = scope.and_then(|e| events.get(e)) {
                if let Some(fields) = ev["fields"].as_object() {
                    for (name, field) in fields {
                        let kind = field["type"].as_str().unwrap_or("value");
                        let mode = if field["writable"] == true {
                            "read/write"
                        } else {
                            "read-only"
                        };
                        items.insert(name.clone(), (5, format!("{kind} · {mode} field")));
                    }
                }
                if let Some(actions) = ev["actions"].as_object() {
                    for (name, args) in actions {
                        let types = args
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ");
                        items.insert(name.clone(), (2, format!("{name}({types}) · event action")));
                    }
                }
            }
        }
        for name in schema["builtins"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            items.insert(name.into(), (3, "Built-in function".into()));
        }
        for n in &self.tree.declarations {
            if let Some(name) = &n.name {
                items.entry(name.clone()).or_insert_with(|| {
                    (
                        if n.kind == "function" { 3 } else { 6 },
                        format!("{} in this document", n.kind),
                    )
                });
            }
        }
        items
    }
    fn token_extent(&self, at: usize) -> (usize, usize) {
        // Identifiers come from the compiler's token stream. A cursor at the
        // end of a token still targets that token for native completion.
        let identifier = |t: &&syntax::Token| {
            self.text[t.start..t.end]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        };
        let tokens = &self.tree.tokens;
        tokens
            .iter()
            .find(|t| t.start <= at && at < t.end && identifier(t))
            .or_else(|| tokens.iter().find(|t| t.end == at && identifier(t)))
            .map_or((at, at), |t| (t.start, t.end))
    }
    pub fn completions(&self, at: usize, schema: &Value) -> Value {
        let (start, end) = self.token_extent(at);
        let prefix = &self.text[start..at];
        let range = text::range(&self.text, start, end);
        let items:Vec<_>=self.vocabulary(at,schema).into_iter().filter(|(k,_)|k.starts_with(prefix)).take(256)
            .map(|(k,(kind,detail))|json!({"label":k,"kind":kind,"detail":detail,"textEdit":{"range":range,"newText":k}})).collect();
        json!({"isIncomplete":false,"items":items})
    }
    pub fn hover(&self, at: usize, schema: &Value) -> Value {
        let (start, end) = self.token_extent(at);
        let name = &self.text[start..end];
        self.vocabulary(at,schema).get(name).map_or(Value::Null,|(_,detail)|json!({"range":text::range(&self.text,start,end),"contents":{"kind":"plaintext","value":format!("{name}\n{detail}")}}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn railroad_projects_branches_and_compact_handlers_with_versioned_ranges() {
        let source = "# café 💡\r\non observe: ip.packet {\r\n    if ip.dscp != 0 { count(); } else { ip.dscp = 16; }\r\n}\r\n";
        let document = Document::new(source.into(), 12, "wireguard".into());
        let graph = document.railroad(&json!({"events": {"ip.packet": {}}}));
        assert_eq!(graph["version"], 12);
        assert_eq!(graph["complete"], true);
        assert_eq!(graph["events"], json!(["ip.packet"]));
        let handler = &graph["declarations"][0];
        assert_eq!(handler["body"]["end"], json!({"line":3,"character":0}));
        let condition = &handler["children"][0];
        let start = source.find("ip.dscp != 0").unwrap();
        assert_eq!(condition["condition"], text::range(source, start, start + "ip.dscp != 0".len()));
        let expression = &condition["expression"];
        assert_eq!(expression["name"], "!=");
        assert_eq!(expression["operands"][0]["kind"], "reference");
        assert_eq!(expression["operands"][0]["range"], text::range(source, start, start + "ip.dscp".len()));
        assert_eq!(expression["operands"][1]["kind"], "literal");
        assert_eq!(condition["children"][0]["call"], true);
        assert_eq!(condition["children"][0]["expression"]["name"], "count");
        assert_eq!(handler["children"][1]["kind"], "else");
        assert_eq!(handler["children"][1]["children"][0]["expression"]["kind"], "literal");

        let compact = Document::new("on web tcp.syn port 443 => clamp-mss 1280\n".into(), 13, "wireguard".into())
            .railroad(&Value::Null);
        assert!(compact["declarations"][0]["body"].is_null());
        assert_eq!(compact["declarations"][0]["children"][0]["kind"], "predicate");
        assert_eq!(compact["declarations"][0]["children"][1]["kind"], "action");

        let incomplete = Document::new("on incomplete: ip.packet {".into(), 14, "wireguard".into())
            .railroad(&Value::Null);
        assert_eq!(incomplete["complete"], false);
    }

    #[test]
    fn syntax_pages_reconstruct_the_entire_versioned_tree() {
        let source = format!(
            "# 🦀\non demo: ip.packet {{\n{}\n}}",
            "count();\n".repeat(700)
        );
        let document = Document::new(source.clone(), 9, "openvpn3".into());
        let mut nodes = Vec::new();
        let mut first = 0;
        loop {
            let page = document.syntax_page(first);
            assert_eq!(page["version"], 9);
            nodes.extend(page["nodes"].as_array().unwrap().iter().cloned());
            let Some(next) = page["nextNode"].as_u64() else {
                break;
            };
            first = next as usize;
        }
        assert!(nodes.len() > 1200);
        assert_eq!(nodes[0]["parent"], Value::Null);
        for (i, node) in nodes.iter().enumerate() {
            assert_eq!(node["index"], i);
            if let Some(p) = node["parent"].as_u64() {
                assert!((p as usize) < i);
            }
            if node["kind"] == "call" {
                let start = node["selectionStartByte"].as_u64().unwrap() as usize;
                let end = node["selectionEndByte"].as_u64().unwrap() as usize;
                assert_eq!(&source[start..end], "count");
            }
        }
        let mut offset = 0;
        let mut token = 0;
        loop {
            let page = document.concrete_syntax(token);
            for t in page["tokens"].as_array().unwrap() {
                assert_eq!(t["startByte"], offset);
                offset = t["endByte"].as_u64().unwrap() as usize;
            }
            let Some(next) = page["nextToken"].as_u64() else {
                break;
            };
            token = next as usize;
        }
        assert_eq!(offset, source.len());
    }
}
