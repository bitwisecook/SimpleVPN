// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

mod features;
mod text;
mod transport;

use features::{Document, checker};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;

const MAX_SOURCE: usize = 32768;
struct Server {
    documents: HashMap<String, Document>,
    schemas: HashMap<String, Value>,
    checker: PathBuf,
    adapter: String,
    initialized: bool,
    shutting_down: bool,
}
impl Server {
    fn run(&mut self, msg: &Value, out: &mut impl Write) -> io::Result<bool> {
        let id = msg.get("id");
        let method = msg["method"].as_str().unwrap_or("");
        let params = &msg["params"];
        if method == "exit" {
            return Ok(false);
        }
        let uri = params["textDocument"]["uri"].as_str().unwrap_or("");
        let version = params["textDocument"]["version"].as_i64().unwrap_or(-1);
        let error = |code: i32, message: &str| json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}});
        if msg["jsonrpc"] != "2.0" {
            transport::write(out, &error(-32600, "Invalid JSON-RPC request"))?;
            return Ok(true);
        }
        if !self.initialized && method != "initialize" {
            if id.is_some() {
                transport::write(out, &error(-32002, "Server has not initialized"))?;
            }
            return Ok(true);
        }
        let result = match method {
            "initialize" if !self.initialized => {
                self.initialized = true;
                if let Some(a) = params["initializationOptions"]["adapter"]
                    .as_str()
                    .filter(|a| valid_adapter(a))
                {
                    self.adapter = a.into();
                }
                json!({"capabilities":{"positionEncoding":"utf-16","textDocumentSync":{"openClose":true,"change":2},"completionProvider":{"triggerCharacters":["."]},"hoverProvider":true,"documentSymbolProvider":true,"experimental":{"simplevpnConcreteSyntax":true,"simplevpnSyntaxTree":true,"simplevpnEventDiagram":true,"simplevpnRailroad":true}},"serverInfo":{"name":"SimpleVPN Routing Language Server","version":env!("CARGO_PKG_VERSION")}})
            }
            "shutdown" => {
                self.shutting_down = true;
                Value::Null
            }
            _ if self.shutting_down => {
                if id.is_some() {
                    transport::write(out, &error(-32600, "Server has shut down"))?;
                }
                return Ok(true);
            }
            "textDocument/didOpen" | "textDocument/didChange" => {
                if uri.is_empty() || uri.len() > 4096 || version < 0 {
                    return Ok(true);
                }
                let next = if method == "textDocument/didOpen" {
                    if self.documents.len() >= 32 && !self.documents.contains_key(uri) {
                        return Ok(true);
                    }
                    let Some(source) = params["textDocument"]["text"]
                        .as_str()
                        .filter(|s| s.len() <= MAX_SOURCE)
                    else {
                        return Ok(true);
                    };
                    let adapter = params["adapter"].as_str().unwrap_or(&self.adapter);
                    if !valid_adapter(adapter) {
                        return Ok(true);
                    }
                    Document::new(source.into(), version, adapter.into())
                } else {
                    let Some(old) = self.documents.get(uri) else {
                        return Ok(true);
                    };
                    if version <= old.version {
                        return Ok(true);
                    }
                    let Some(source) = params["contentChanges"]
                        .as_array()
                        .and_then(|edits| text::changes(&old.text, edits, MAX_SOURCE))
                    else {
                        return Ok(true);
                    };
                    Document::new(source, version, old.adapter.clone())
                };
                let ds = next.diagnostics(&self.checker);
                self.documents.insert(uri.into(), next);
                transport::write(
                    out,
                    &json!({"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":uri,"version":version,"diagnostics":ds}}),
                )?;
                return Ok(true);
            }
            "textDocument/didClose" => {
                self.documents.remove(uri);
                transport::write(
                    out,
                    &json!({"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":uri,"diagnostics":[]}}),
                )?;
                return Ok(true);
            }
            "textDocument/documentSymbol"
            | "simplevpn/concreteSyntax"
            | "simplevpn/syntaxTree"
            | "simplevpn/eventDiagram"
            | "simplevpn/railroad"
            | "simplevpn/addHandler"
            | "textDocument/completion"
            | "textDocument/hover" => {
                let Some(doc) = self.documents.get(uri) else {
                    transport::write(out, &error(-32602, "Document is not open"))?;
                    return Ok(true);
                };
                match method {
                    "textDocument/documentSymbol" => json!(doc.symbols()),
                    "simplevpn/syntaxTree" => match params.get("firstNode") {
                        None => doc.diagram(),
                        Some(first) => match first.as_u64().and_then(|n| usize::try_from(n).ok()) {
                            Some(n) => doc.syntax_page(n),
                            None => {
                                transport::write(out, &error(-32602, "Invalid firstNode"))?;
                                return Ok(true);
                            }
                        },
                    },
                    "simplevpn/concreteSyntax" => {
                        doc.concrete_syntax(params["firstToken"].as_u64().unwrap_or(0) as usize)
                    }
                    _ => {
                        if !self.schemas.contains_key(&doc.adapter) {
                            let schema =
                                checker(&self.checker, &["--schema-for", &doc.adapter], None)
                                    .ok()
                                    .and_then(|v| serde_json::from_slice(&v).ok())
                                    .unwrap_or(Value::Null);
                            if !schema.is_null() && self.schemas.len() < 64 {
                                self.schemas.insert(doc.adapter.clone(), schema);
                            }
                        }
                        let schema = self.schemas.get(&doc.adapter).unwrap_or(&Value::Null);
                        if method == "simplevpn/eventDiagram" {
                            doc.events(schema)
                        } else if method == "simplevpn/railroad" {
                            doc.railroad(schema)
                        } else if method == "simplevpn/addHandler" {
                            if params["version"].as_i64() != Some(doc.version) {
                                transport::write(
                                    out,
                                    &error(-32801, "Source changed. Open the diagram again."),
                                )?;
                                return Ok(true);
                            }
                            match doc.add_handler(
                                params["event"].as_str().unwrap_or(""),
                                schema,
                                &self.checker,
                            ) {
                                Ok(edit) => edit,
                                Err(why) => {
                                    transport::write(out, &error(-32602, &why))?;
                                    return Ok(true);
                                }
                            }
                        } else {
                            let Some(at) = text::offset(&doc.text, &params["position"]) else {
                                transport::write(out, &error(-32602, "Invalid UTF-16 position"))?;
                                return Ok(true);
                            };
                            if method == "textDocument/hover" {
                                doc.hover(at, schema)
                            } else {
                                doc.completions(at, schema)
                            }
                        }
                    }
                }
            }
            _ => {
                if id.is_some() {
                    transport::write(out, &error(-32601, "Unknown method"))?;
                }
                return Ok(true);
            }
        };
        if id.is_some() {
            transport::write(out, &json!({"jsonrpc":"2.0","id":id,"result":result}))?;
        }
        Ok(true)
    }
}
fn valid_adapter(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn main() -> io::Result<()> {
    let mut checker = std::env::current_exe()?.with_file_name("routecheck");
    let mut adapter = String::from("wireguard-shared");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--stdio" => (),
            "--adapter" => {
                adapter = args
                    .next()
                    .filter(|s| valid_adapter(s))
                    .ok_or_else(|| io::Error::other("expected adapter ID"))?
            }
            "--routecheck" => {
                checker = PathBuf::from(
                    args.next()
                        .ok_or_else(|| io::Error::other("expected checker path"))?,
                )
            }
            "--help" => {
                println!("routing-lsp [--stdio] [--adapter ID] [--routecheck PATH]");
                return Ok(());
            }
            _ => return Err(io::Error::other("unknown option")),
        }
    }
    let mut server = Server {
        documents: HashMap::new(),
        schemas: HashMap::new(),
        checker,
        adapter,
        initialized: false,
        shutting_down: false,
    };
    let mut reader = io::stdin().lock();
    let mut writer = io::stdout().lock();
    while let Some(body) = transport::read(&mut reader)? {
        match serde_json::from_slice(&body) {
            Ok(msg) => {
                if !server.run(&msg, &mut writer)? {
                    if !server.shutting_down {
                        std::process::exit(1)
                    }
                    break;
                }
            }
            Err(_) => transport::write(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON"}}),
            )?,
        }
    }
    Ok(())
}
