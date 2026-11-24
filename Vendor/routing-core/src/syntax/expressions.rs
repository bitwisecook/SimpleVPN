// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::{Node, Tree};

fn precedence(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "==" | "!=" | "in" => 3,
        "<" | ">" | "<=" | ">=" => 4,
        "+" | "-" => 5,
        "*" | "/" | "%" => 6,
        _ => return None,
    })
}

impl Tree<'_> {
    fn outside(&self, start: usize, end: usize) -> impl Iterator<Item = usize> + '_ {
        std::iter::successors((start < end).then_some(start), move |i| {
            let next = self.pairs[*i].unwrap_or(*i) + 1;
            (next < end).then_some(next)
        })
    }

    fn parts(&self, start: usize, end: usize) -> Vec<(usize, usize)> {
        let mut from = start;
        let mut items = Vec::new();
        for i in self.outside(start, end) {
            if self.text(i) == "," {
                if from < i {
                    items.push((from, i));
                }
                from = i + 1;
            }
        }
        if from < end {
            items.push((from, end));
        }
        items
    }

    fn expr(&self, start: usize, end: usize, depth: usize) -> Option<Node> {
        if start >= end {
            return None;
        }
        if depth >= 32 {
            return Some(self.node("expression", start, end, None));
        }
        let mut operator = None;
        let mut level = u8::MAX;
        let mut operand_expected = true;
        for i in self.outside(start, end) {
            let current = self.text(i);
            if let Some(p) = precedence(current) {
                if !operand_expected && p <= level {
                    operator = Some(i);
                    level = p;
                }
                operand_expected = true;
            } else {
                operand_expected = current == "!";
            }
        }
        if let Some(i) = operator {
            let mut n = self.node("binary", start, end, Some(i));
            n.children.extend(self.expr(start, i, depth + 1));
            n.children.extend(self.expr(i + 1, end, depth + 1));
            return Some(n);
        }
        let head = self.text(start);
        if matches!(head, "!" | "-") {
            let mut n = self.node("unary", start, end, Some(start));
            n.children.extend(self.expr(start + 1, end, depth + 1));
            return Some(n);
        }
        if let Some(tail) = self.outside(start, end).last() {
            if tail > start && self.text(tail) == "[" && self.pairs[tail] == Some(end - 1) {
                let mut n = self.node("index", start, end, None);
                n.children.extend(self.expr(start, tail, depth + 1));
                n.children.extend(self.expr(tail + 1, end - 1, depth + 1));
                return Some(n);
            }
        }
        if start + 1 < end && self.text(start + 1) == "(" && self.pairs[start + 1] == Some(end - 1)
        {
            let mut n = self.node("call", start, end, Some(start));
            for (a, b) in self.parts(start + 2, end - 1) {
                n.children.extend(self.expr(a, b, depth + 1));
            }
            return Some(n);
        }
        if matches!(head, "(" | "[") && self.pairs[start] == Some(end - 1) {
            let mut n = self.node(
                if head == "(" { "group" } else { "array" },
                start,
                end,
                None,
            );
            for (a, b) in self.parts(start + 1, end - 1) {
                n.children.extend(self.expr(a, b, depth + 1));
            }
            return Some(n);
        }
        let kind = if end == start + 1 {
            match self.tokens[start].kind {
                "identifier" => "reference",
                "string" | "address" | "integer" => "literal",
                "keyword" if matches!(head, "true" | "false") => "literal",
                _ => "expression",
            }
        } else {
            "expression"
        };
        Some(self.node(kind, start, end, (end == start + 1).then_some(start)))
    }

    pub(super) fn describe(
        &self,
        node: &mut Node,
        start: usize,
        end: usize,
        body: Option<(usize, usize)>,
        compact: bool,
    ) {
        let head_end = body.map_or_else(
            || {
                if self.text(end - 1) == ";" {
                    end - 1
                } else {
                    end
                }
            },
            |(first, _)| first - 1,
        );
        if node.kind == "binding" && self.text(start + 2) == ":" {
            if let Some(eq) = self
                .outside(start + 3, head_end)
                .find(|&i| self.text(i) == "=")
            {
                if start + 3 < eq {
                    node.children
                        .push(self.node("type", start + 3, eq, Some(eq - 1)));
                }
            }
        }
        if node.kind == "found"
            && self.text(start + 1) == "("
            && start + 2 < head_end
            && self.tokens[start + 2].kind == "identifier"
        {
            node.children
                .push(self.node("binding", start + 2, start + 3, Some(start + 2)));
        }
        let source = match node.kind {
            "binding" | "assignment" => self
                .outside(start, head_end)
                .find(|i| self.text(*i) == "=")
                .map(|i| i + 1),
            "if" | "match" | "return" => Some(start + 1),
            "elseIf" => Some(start + 2),
            "for" => Some(start + 3),
            "expression" => Some(start),
            _ => None,
        };
        if let Some(a) = source {
            node.children.extend(self.expr(a, head_end, 0));
        }
        if node.kind == "assignment" {
            node.name = Some(self.text(start).into());
        }
        if node.kind == "function" && self.text(start + 2) == "(" {
            if let Some(close) = self.pairs[start + 2] {
                for (a, b) in self.parts(start + 3, close) {
                    let mut p = self.node("parameter", a, b, Some(a));
                    if a + 2 < b {
                        p.children.push(self.node("type", a + 2, b, Some(b - 1)));
                    }
                    node.children.push(p);
                }
                if self.text(close + 1) == "->" && close + 2 < head_end {
                    node.children.push(self.node(
                        "returnType",
                        close + 2,
                        head_end,
                        Some(head_end - 1),
                    ));
                }
            }
        }
        if node.kind == "table" {
            if let Some(arrow) = self
                .outside(start + 3, head_end)
                .find(|&i| self.text(i) == "->")
            {
                if start + 3 < arrow {
                    node.children
                        .push(self.node("keyType", start + 3, arrow, Some(arrow - 1)));
                }
                if let Some(eq) = self
                    .outside(arrow + 1, head_end)
                    .find(|&i| self.text(i) == "=")
                {
                    if arrow + 1 < eq {
                        node.children
                            .push(self.node("valueType", arrow + 1, eq, Some(eq - 1)));
                    }
                }
            }
            if let Some((first, last)) = body {
                for (a, b) in self.parts(first, last) {
                    let mut entry = self.node("entry", a, b, None);
                    if let Some(sep) = self.outside(a, b).find(|i| self.text(*i) == ":") {
                        entry.children.extend(self.expr(a, sep, 0));
                        entry.children.extend(self.expr(sep + 1, b, 0));
                    }
                    node.children.push(entry);
                }
            } else if let Some(i) = self
                .outside(start, head_end)
                .find(|i| self.text(*i) == "external")
            {
                node.children.extend(self.expr(i + 1, head_end, 0));
            }
        }
        if node.kind == "handler" && compact && start + 2 < end {
            let mut after = start + 2;
            while after < end && self.tokens[after - 1].end == self.tokens[after].start {
                after += 1;
            }
            node.selection_end = self.tokens[after - 1].end;
            node.name = Some(self.source[node.selection_start..node.selection_end].into());
            node.event = (after < end).then(|| self.text(after).into());
            if let Some(arrow) = self.outside(after, end).find(|i| self.text(*i) == "=>") {
                if after + 1 < arrow {
                    node.children
                        .push(self.node("predicate", after + 1, arrow, None));
                }
                if arrow + 1 < end {
                    node.children
                        .push(self.node("action", arrow + 1, end, Some(arrow + 1)));
                }
            }
        }
    }
}
