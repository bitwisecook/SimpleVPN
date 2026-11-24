// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//! Configuration-time SSA construction for the forward-only numeric language.
//! Stack slots and locals become immutable values. Executable predecessor edges
//! supply phi arguments at joins. No code generation permission is necessary.

use super::*;
use std::{cell::RefCell, collections::HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Value {
    Constant(i64),
    Register(usize),
}
impl Value {
    fn get(self, regs: &[i64]) -> i64 {
        match self {
            Self::Constant(v) => v,
            Self::Register(r) => regs[r],
        }
    }
}
#[derive(Clone)]
struct Environment {
    stack: Vec<Value>,
    locals: [Option<Value>; LOCALS],
}
impl Default for Environment {
    fn default() -> Self {
        Self {
            stack: Vec::new(),
            locals: [None; LOCALS],
        }
    }
}

enum Instruction {
    Read(Field, usize),
    Write(Field, Value),
    Binary(Binary, Value, Value, usize),
    Fault,
}
struct At {
    pc: usize,
    instruction: Instruction,
}
struct Edge {
    target: usize,
    moves: Vec<(usize, Value)>,
}
enum End {
    Exit,
    Drop,
    Jump(usize),
    Branch(Value, usize, usize),
}
struct Block {
    start: usize,
    length: usize,
    instructions: Vec<At>,
    end: End,
}
pub(super) struct Graph {
    blocks: Vec<Block>,
    edges: Vec<Edge>,
    register_count: usize,
}
#[derive(Clone)]
struct Input {
    edge: usize,
    env: Environment,
    parent: usize,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key(Binary, Value, Value);

struct Builder {
    graph: Graph,
    // Edges are forward-only, so all executable predecessors have been compiled
    // when a block is visited. Conditional constant propagation excludes the
    // other edge before joining environments.
    inputs: Vec<Vec<Input>>,
    block_at: Vec<usize>,
    immediate_dominator: Vec<usize>,
    definitions: Vec<Vec<Value>>,
    roots: Vec<Value>,
    values: HashMap<Key, (usize, Value)>,
}

impl Graph {
    pub(super) fn compile(code: &[Op]) -> Option<Self> {
        let mut starts = vec![0, code.len()];
        for (pc, op) in code.iter().enumerate() {
            match op {
                Op::Jump(to) | Op::BranchFalse(to) | Op::AndThen(to) | Op::OrElse(to) => {
                    starts.extend([pc + 1, *to]);
                }
                Op::Drop => starts.push(pc + 1),
                _ => {}
            }
        }
        starts.sort_unstable();
        starts.dedup();
        let mut block_at = vec![0; code.len() + 1];
        for (i, &pc) in starts.iter().enumerate() {
            block_at[pc] = i;
        }
        let mut b = Builder {
            graph: Graph {
                blocks: Vec::new(),
                edges: Vec::new(),
                register_count: 0,
            },
            inputs: vec![Vec::new(); starts.len()],
            block_at,
            immediate_dominator: vec![0; starts.len()],
            definitions: Vec::new(),
            roots: Vec::new(),
            values: HashMap::new(),
        };
        for (id, &start) in starts.iter().enumerate() {
            let end = starts.get(id + 1).copied().unwrap_or(start);
            let mut block = Block {
                start,
                length: end - start,
                instructions: Vec::new(),
                end: End::Exit,
            };
            let inputs = std::mem::take(&mut b.inputs[id]);
            if id == 0 || !inputs.is_empty() {
                let mut env = b.merge(id, &inputs)?;
                for (i, &op) in code[start..end].iter().enumerate() {
                    let pc = start + i;
                    let end = b.lower(id, pc, op, &mut env, &mut block.instructions)?;
                    if let Some(end) = end {
                        block.end = end;
                        break;
                    }
                }
                if matches!(block.end, End::Exit) && start < code.len() {
                    block.end = End::Jump(b.edge(id, end, env));
                }
            }
            b.graph.blocks.push(block);
        }
        b.eliminate_dead_values();
        b.graph.register_count = b.definitions.len();
        Some(b.graph)
    }

    pub(super) fn eval(&self, frame: &mut RCFrame) -> RCResult {
        if self.register_count <= 32 {
            return self.run(frame, &mut [0; 32]);
        }
        thread_local! {static REGISTERS:RefCell<Vec<i64>>=const {RefCell::new(Vec::new())};}
        REGISTERS.with_borrow_mut(|regs| {
            regs.resize(self.register_count, 0);
            self.run(frame, regs)
        })
    }
    fn run(&self, frame: &mut RCFrame, regs: &mut [i64]) -> RCResult {
        let (mut id, mut count) = (0, 0u32);
        loop {
            let block = &self.blocks[id];
            for op in &block.instructions {
                let fail = |status| result(status, op.pc, count + (op.pc - block.start + 1) as u32);
                match op.instruction {
                    Instruction::Read(f, r) => match f.read(frame) {
                        Some(v) => regs[r] = v,
                        None => return fail(MISSING),
                    },
                    Instruction::Write(f, v) => {
                        if f.write(frame, v.get(regs)).is_none() {
                            return fail(BAD_WRITE);
                        }
                    }
                    Instruction::Binary(operator, a, b, r) => {
                        match operator.apply(a.get(regs), b.get(regs)) {
                            Some(v) => regs[r] = v,
                            None => return fail(BOUNDS),
                        }
                    }
                    Instruction::Fault => return fail(BOUNDS),
                }
            }
            count += block.length as u32;
            let edge = match block.end {
                End::Exit => return result(OK, block.start, count),
                End::Drop => return result(DROPPED, block.start + block.length - 1, count),
                End::Jump(e) => e,
                End::Branch(v, yes, no) => {
                    if v.get(regs) != 0 {
                        yes
                    } else {
                        no
                    }
                }
            };
            let edge = &self.edges[edge];
            // Phi registers are fresh and the graph is acyclic. No source of
            // this parallel copy can be a destination on the same edge.
            for &(r, v) in &edge.moves {
                regs[r] = v.get(regs);
            }
            id = edge.target;
        }
    }
}

impl Builder {
    fn register(&mut self, inputs: Vec<Value>) -> Option<usize> {
        let r = self.definitions.len();
        // Bound configuration work even for very large joins.
        if r >= 32768 {
            return None;
        }
        self.definitions.push(inputs);
        Some(r)
    }
    fn edge(&mut self, from: usize, to: usize, env: Environment) -> usize {
        let target = self.block_at[to];
        let id = self.graph.edges.len();
        self.graph.edges.push(Edge {
            target,
            moves: Vec::new(),
        });
        self.inputs[target].push(Input {
            edge: id,
            env,
            parent: from,
        });
        id
    }
    fn meet(&self, mut a: usize, mut b: usize) -> usize {
        while a != b {
            if a > b {
                a = self.immediate_dominator[a]
            } else {
                b = self.immediate_dominator[b]
            }
        }
        a
    }
    fn phi(
        &mut self,
        inputs: &[Input],
        get: impl Fn(&Environment) -> Option<Value>,
    ) -> Option<Option<Value>> {
        let first = get(&inputs[0].env);
        if inputs.iter().skip(1).all(|i| get(&i.env) == first) {
            return Some(first);
        }
        let Some(args) = inputs
            .iter()
            .map(|i| get(&i.env))
            .collect::<Option<Vec<_>>>()
        else {
            return Some(None);
        };
        let r = self.register(args)?;
        for i in inputs {
            self.graph.edges[i.edge].moves.push((r, get(&i.env)?));
        }
        Some(Some(Value::Register(r)))
    }
    fn merge(&mut self, id: usize, inputs: &[Input]) -> Option<Environment> {
        let Some(first) = inputs.first() else {
            return Some(Environment::default());
        };
        self.immediate_dominator[id] = inputs
            .iter()
            .skip(1)
            .fold(first.parent, |dom, i| self.meet(dom, i.parent));
        let mut env = first.env.clone();
        if inputs.len() > 1 {
            for (i, value) in env.stack.iter_mut().enumerate() {
                *value = self.phi(inputs, |e| e.stack.get(i).copied())??;
            }
            for (i, value) in env.locals.iter_mut().enumerate() {
                *value = self.phi(inputs, |e| e.locals[i])?;
            }
        }
        Some(env)
    }
    fn binary(
        &mut self,
        id: usize,
        pc: usize,
        op: Binary,
        a: Value,
        b: Value,
        out: &mut Vec<At>,
    ) -> Option<Value> {
        use Value::*;
        if let (Constant(x), Constant(y)) = (a, b) {
            return match op.apply(x, y) {
                Some(v) => Some(Constant(v)),
                None => {
                    out.push(At {
                        pc,
                        instruction: Instruction::Fault,
                    });
                    Some(Constant(0))
                }
            };
        }
        let key = Key(op, a, b);
        if let Some(&(def, v)) = self.values.get(&key) {
            if self.meet(id, def) == def {
                return Some(v);
            }
        }
        let r = self.register(vec![a, b])?;
        let value = Register(r);
        self.values.insert(key, (id, value));
        out.push(At {
            pc,
            instruction: Instruction::Binary(op, a, b, r),
        });
        // Arithmetic can trap even when its result is unused.
        if op.can_fault() {
            self.roots.push(value);
        }
        Some(value)
    }
    fn lower(
        &mut self,
        id: usize,
        pc: usize,
        op: Op,
        env: &mut Environment,
        out: &mut Vec<At>,
    ) -> Option<Option<End>> {
        use Value::*;
        match op {
            Op::Const(v, _) => env.stack.push(Constant(v)),
            Op::Read(f) => {
                let r = self.register(Vec::new())?;
                out.push(At {
                    pc,
                    instruction: Instruction::Read(f, r),
                });
                env.stack.push(Register(r));
            }
            Op::Write(f) => {
                let v = env.stack.pop()?;
                self.roots.push(v);
                out.push(At {
                    pc,
                    instruction: Instruction::Write(f, v),
                });
            }
            Op::Load(i) => env.stack.push(env.locals[i as usize]?),
            Op::Store(i) => env.locals[i as usize] = Some(env.stack.pop()?),
            Op::Binary(op) => {
                let b = env.stack.pop()?;
                let a = env.stack.pop()?;
                env.stack.push(self.binary(id, pc, op, a, b, out)?);
            }
            Op::Not | Op::Neg => {
                let v = env.stack.pop()?;
                let op = if matches!(op, Op::Not) {
                    Binary::Eq
                } else {
                    Binary::Sub
                };
                env.stack
                    .push(self.binary(id, pc, op, Constant(0), v, out)?);
            }
            Op::Discard => {
                env.stack.pop()?;
            }
            Op::Count => {}
            Op::Drop => return Some(Some(End::Drop)),
            Op::Jump(to) => return Some(Some(End::Jump(self.edge(id, to, env.clone())))),
            Op::BranchFalse(to) | Op::AndThen(to) | Op::OrElse(to) => {
                let v = *env.stack.last()?;
                if matches!(op, Op::BranchFalse(_)) {
                    env.stack.pop()?;
                }
                let taken = env.clone();
                if !matches!(op, Op::BranchFalse(_)) {
                    env.stack.pop()?;
                }
                let jump_on_true = matches!(op, Op::OrElse(_));
                let term = if let Constant(x) = v {
                    let edge = if (x != 0) == jump_on_true {
                        self.edge(id, to, taken)
                    } else {
                        self.edge(id, pc + 1, env.clone())
                    };
                    End::Jump(edge)
                } else {
                    let fall = self.edge(id, pc + 1, env.clone());
                    let jump = self.edge(id, to, taken);
                    self.roots.push(v);
                    if jump_on_true {
                        End::Branch(v, jump, fall)
                    } else {
                        End::Branch(v, fall, jump)
                    }
                };
                return Some(Some(term));
            }
        }
        Some(None)
    }
    fn eliminate_dead_values(&mut self) {
        let mut live = vec![false; self.definitions.len()];
        while let Some(v) = self.roots.pop() {
            if let Value::Register(r) = v {
                if !live[r] {
                    live[r] = true;
                    self.roots.extend(&self.definitions[r]);
                }
            }
        }
        for block in &mut self.graph.blocks {
            block.instructions.retain(|i| match i.instruction {
                Instruction::Binary(_, _, _, r) => live[r],
                _ => true,
            });
        }
        for edge in &mut self.graph.edges {
            edge.moves.retain(|(r, _)| live[*r]);
        }
    }
}
