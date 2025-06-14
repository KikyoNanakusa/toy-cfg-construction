use capstone::{Capstone, Insn};
use capstone::arch::x86::{X86Insn, X86OperandType};
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax, DetailsArchInsn};
use petgraph::graph::{Graph};
use petgraph::Directed;
use std::collections::{HashSet, HashMap};
use std::path::Path;

mod read_binary;

/// Basic block structure
struct BasicBlock<'a> {
    start: u64,
    end: u64,
    instructions: Vec<&'a Insn<'a>>,
}

fn is_conditional_jump(id: u32) -> bool {
    id == capstone::arch::x86::X86Insn::X86_INS_JE as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JNE as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JB as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JBE as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JA as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JAE as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JL as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JLE as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JG as u32 ||
    id == capstone::arch::x86::X86Insn::X86_INS_JGE as u32
}

fn is_unconditional_jump(id: u32) -> bool {
    id == X86Insn::X86_INS_JMP as u32
}

fn is_terminator(id: u32) -> bool {
    is_unconditional_jump(id)
        || is_conditional_jump(id)
        || id == X86Insn::X86_INS_RET as u32
}

/// Extract immediate target of a jump instruction
fn extract_imm(cs: &Capstone, insn: &Insn) -> Option<u64> {
    if let Some(detail) = cs.insn_detail(insn).ok() {
        if let capstone::arch::ArchDetail::X86Detail(d) = detail.arch_detail() {
            for op in d.operands() {
                if let X86OperandType::Imm(imm) = op.op_type {
                    return Some(imm as u64);
                }
            }
        }
    }
    None
}

fn main() {
    // Initialize Capstone
    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to build Capstone");

    // Read binary .text section (user implements read_text_section)
    let base_addr = 0x1000;
    let code = read_binary::read_text_section(Path::new("test")).expect("Failed to read text section");
    let insns = cs.disasm_all(&code, base_addr).expect("Failed to disassemble");

    // 1. Collect block start labels
    let mut labels = HashSet::new();
    labels.insert(base_addr);
    for insn in insns.as_ref() {
        let id = insn.id().0;
        if is_unconditional_jump(id) || is_conditional_jump(id) {
            if let Some(target) = extract_imm(&cs, insn) {
                labels.insert(target);
            }
            if is_conditional_jump(id) {
                // fall-through
                labels.insert(insn.address() + insn.bytes().len() as u64);
            }
        }
    }

    // Sort labels
    let mut starts: Vec<u64> = labels.into_iter().collect();
    starts.sort_unstable();

    // 2. Build basic blocks with adjacent ranges
    let mut blocks: Vec<BasicBlock> = starts
        .windows(2)
        .map(|w| BasicBlock { start: w[0], end: w[1], instructions: Vec::new() })
        .collect();
    // last block to end of section or last insn + size
    if let Some(last) = starts.last() {
        let end = insns.as_ref().last()
            .map(|i| i.address() + i.bytes().len() as u64)
            .unwrap_or(*last);
        blocks.push(BasicBlock { start: *last, end, instructions: Vec::new() });
    }

    // 3. Linear scan to fill instructions per block
    let mut iter = insns.as_ref().iter().peekable();
    for block in &mut blocks {
        while let Some(&insn) = iter.peek() {
            if insn.address() >= block.end {
                break;
            }
            block.instructions.push(insn);
            iter.next();
            if is_terminator(insn.id().0) {
                break;
            }
        }
    }

    // 4. Generate CFG edges
    let mut graph = Graph::<u64, (), Directed>::new();
    let mut idx_map = HashMap::new();
    for block in &blocks {
        let idx = graph.add_node(block.start);
        idx_map.insert(block.start, idx);
    }
    for block in &blocks {
        if let Some(term) = block.instructions.last() {
            let id = term.id().0;
            // Jump targets
            if is_unconditional_jump(id) {
                if let Some(tgt) = extract_imm(&cs, term) {
                    if let (Some(&s), Some(&d)) = (idx_map.get(&block.start), idx_map.get(&tgt)) {
                        graph.add_edge(s, d, ());
                    }
                }
            } else if is_conditional_jump(id) {
                if let Some(tgt) = extract_imm(&cs, term) {
                    let fall = term.address() + term.bytes().len() as u64;
                    if let Some(&s) = idx_map.get(&block.start) {
                        if let Some(&d1) = idx_map.get(&tgt) {
                            graph.add_edge(s, d1, ());
                        }
                        if let Some(&d2) = idx_map.get(&fall) {
                            graph.add_edge(s, d2, ());
                        }
                    }
                }
            }
        }
    }

    // Print blocks and edges in Mermaid
    println!("```mermaid");
    println!("graph TD");

    for block in &blocks {
        let node_id = format!("B{:x}", block.start);
        let label = block.instructions.iter()
            .map(|insn| {
                let m = insn.mnemonic().unwrap_or("").replace('"', "\\\"");
                let o = insn.op_str().unwrap_or("").replace('"', "\\\"");
                format!("{} {}", m, o)
            })
            .collect::<Vec<_>>()
            .join("<br>");
        println!("    {}[\"0x{:x}:<br>{}\"]", node_id, block.start, label);
    }

    for edge in graph.raw_edges() {
        let src_id = format!("B{:x}", graph[edge.source()]);
        let dst_id = format!("B{:x}", graph[edge.target()]);
        println!("    {} --> {}", src_id, dst_id);
    }

    println!("```");
}
