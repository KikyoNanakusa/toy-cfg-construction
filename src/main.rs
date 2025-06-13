mod read_binary;

use capstone::{self, arch::{BuildsCapstone, BuildsCapstoneSyntax}, Insn};
use std::path::Path;

struct BasicBlock<'a> {
    start_address: u64, 
    end_address: u64,
    instructions: Vec<&'a Insn<'a>>,
}

fn main() {
    let cs = capstone::Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Falied to build capstone");

    let code = read_binary::read_text_section(Path::new("test")).expect("Failed to read text section");
    let insns = cs.disasm_all(&code, 0x1000)
        .expect("Failed to disassemble");

    let mut direct_labels = Vec::new(); // 即値アドレス (e.g, 0x1000)
    let mut indirect_labels = Vec::new(); // 間接アドレス (e.g, rax)

    analyze_instructions(&cs, &insns, &mut direct_labels, &mut indirect_labels);

    let mut basic_blocks: Vec<BasicBlock> = Vec::new();
    let labels: Vec<_> = direct_labels.iter().collect();  // 参照のコレクションを作成

    // ブロックの開始アドレスを設定
    for (_, op_str) in &labels {
        let addr = u64::from_str_radix(&op_str[2..], 16).unwrap();
        basic_blocks.push(BasicBlock {
            start_address: addr,
            end_address: 0,
            instructions: Vec::new(),
        });
    }

    // ブロックの終了アドレスを設定
    for i in 0..basic_blocks.len() - 1 {
        let (left, right) = basic_blocks.split_at_mut(i + 1);
        left[i].end_address = right[0].start_address;
    }

    // ブロックの命令列を設定
    for (_, op_str) in &labels {
        let addr = u64::from_str_radix(&op_str[2..], 16).unwrap();
        for block in &mut basic_blocks {
            if block.start_address <= addr && addr < block.end_address {
                for insn in insns.as_ref() {
                    if block.start_address <= insn.address() && insn.address() < block.end_address {
                        block.instructions.push(insn);
                    }
                }
                break;
            }
        }
    }

    for block in basic_blocks {
        print_basic_block(&block);
    }
}

fn print_basic_block(block: &BasicBlock) {
    println!("\nBasic Block: --------------------------------");
    println!("Start Address: 0x{:x}", block.start_address);
    println!("End Address: 0x{:x}", block.end_address);
    println!("Instructions: --------------------------------");
    for insn in &block.instructions {
        println!("0x{:x}: {} {}", insn.address(), insn.mnemonic().unwrap_or("unknown"), insn.op_str().unwrap_or("unknown"));
    }
}

fn analyze_instructions(cs: &capstone::Capstone, insns: &capstone::Instructions, direct_labels: &mut Vec<(String, String)>, indirect_labels: &mut Vec<(String, String)>) {
    for i in insns.as_ref() {
        let mnemonic = i.mnemonic().unwrap_or("unknown").to_string();
        let op_str = i.op_str().unwrap_or("unknown").to_string();
        // println!("0x{:x}: {} {}", address, mnemonic, op_str);

        let detail = cs.insn_detail(i).expect("Failed to get instruction detail");
        let group_names: Vec<_> = detail.groups().iter()
            .map(|&g| cs.group_name(g).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()))
            .collect();
        // println!("Groups: {:?}", group_names);

        if group_names.contains(&String::from("jump")) {
            if op_str.starts_with("0x") {
                direct_labels.push((mnemonic, op_str));
            } else {
                indirect_labels.push((mnemonic, op_str));
            }
        }
    }

    // 重複を排除
    direct_labels.sort_by(|a, b| a.1.cmp(&b.1));
    direct_labels.dedup();
    indirect_labels.sort_by(|a, b| a.1.cmp(&b.1));
    indirect_labels.dedup();

    println!("\nDirect Labels: --------------------------------\n");
    for (mnemonic, op_str) in direct_labels {
        println!("{} {}", mnemonic, op_str);
    }
    println!("\nIndirect Labels: --------------------------------\n");
    for (mnemonic, op_str) in indirect_labels {
        println!("{} {}", mnemonic, op_str);
    }
}
