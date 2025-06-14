mod read_binary;

use capstone::{self, arch::{BuildsCapstone, BuildsCapstoneSyntax}, Insn};
use std::path::Path;

struct BasicBlock<'a> {
    start_address: u64, 
    end_address: u64,
    instructions: Vec<&'a Insn<'a>>,
}


fn is_unconditional_jump(id: u32) -> bool {
    id == capstone::arch::x86::X86Insn::X86_INS_JMP as u32
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

fn is_terminator(id: u32) -> bool {
    if is_unconditional_jump(id) {
        return true;
    }

    if is_conditional_jump(id) {
        return true;
    }

    id == capstone::arch::x86::X86Insn::X86_INS_RET as u32
}

fn main() {
    let cs = capstone::Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Falied to build capstone");

    let base_addr = 0x1000;
    let code = read_binary::read_text_section(Path::new("test")).expect("Failed to read text section");
    let insns = cs.disasm_all(&code, base_addr)
        .expect("Failed to disassemble");

    let mut direct_labels = Vec::new(); // 即値アドレス (e.g, 0x1000)
    let mut indirect_labels = Vec::new(); // 間接アドレス (e.g, rax)

    analyze_instructions(&cs, &insns, &mut direct_labels, &mut indirect_labels);

    let mut basic_blocks: Vec<BasicBlock> = Vec::new();
    let labels: Vec<_> = direct_labels.iter().collect();  // 参照のコレクションを作成

    // base addrをブロックとして追加 
    basic_blocks.push(BasicBlock {
        start_address: base_addr,
        end_address: 0,
        instructions: Vec::new(),
    });

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
                        if is_terminator(insn.id().0) {
                            block.end_address = insn.address();
                            break;
                        }
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

fn analyze_instructions(
    cs: &capstone::Capstone,
    insns: &capstone::Instructions,
    direct_labels: &mut Vec<(String, String)>,
    indirect_labels: &mut Vec<(String, String)>,
) {
    for insn in insns.as_ref() {
        let mnemonic = insn.mnemonic().unwrap_or("unknown").to_string();
        let op_str   = insn.op_str().unwrap_or("unknown").to_string();

        // 命令詳細とグループ名の取得
        let detail = cs.insn_detail(insn).expect("Failed to get instruction detail");
        let groups: Vec<_> = detail
            .groups()
            .iter()
            .filter_map(|&g| cs.group_name(g))
            .map(|s| s.to_string())
            .collect();

        // “jump” グループに属していればラベル扱い
        if groups.contains(&"jump".to_string()) {
            if op_str.starts_with("0x") {
                // 1) 即値アドレスへのジャンプ先
                direct_labels.push((mnemonic.clone(), op_str.clone()));

                // 2) 条件ジャンプの場合は「フォールスルー先」も追加
                //    無条件ジャンプ (jmp) は除外
                if mnemonic != "jmp" && mnemonic.starts_with('j') {
                    let fall_addr = insn.address() + insn.bytes().len() as u64;
                    let fall_str  = format!("0x{:x}", fall_addr);
                    direct_labels.push(("fall".into(), fall_str));
                }
            } else {
                // 間接ジャンプ
                indirect_labels.push((mnemonic.clone(), op_str.clone()));
            }
        }
    }

    // 重複排除
    direct_labels.sort_by(|a, b| a.1.cmp(&b.1));
    direct_labels.dedup();
    indirect_labels.sort_by(|a, b| a.1.cmp(&b.1));
    indirect_labels.dedup();

    // 確認出力
    println!("\nDirect Labels: --------------------------------\n");
    for (m, o) in direct_labels {
        println!("{} {}", m, o);
    }
    println!("\nIndirect Labels: --------------------------------\n");
    for (m, o) in indirect_labels {
        println!("{} {}", m, o);
    }
}
