use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use goblin::Object;

#[allow(dead_code)]
pub fn read_text_section(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // ELFファイルをパース
    let object = Object::parse(&buffer)?;
    
    match object {
        Object::Elf(elf) => {
            // .textセクションを探す
            if let Some(text_section) = elf.section_headers.iter()
                .find(|section| {
                    elf.shdr_strtab.get_at(section.sh_name as usize)
                        .map_or(false, |name| name == ".text")
                }) {
                // textセクションのデータを読み込む
                let mut text_data = vec![0u8; text_section.sh_size as usize];
                file.seek(SeekFrom::Start(text_section.sh_offset))?;
                file.read_exact(&mut text_data)?;
                Ok(text_data)
            } else {
                Err("No .text section found".into())
            }
        }
        _ => Err("Not an ELF file".into())
    }
} 