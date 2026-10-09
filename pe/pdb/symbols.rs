//! CodeView symbol records that the PDB's modules hold, and the linker's own
//! module, which describes the image. Follows the record layouts of LLVM's
//! `SymbolRecordMapping` and the records that lld writes for its linker module.

use super::dbi::{Section, SectionContrib};

const S_OBJNAME: u16 = 0x1101;
const S_COMPILE3: u16 = 0x113c;
const S_ENVBLOCK: u16 = 0x113d;
const S_SECTION: u16 = 0x1136;
const S_COFFGROUP: u16 = 0x1137;

/// `CV_CFL_X64`, the machine that `S_COMPILE3` records.
const CPU_X64: u16 = 0xd0;
/// `CV_CFL_LINK`, the source language of the linker module.
const LANGUAGE_LINK: u32 = 0x07;
/// The section alignment that lld records for every section: 2^12, 4 KiB.
const SECTION_ALIGNMENT: u8 = 12;
/// The characteristics of `.idata` groups, which lld always marks writable.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// A COFF group: a range of one output section that holds an input section's
/// chunks, which the linker module describes.
pub struct CoffGroup {
    /// One-based index of the output section.
    pub section: u16,
    pub name: Vec<u8>,
    pub characteristics: u32,
    /// Offset of the group within its section.
    pub offset: u32,
    pub size: u32,
}

/// The environment that the linker module records: the working directory, the
/// program, and the command line it was run with.
#[derive(Clone, Default)]
pub struct Env {
    pub cwd: String,
    pub exe: String,
    pub command_line: String,
    /// The absolute path of the PDB file.
    pub pdb: String,
}

/// Frames a symbol record: a length, its kind, and the body padded to four
/// bytes. The length counts everything after itself.
fn record(kind: u16, body: &[u8]) -> Vec<u8> {
    let total = (4 + body.len()).next_multiple_of(4);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&((total - 2) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(body);
    out.resize(total, 0);
    out
}

fn push_name(out: &mut Vec<u8>, name: &[u8]) {
    out.extend_from_slice(name);
    out.push(0);
}

/// `S_OBJNAME`: a signature, then the name of the object.
fn obj_name(name: &str) -> Vec<u8> {
    let mut body = 0u32.to_le_bytes().to_vec();
    push_name(&mut body, name.as_bytes());
    record(S_OBJNAME, &body)
}

/// `S_COMPILE3`: the linker's language and machine, and the version that lld
/// reports for its backend. lld names itself "LLVM Linker" with a zero frontend.
fn compile3() -> Vec<u8> {
    let mut body = LANGUAGE_LINK.to_le_bytes().to_vec();
    body.extend_from_slice(&CPU_X64.to_le_bytes());
    body.resize(body.len() + 8, 0); // The frontend version: 0.0.0.0.
    for v in [14u16, 10, 25019, 0] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    push_name(&mut body, b"LLVM Linker");
    record(S_COMPILE3, &body)
}

/// `S_ENVBLOCK`: a reserved byte, then key and value strings, ended by an
/// empty string.
fn env_block(fields: &[&str]) -> Vec<u8> {
    let mut body = vec![0u8];
    for f in fields {
        push_name(&mut body, f.as_bytes());
    }
    body.push(0);
    record(S_ENVBLOCK, &body)
}

/// `S_SECTION`: an output section, with its number, address and size.
fn section(number: u16, s: &Section) -> Vec<u8> {
    let mut body = number.to_le_bytes().to_vec();
    body.push(SECTION_ALIGNMENT);
    body.push(0);
    body.extend_from_slice(&s.rva.to_le_bytes());
    body.extend_from_slice(&s.virtual_size.to_le_bytes());
    body.extend_from_slice(&s.characteristics.to_le_bytes());
    push_name(&mut body, &s.name);
    record(S_SECTION, &body)
}

/// `S_COFFGROUP`: a group of input sections within an output section.
fn coff_group(g: &CoffGroup) -> Vec<u8> {
    let mut characteristics = g.characteristics;
    // lld marks .idata groups writable, though their section headers are not.
    if g.name.starts_with(b".idata") {
        characteristics |= IMAGE_SCN_MEM_WRITE;
    }
    let mut body = g.size.to_le_bytes().to_vec();
    body.extend_from_slice(&characteristics.to_le_bytes());
    body.extend_from_slice(&g.offset.to_le_bytes());
    body.extend_from_slice(&g.section.to_le_bytes());
    push_name(&mut body, &g.name);
    record(S_COFFGROUP, &body)
}

/// The symbol records of the linker module, in lld's order: the object name,
/// the compiler, and the environment, then each output section followed by its
/// COFF groups.
pub fn linker_symbols(sections: &[Section], groups: &[CoffGroup], env: &Env) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(obj_name("* Linker *"));
    out.extend(compile3());
    out.extend(env_block(&[
        "cwd",
        &env.cwd,
        "exe",
        &env.exe,
        "pdb",
        &env.pdb,
        "cmd",
        &env.command_line,
    ]));
    for (i, s) in sections.iter().enumerate() {
        let number = (i + 1) as u16;
        out.extend(section(number, s));
        for g in groups.iter().filter(|g| g.section == number) {
            out.extend(coff_group(g));
        }
    }
    out
}

/// The first section contribution of the linker module. It describes no
/// section, as lld's does.
pub fn linker_contrib() -> SectionContrib {
    SectionContrib {
        section: u16::MAX,
        offset: 0,
        size: u32::MAX,
        characteristics: 0,
        module: u16::MAX,
    }
}
