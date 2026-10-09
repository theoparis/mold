//! The DBI stream (stream 3): module list, section contributions, section
//! map, and the debug-header stream table. Follows LLVM's `DbiStreamBuilder`
//! and `DbiModuleDescriptorBuilder`.

/// Stream index that means no stream.
pub const NIL_STREAM: u16 = 0xffff;

/// `PdbDbiV70`, the DBI version lld writes.
const DBI_VERSION_V70: u32 = 19990903;
/// `DbiSecContribVer60`, the section contribution record version.
const SEC_CONTRIB_VER60: u32 = 0xeffe_0000 + 19970605;
/// Number of debug-header stream slots, one per `DbgHeaderType`.
const DBG_HEADER_COUNT: usize = 11;
/// The `DbgHeaderType::SectionHdr` slot.
const DBG_SECTION_HDR: usize = 5;
/// The `OMFSegDescFlags` bits the section map uses.
const SEG_READ: u16 = 1 << 0;
const SEG_WRITE: u16 = 1 << 1;
const SEG_EXECUTE: u16 = 1 << 2;
const SEG_ADDRESS_32BIT: u16 = 1 << 3;
const SEG_IS_SELECTOR: u16 = 1 << 8;
const SEG_IS_ABSOLUTE: u16 = 1 << 9;

/// The `IMAGE_SCN_*` characteristics the section map reads.
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_16BIT: u32 = 0x0002_0000;

/// Builds the DBI build number lld reports, `LINK 14.11`.
const BUILD_NUMBER: u16 = (14 << 8) | 11 | 0x8000;

/// A section contribution: a range of one section that a module provides.
#[derive(Clone, Copy, Default)]
pub struct SectionContrib {
    /// One-based index of the output section.
    pub section: u16,
    pub offset: u32,
    pub size: u32,
    pub characteristics: u32,
    /// Index of the module in the DBI module list.
    pub module: u16,
}

/// One object's entry in the module list.
pub struct Module {
    /// The module's name, usually the object file's path.
    pub name: String,
    pub obj_name: String,
    /// The module's symbol stream, or `NIL_STREAM` if it has none.
    pub stream: u16,
    /// Length of the symbol substream, including its signature.
    pub sym_bytes: u32,
    /// The module's first section contribution, if it has one.
    pub first_contrib: SectionContrib,
}

/// The fields of an output section that the section map records.
pub struct Section {
    pub characteristics: u32,
    pub virtual_size: u32,
}

/// Everything the DBI stream records about the image.
pub struct Dbi<'a> {
    pub age: u32,
    pub machine: u16,
    pub global_stream: u16,
    pub public_stream: u16,
    pub sym_record_stream: u16,
    pub modules: &'a [Module],
    pub contribs: &'a [SectionContrib],
    pub sections: &'a [Section],
    /// The serialized EC-names string table.
    pub ec_names: &'a [u8],
    /// The stream holding the COFF section headers.
    pub section_hdr_stream: u16,
}

fn module_record(m: &Module) -> Vec<u8> {
    let mut out = Vec::new();
    // Mod (unused), the first contribution, flags, the module's streams,
    // then the C11 and C13 line-table sizes, which are empty here.
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&contrib_record(&m.first_contrib));
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&m.stream.to_le_bytes());
    out.extend_from_slice(&m.sym_bytes.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // NumFiles, padding, FileNameOffs, SrcFileNameNI, PdbFilePathNI.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 2]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(m.name.as_bytes());
    out.push(0);
    out.extend_from_slice(m.obj_name.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// A `SectionContrib` record, 28 bytes.
fn contrib_record(c: &SectionContrib) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[0..2].copy_from_slice(&c.section.to_le_bytes());
    out[4..8].copy_from_slice(&c.offset.to_le_bytes());
    out[8..12].copy_from_slice(&c.size.to_le_bytes());
    out[12..16].copy_from_slice(&c.characteristics.to_le_bytes());
    out[16..18].copy_from_slice(&c.module.to_le_bytes());
    // The data and relocation CRCs are zero.
    out
}

fn section_map_flags(characteristics: u32) -> u16 {
    let mut flags = 0;
    if characteristics & SCN_MEM_READ != 0 {
        flags |= SEG_READ;
    }
    if characteristics & SCN_MEM_WRITE != 0 {
        flags |= SEG_WRITE;
    }
    if characteristics & SCN_MEM_EXECUTE != 0 {
        flags |= SEG_EXECUTE;
    }
    if characteristics & SCN_MEM_16BIT == 0 {
        flags |= SEG_ADDRESS_32BIT;
    }
    flags | SEG_IS_SELECTOR
}

/// Serializes the DBI stream.
pub fn dbi_stream(d: &Dbi) -> Vec<u8> {
    let modi: Vec<u8> = d.modules.iter().flat_map(module_record).collect();

    let mut contribs = Vec::new();
    if !d.contribs.is_empty() {
        contribs.extend_from_slice(&SEC_CONTRIB_VER60.to_le_bytes());
        for c in d.contribs {
            contribs.extend_from_slice(&contrib_record(c));
        }
    }

    // One entry per section, then one for absolute symbols.
    let mut sec_map = Vec::new();
    if !d.sections.is_empty() {
        let count = (d.sections.len() + 1) as u16;
        sec_map.extend_from_slice(&count.to_le_bytes());
        sec_map.extend_from_slice(&count.to_le_bytes());
        for (i, s) in d.sections.iter().enumerate() {
            push_sec_map_entry(
                &mut sec_map,
                section_map_flags(s.characteristics),
                (i + 1) as u16,
                s.virtual_size,
            );
        }
        let absolute = SEG_ADDRESS_32BIT | SEG_IS_ABSOLUTE;
        push_sec_map_entry(&mut sec_map, absolute, (d.sections.len() + 1) as u16, u32::MAX);
    }

    // The file info substream lists no source files: each module has zero.
    let mut file_info = Vec::new();
    file_info.extend_from_slice(&(d.modules.len() as u16).to_le_bytes());
    file_info.extend_from_slice(&0u16.to_le_bytes());
    for i in 0..d.modules.len() {
        file_info.extend_from_slice(&(i as u16).to_le_bytes());
    }
    for _ in 0..d.modules.len() {
        file_info.extend_from_slice(&0u16.to_le_bytes());
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(-1i32).to_le_bytes());
    out.extend_from_slice(&DBI_VERSION_V70.to_le_bytes());
    out.extend_from_slice(&d.age.to_le_bytes());
    out.extend_from_slice(&d.global_stream.to_le_bytes());
    out.extend_from_slice(&BUILD_NUMBER.to_le_bytes());
    out.extend_from_slice(&d.public_stream.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // PdbDllVersion
    out.extend_from_slice(&d.sym_record_stream.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // PdbDllRbld
    out.extend_from_slice(&(modi.len() as u32).to_le_bytes());
    out.extend_from_slice(&(contribs.len() as u32).to_le_bytes());
    out.extend_from_slice(&(sec_map.len() as u32).to_le_bytes());
    out.extend_from_slice(&(file_info.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // TypeServerSize
    out.extend_from_slice(&0u32.to_le_bytes()); // MFCTypeServerIndex
    out.extend_from_slice(&((DBG_HEADER_COUNT * 2) as u32).to_le_bytes());
    out.extend_from_slice(&(d.ec_names.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Flags
    out.extend_from_slice(&d.machine.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved

    out.extend_from_slice(&modi);
    out.extend_from_slice(&contribs);
    out.extend_from_slice(&sec_map);
    out.extend_from_slice(&file_info);
    out.extend_from_slice(d.ec_names);
    for slot in 0..DBG_HEADER_COUNT {
        let index = if slot == DBG_SECTION_HDR { d.section_hdr_stream } else { NIL_STREAM };
        out.extend_from_slice(&index.to_le_bytes());
    }
    out
}

fn push_sec_map_entry(out: &mut Vec<u8>, flags: u16, frame: u16, length: u32) {
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Ovl
    out.extend_from_slice(&0u16.to_le_bytes()); // Group
    out.extend_from_slice(&frame.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes()); // SecName
    out.extend_from_slice(&u16::MAX.to_le_bytes()); // ClassName
    out.extend_from_slice(&0u32.to_le_bytes()); // Offset
    out.extend_from_slice(&length.to_le_bytes());
}
