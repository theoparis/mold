//! Lays out the live chunks in output sections, applies the relocations of the
//! target architecture, builds the base relocation table and writes the PE
//! headers. The image is built in memory and returned as bytes.

use std::collections::HashMap;
use std::rc::Rc;

use mold_common::fatal;
use mold_common::util::align_to;

use crate::arch::x86_64::X86_64;
use crate::arch::{Arch, Fixup, RelocError, Target};
use crate::coff::{self, SCN_CNT_CODE, SCN_CNT_INITIALIZED_DATA, SCN_CNT_UNINITIALIZED_DATA};
use crate::import::ImportMember;
use crate::link::{Linker, Loc};
use crate::pdb::gsi;
use crate::pdb::{self, dbi::SectionContrib};

/// The image base that lld uses for executables, so that 32-bit absolute
/// addresses (`IMAGE_REL_AMD64_ADDR32`) come out as lld writes them.
pub const DEFAULT_IMAGE_BASE: u64 = 0x1_4000_0000;

const SECTION_ALIGN: u64 = 0x1000;
const FILE_ALIGN: u64 = 0x200;

/// The file offset of the PE signature. Like lld, we leave room for a DOS stub.
const PE_OFFSET: usize = 0x78;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_SIZE: usize = 240;
const SECTION_HEADER_SIZE: usize = 40;
const NUM_DATA_DIRECTORIES: usize = 16;
const BASE_RELOC_DIRECTORY: usize = 5;
const IMPORT_DIRECTORY: usize = 1;
const IAT_DIRECTORY: usize = 12;
const DEBUG_DIRECTORY: usize = 6;
/// The size of an IMAGE_DEBUG_DIRECTORY entry.
const DEBUG_DIRECTORY_SIZE: usize = 28;
/// The fixed part of a CodeView RSDS record: signature, GUID and age.
const CODEVIEW_HEADER_SIZE: usize = 24;
/// The debug directory type for a CodeView record.
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

/// Where the CodeView record of the PDB goes in the image. Its contents depend
/// on the PDB, which depends on the layout, so they are written afterward.
pub(crate) struct DebugRecord {
    pub file_off: usize,
    pub len: usize,
}

const RELOC_SECTION_CHARS: u32 = 0x4200_0040;

/// Output sections that lld creates before any others, in its order.
const BUILTIN_SECTIONS: &[&[u8]] = &[
    b".text",
    b".rdata",
    b".buildid",
    b".cvinfo",
    b".data",
    b".pdata",
    b".idata",
    b".edata",
    b".didat",
    b".rsrc",
    b".reloc",
    b".ctors",
    b".dtors",
];

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

const OUTPUT_CHAR_MASK: u32 = SCN_CNT_CODE
    | SCN_CNT_INITIALIZED_DATA
    | SCN_CNT_UNINITIALIZED_DATA
    | coff::SCN_MEM_READ
    | coff::SCN_MEM_WRITE
    | coff::SCN_MEM_EXECUTE;

/// A member of an output section: a chunk, with the keys that order it.
struct Member {
    uninit: bool,
    /// The rank of the chunk's partial section: the chunks that share a full
    /// input section name and characteristics. lld orders partial sections
    /// by that key.
    partial: u32,
    /// The position of the chunk in lld's order: by object completion, then section.
    seq: u32,
    chunk: u32,
}

/// An output section: the chunks that share a name, laid out in order.
struct OutSection {
    name: Vec<u8>,
    chars: u32,
    members: Vec<Member>,
    init_size: u64,
    virt_size: u64,
    rva: u64,
    raw_off: u64,
    raw_size: u64,
}

/// Lays out the live chunks of `ln` and returns the image, for the machine
/// type of the input objects.
pub(crate) fn build(
    ln: &mut Linker<'_>,
    entry: u32,
    pdb_path: Option<&str>,
) -> (Vec<u8>, pdb::Input, Option<DebugRecord>) {
    match ln.machine {
        Some(machine) if machine == X86_64::MACHINE => build_for::<X86_64>(ln, entry, pdb_path),
        Some(machine) => fatal!("unsupported machine type 0x{machine:04x}"),
        None => fatal!("no input object files"),
    }
}

/// Lays out the live chunks of `ln` and returns the image for architecture `A`.
fn build_for<A: Arch>(
    ln: &mut Linker<'_>,
    entry: u32,
    pdb_path: Option<&str>,
) -> (Vec<u8>, pdb::Input, Option<DebugRecord>) {
    let image_base = ln.opts.image_base.unwrap_or(DEFAULT_IMAGE_BASE);

    let mut outs = group_chunks(ln);
    sort_outs(&mut outs);
    for out in &mut outs {
        // Initialized chunks come first. Uninitialized ones, which are
        // merged into the same output section, follow them.
        out.members.sort_by_key(|m| (m.uninit, m.partial, m.seq));
        let mut cursor = 0u64;
        let mut init_size = 0u64;
        for m in &out.members {
            let ch = &mut ln.chunks[m.chunk as usize];
            cursor = align_to(cursor, ch.align as u64);
            ch.offset = cursor as u32;
            cursor += ch.size as u64;
            if !m.uninit {
                init_size = cursor;
            }
        }
        out.init_size = init_size;
        out.virt_size = cursor;
    }

    // lld puts the import tables at the end of .rdata, ahead of the debug directory.
    let import_at = (!ln.import_slots.is_empty()).then(|| {
        let len = import_tables(&ln.import_slots, 0).bytes.len() as u64;
        let idx = match outs.iter().position(|o| o.name == b".rdata") {
            Some(i) => i,
            None => {
                outs.push(OutSection {
                    name: b".rdata".to_vec(),
                    chars: SCN_CNT_INITIALIZED_DATA | coff::SCN_MEM_READ,
                    members: Vec::new(),
                    init_size: 0,
                    virt_size: 0,
                    rva: 0,
                    raw_off: 0,
                    raw_size: 0,
                });
                outs.len() - 1
            }
        };
        let out = &mut outs[idx];
        let at = align_to(out.virt_size, 8);
        out.virt_size = at + len;
        out.init_size = out.virt_size;
        (idx, at)
    });
    // lld keeps the debug directory and its CodeView record at the end of
    // .rdata, so they take part in its layout. The record is as long as the
    // path, which is known before the PDB is written.
    let debug_at = pdb_path.map(|p| {
        let rec_len = CODEVIEW_HEADER_SIZE + p.len() + 1;
        let idx = match outs.iter().position(|o| o.name == b".rdata") {
            Some(i) => i,
            None => {
                outs.push(OutSection {
                    name: b".rdata".to_vec(),
                    chars: SCN_CNT_INITIALIZED_DATA | coff::SCN_MEM_READ,
                    members: Vec::new(),
                    init_size: 0,
                    virt_size: 0,
                    rva: 0,
                    raw_off: 0,
                    raw_size: 0,
                });
                outs.len() - 1
            }
        };
        let out = &mut outs[idx];
        let at = align_to(out.virt_size, 4);
        out.virt_size = at + (DEBUG_DIRECTORY_SIZE + rec_len) as u64;
        out.init_size = out.virt_size;
        (idx, at, rec_len)
    });

    let ln_ref: &Linker<'_> = ln;
    let have_relocs = outs
        .iter()
        .flat_map(|o| o.members.iter())
        .any(|m| has_address_relocs::<A>(ln_ref, m.chunk as usize));
    let emitted = outs.iter().filter(|o| o.virt_size > 0).count();
    let nsec = emitted + usize::from(have_relocs);
    let headers_size = align_to(
        (PE_OFFSET + 4 + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE + SECTION_HEADER_SIZE * nsec)
            as u64,
        FILE_ALIGN,
    );

    let mut rva = align_to(headers_size, SECTION_ALIGN);
    let mut file = headers_size;
    for out in &mut outs {
        out.rva = rva;
        if out.init_size > 0 {
            out.raw_size = align_to(out.init_size, FILE_ALIGN);
            out.raw_off = file;
            file += out.raw_size;
        }
        rva += align_to(out.virt_size, SECTION_ALIGN);
    }

    // The debug directory and its record, as places in the file.
    let debug_slot = debug_at.map(|(idx, at, rec_len)| {
        let out = &outs[idx];
        (out.rva + at, (out.raw_off + at) as usize, rec_len)
    });
    // The import tables, now that their place in the file is known.
    let imports = import_at.map(|(idx, at)| import_tables(&ln.import_slots, outs[idx].rva + at));
    let import_file = import_at.map(|(idx, at)| (outs[idx].raw_off + at) as usize);
    let import_rva: Vec<u64> = imports.as_ref().map_or_else(Vec::new, |t| t.slot_rva.clone());
    // The RVA and file offset of every chunk that the image keeps.
    let mut chunk_rva = vec![0u64; ln.chunks.len()];
    let mut chunk_file = vec![0u64; ln.chunks.len()];
    for out in &outs {
        for m in &out.members {
            let offset = ln.chunks[m.chunk as usize].offset as u64;
            chunk_rva[m.chunk as usize] = out.rva + offset;
            chunk_file[m.chunk as usize] = out.raw_off + offset;
        }
    }

    let mut image = vec![0u8; file as usize];
    if let (Some(t), Some(at)) = (&imports, import_file) {
        put(&mut image, at, &t.bytes);
    }
    // Like lld, pad code with int3, so that the gaps between functions hold it.
    for out in outs.iter().filter(|o| o.chars & SCN_CNT_CODE != 0) {
        let at = out.raw_off as usize;
        image[at..at + out.raw_size as usize].fill(0xcc);
    }
    for out in &outs {
        for m in &out.members {
            if m.uninit {
                continue;
            }
            let ch = &ln.chunks[m.chunk as usize];
            let obj = Rc::clone(&ln.objs[ch.obj as usize]);
            let data = obj.sections[ch.sec as usize].data;
            let at = chunk_file[m.chunk as usize] as usize;
            image[at..at + data.len()].copy_from_slice(data);
        }
    }

    let mut sites = Vec::new();
    for c in 0..ln.chunks.len() {
        if ln.chunks[c].live {
            apply_relocs::<A>(
                ln,
                c,
                image_base,
                &import_rva,
                &chunk_rva,
                &chunk_file,
                &mut image,
                &mut sites,
            );
        }
    }

    // The base relocation table goes last, after every other section.
    let reloc_table = base_relocs(&mut sites);
    let mut reloc_dir = (0u64, 0u64);
    if !reloc_table.is_empty() {
        let len = reloc_table.len() as u64;
        let raw_size = align_to(len, FILE_ALIGN);
        image.resize((file + raw_size) as usize, 0);
        image[file as usize..(file + len) as usize].copy_from_slice(&reloc_table);
        outs.push(OutSection {
            name: b".reloc".to_vec(),
            chars: RELOC_SECTION_CHARS,
            members: Vec::new(),
            init_size: len,
            virt_size: len,
            rva,
            raw_off: file,
            raw_size,
        });
        reloc_dir = (rva, len);
        rva += align_to(len, SECTION_ALIGN);
    }

    let entry_rva = match ln.resolve(entry) {
        Some(Loc::Chunk { chunk, value }) => chunk_rva[chunk as usize] + value as u64,
        _ => fatal!(
            "entry symbol {} is not defined in a section that is linked",
            String::from_utf8_lossy(ln.globals[entry as usize].name)
        ),
    };

    let code_size: u64 =
        outs.iter().filter(|o| o.chars & SCN_CNT_CODE != 0).map(|o| o.raw_size).sum();
    let init_size: u64 = outs
        .iter()
        .filter(|o| o.chars & SCN_CNT_CODE == 0 && o.chars & SCN_CNT_INITIALIZED_DATA != 0)
        .map(|o| o.raw_size)
        .sum();
    let uninit_size: u64 = outs.iter().map(|o| o.virt_size.saturating_sub(o.raw_size)).sum();
    let base_of_code = outs.iter().find(|o| o.chars & SCN_CNT_CODE != 0).map_or(0, |o| o.rva);

    let headers = Headers {
        image_base,
        machine: A::MACHINE,
        entry_rva,
        subsystem: ln.opts.subsystem,
        nxcompat: ln.opts.nxcompat,
        relocatable: !reloc_table.is_empty(),
        code_size,
        init_size,
        uninit_size,
        base_of_code,
        size_of_image: align_to(rva, SECTION_ALIGN),
        size_of_headers: headers_size,
        reloc_dir,
        debug_dir: debug_slot.map_or((0, 0), |(rva, _, _)| (rva, DEBUG_DIRECTORY_SIZE as u64)),
        import_dir: imports.as_ref().map_or((0, 0), |t| (t.dir_rva, t.dir_size)),
        iat_dir: imports.as_ref().map_or((0, 0), |t| (t.iat_rva, t.iat_size)),
    };
    let sections: Vec<&OutSection> = outs.iter().filter(|o| o.virt_size > 0).collect();
    let debug_record = debug_slot.map(|(rva, off, len)| {
        write_debug_directory(&mut image, off, rva, len);
        DebugRecord { file_off: off + DEBUG_DIRECTORY_SIZE, len }
    });
    write_headers(&mut image, &headers, &sections);
    let pdb = pdb_input::<A>(ln, &sections, &image, pdb_path);
    (image, pdb, debug_record)
}

/// Describes the linked image for its PDB: the modules that contributed
/// chunks, the chunks as section contributions, and the section table.
fn pdb_input<A: Arch>(
    ln: &Linker<'_>,
    sections: &[&OutSection],
    image: &[u8],
    pdb_path: Option<&str>,
) -> pdb::Input {
    let mut module_of = vec![None; ln.objs.len()];
    let mut modules = Vec::new();
    // lld lists modules in the order it included the objects, which for archive
    // members is the order they were pulled in, not the order they were read.
    // Import members have no sections. lld describes them as "Import:" modules, with
    // their thunks, which are not written yet.
    let mut included: Vec<usize> =
        (0..ln.objs.len()).filter(|&oi| ln.included[oi] && ln.objs[oi].import.is_none()).collect();
    included.sort_by_key(|&oi| ln.file_seq[oi]);
    for oi in included {
        let obj = &ln.objs[oi];
        module_of[oi] = Some(modules.len() as u16);
        modules.push(pdb::ModuleInput {
            name: module_names(&obj.name).0,
            obj_name: module_names(&obj.name).1,
            symbols: Vec::new(),
            first_contrib: SectionContrib::default(),
        });
    }

    let mut contribs = Vec::new();
    for (si, out) in sections.iter().enumerate() {
        for m in &out.members {
            let ch = &ln.chunks[m.chunk as usize];
            let module = module_of[ch.obj as usize].expect("chunk from an included object");
            contribs.push(SectionContrib {
                section: (si + 1) as u16,
                offset: ch.offset,
                size: ch.size as u32,
                characteristics: out.chars,
                module,
            });
        }
    }
    let mut seen = vec![false; modules.len()];
    for c in &contribs {
        let m = c.module as usize;
        if !seen[m] {
            seen[m] = true;
            modules[m].first_contrib = *c;
        }
    }

    let start = (PE_OFFSET + 4 + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE) as usize;
    let len = SECTION_HEADER_SIZE as usize * sections.len();

    // Where each chunk that the image keeps is: its section number and offset.
    let mut chunk_loc: Vec<Option<(u16, u32)>> = vec![None; ln.chunks.len()];
    for (si, out) in sections.iter().enumerate() {
        for m in &out.members {
            chunk_loc[m.chunk as usize] =
                Some(((si + 1) as u16, ln.chunks[m.chunk as usize].offset));
        }
    }
    // The symbol records of each module, with the addresses its relocations fill in.
    let module_objs: Vec<usize> =
        module_of.iter().enumerate().filter_map(|(oi, m)| m.map(|_| oi)).collect();
    for (m, &oi) in modules.iter_mut().zip(&module_objs) {
        m.symbols = debug_symbols::<A>(ln, oi, &chunk_loc);
    }
    // Names that the objects define as functions, which lld flags in publics.
    let functions: std::collections::HashSet<&[u8]> = ln
        .objs
        .iter()
        .flat_map(|o| o.symbols.iter())
        .filter(|s| {
            s.storage == coff::CLASS_EXTERNAL
                && s.section > 0
                && s.typ & 0x0f == 0
                && s.typ & 0xf0 == 0x20
        })
        .map(|s| s.name)
        .collect();
    // lld leaves out the coverage symbols, which double the size of publics.
    const COVERAGE_PREFIXES: [&[u8]; 3] = [b"__profd_", b"__profc_", b"__covrec_"];
    let mut publics = Vec::new();
    for gi in 0..ln.globals.len() {
        let g = &ln.globals[gi];
        // A weak external defers to its default, so follow the name's resolution.
        let Some(Loc::Chunk { chunk, value }) = ln.resolve(gi as u32) else {
            continue;
        };
        let Some((segment, base)) = chunk_loc[chunk as usize] else {
            continue;
        };
        if COVERAGE_PREFIXES.iter().any(|p| g.name.starts_with(p)) {
            continue;
        }
        publics.push(gsi::Public {
            name: g.name.to_vec(),
            segment,
            offset: base + value,
            function: functions.contains(g.name),
        });
    }

    // The COFF groups of each output section: one per partial section, which
    // spans the chunks that the section holds, in lld's partial section order.
    let mut groups = Vec::new();
    for (si, out) in sections.iter().enumerate() {
        let mut by_key: std::collections::BTreeMap<u32, (Vec<u8>, u32, u32, u32)> =
            std::collections::BTreeMap::new();
        for m in &out.members {
            let ch = &ln.chunks[m.chunk as usize];
            let sec = &ln.objs[ch.obj as usize].sections[ch.sec as usize];
            let end = ch.offset + ch.size as u32;
            let entry = by_key.entry(m.partial).or_insert_with(|| {
                (sec.name.to_vec(), sec.characteristics & OUTPUT_CHAR_MASK, ch.offset, end)
            });
            entry.2 = entry.2.min(ch.offset);
            entry.3 = entry.3.max(end);
        }
        let mut section_groups: Vec<pdb::symbols::CoffGroup> = by_key
            .into_values()
            .map(|(name, characteristics, start, end)| pdb::symbols::CoffGroup {
                section: (si + 1) as u16,
                name,
                characteristics,
                offset: start,
                size: end - start,
            })
            .collect();
        // lld lists a section's groups in the order they are laid out.
        section_groups.sort_by_key(|g| g.offset);
        groups.extend(section_groups);
    }
    pdb::Input {
        age: 1,
        pdb_path: pdb_path.unwrap_or_default().to_string(),
        publics,
        groups,
        env: pdb::symbols::Env::default(),
        machine: A::MACHINE,
        modules,
        contribs,
        sections: sections
            .iter()
            .map(|o| pdb::dbi::Section {
                name: o.name.clone(),
                rva: o.rva as u32,
                characteristics: o.chars,
                virtual_size: o.virt_size as u32,
            })
            .collect(),
        section_headers: image[start..start + len].to_vec(),
    }
}

/// Groups the live chunks by output section name. Input sections whose names
/// differ only after a '$' are merged, and `.bss` goes into `.data`, as in lld.
fn group_chunks(ln: &Linker<'_>) -> Vec<OutSection> {
    // The live chunks in lld's order: by object completion, then by section.
    let mut order: Vec<usize> = (0..ln.chunks.len()).filter(|&c| ln.chunks[c].live).collect();
    order.sort_by_key(|&c| (ln.file_seq[ln.chunks[c].obj as usize], ln.chunks[c].sec));

    // lld keeps its partial sections in a map keyed by the full input section
    // name and characteristics, so they are laid out in that key's order.
    let key_of = |c: usize| -> (Vec<u8>, u32) {
        let ch = &ln.chunks[c];
        let sec = &ln.objs[ch.obj as usize].sections[ch.sec as usize];
        (sec.name.to_vec(), sec.characteristics & OUTPUT_CHAR_MASK)
    };
    let mut keys: Vec<(Vec<u8>, u32)> = order.iter().map(|&c| key_of(c)).collect();
    keys.sort();
    keys.dedup();
    let rank: HashMap<(Vec<u8>, u32), u32> =
        keys.into_iter().enumerate().map(|(i, k)| (k, i as u32)).collect();

    let mut outs: Vec<OutSection> = Vec::new();
    let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
    for (seq, &c) in order.iter().enumerate() {
        let ch = &ln.chunks[c];
        let sec = &ln.objs[ch.obj as usize].sections[ch.sec as usize];
        let name = out_name(sec.name);
        let i = match index.get(&name) {
            Some(&i) => i,
            None => {
                outs.push(OutSection {
                    name: name.clone(),
                    chars: 0,
                    members: Vec::new(),
                    init_size: 0,
                    virt_size: 0,
                    rva: 0,
                    raw_off: 0,
                    raw_size: 0,
                });
                index.insert(name, outs.len() - 1);
                outs.len() - 1
            }
        };
        let key = key_of(c);
        let out = &mut outs[i];
        out.chars |= key.1;
        out.members.push(Member {
            uninit: ch.uninit,
            partial: rank[&key],
            seq: seq as u32,
            chunk: c as u32,
        });
    }
    outs
}

/// Returns the output section name for an input section name.
fn out_name(name: &[u8]) -> Vec<u8> {
    let base = name.split(|&b| b == b'$').next().unwrap_or(name);
    if base == b".bss" { b".data".to_vec() } else { base.to_vec() }
}

/// Orders output sections as lld does: its builtin sections in their creation
/// order, then the others in the order of their partial sections, which is by name.
fn sort_outs(outs: &mut [OutSection]) {
    fn rank(name: &[u8]) -> (usize, Vec<u8>) {
        match BUILTIN_SECTIONS.iter().position(|&b| b == name) {
            Some(i) => (i, Vec::new()),
            None => (BUILTIN_SECTIONS.len(), name.to_vec()),
        }
    }
    outs.sort_by_cached_key(|o| rank(&o.name));
}

/// Returns true if a chunk has a relocation that needs a base relocation entry.
fn has_address_relocs<A: Arch>(ln: &Linker<'_>, c: usize) -> bool {
    let ch = &ln.chunks[c];
    let obj = &ln.objs[ch.obj as usize];
    obj.sections[ch.sec as usize].relocs.iter().any(|r| A::has_base_reloc(r.kind))
}

/// Applies the relocations of live chunk `c` to `image`. Each absolute
/// address that depends on the image base is recorded in `sites`.
fn apply_relocs<A: Arch>(
    ln: &Linker<'_>,
    c: usize,
    image_base: u64,
    import_rva: &[u64],
    chunk_rva: &[u64],
    chunk_file: &[u64],
    image: &mut [u8],
    sites: &mut Vec<(u32, u8)>,
) {
    let ch = &ln.chunks[c];
    let obj = Rc::clone(&ln.objs[ch.obj as usize]);
    let sec = &obj.sections[ch.sec as usize];
    if sec.relocs.is_empty() {
        return;
    }
    if ch.uninit {
        fatal!("{}: relocations in an uninitialized section", obj.name);
    }
    let p_base_rva = chunk_rva[c];
    let p_base_off = chunk_file[c];

    for r in &sec.relocs {
        let fixup = Fixup {
            kind: r.kind,
            at: (p_base_off + r.offset as u64) as usize,
            rva: p_base_rva + r.offset as u64,
            target: target_of(ln, ch.obj, r.symbol, import_rva, chunk_rva, &obj.name),
            image_base,
        };
        match A::apply(image, fixup) {
            Ok(Some(kind)) => sites.push((rva32(fixup.rva), kind)),
            Ok(None) => {}
            Err(RelocError::Unsupported(kind)) => {
                fatal!("{}: unsupported relocation type 0x{kind:x}", obj.name)
            }
            Err(RelocError::OutOfRange) => {
                fatal!("{}: relocation out of range at offset {}", obj.name, r.offset)
            }
        }
    }
}

fn rva32(rva: u64) -> u32 {
    match u32::try_from(rva) {
        Ok(rva) => rva,
        Err(_) => fatal!("image is larger than 4 GiB"),
    }
}

/// Resolves a symbol referenced by a relocation to an address.
fn target_of(
    ln: &Linker<'_>,
    oi: u32,
    symbol: u32,
    import_rva: &[u64],
    chunk_rva: &[u64],
    file: &str,
) -> Target {
    let sym_name =
        || String::from_utf8_lossy(ln.objs[oi as usize].symbols[symbol as usize].name).into_owned();
    let loc = ln.locs[oi as usize][symbol as usize];
    let resolved = match loc {
        Loc::Global(g) => ln.resolve(g),
        other => Some(other),
    };
    match resolved {
        Some(Loc::Chunk { chunk, value }) => {
            let ch = &ln.chunks[chunk as usize];
            if ch.discarded || !ch.live {
                fatal!("{file}: relocation refers to {} in a discarded COMDAT section", sym_name());
            }
            Target::Image(chunk_rva[chunk as usize] + value as u64)
        }
        Some(Loc::Abs(v)) => Target::Abs(v as u64),
        Some(Loc::Import(slot)) => Target::Image(import_rva[slot as usize]),
        _ => fatal!("{file}: relocation refers to undefined symbol {}", sym_name()),
    }
}

/// Encodes the base relocation table. Entries are grouped by 4 KiB page, and
/// each block is padded to a multiple of 4 bytes.
fn base_relocs(sites: &mut [(u32, u8)]) -> Vec<u8> {
    sites.sort_unstable();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sites.len() {
        let page = sites[i].0 & !0xfff;
        let start = i;
        while i < sites.len() && sites[i].0 & !0xfff == page {
            i += 1;
        }
        let mut entries: Vec<u16> = sites[start..i]
            .iter()
            .map(|&(rva, kind)| ((kind as u16) << 12) | (rva & 0xfff) as u16)
            .collect();
        if entries.len() % 2 == 1 {
            entries.push(0);
        }
        let block_size = 8 + 2 * entries.len() as u32;
        out.extend_from_slice(&page.to_le_bytes());
        out.extend_from_slice(&block_size.to_le_bytes());
        for e in entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
    }
    out
}

struct Headers {
    machine: u16,
    image_base: u64,
    entry_rva: u64,
    subsystem: u16,
    nxcompat: bool,
    relocatable: bool,
    code_size: u64,
    init_size: u64,
    uninit_size: u64,
    base_of_code: u64,
    size_of_image: u64,
    size_of_headers: u64,
    reloc_dir: (u64, u64),
    debug_dir: (u64, u64),
    import_dir: (u64, u64),
    iat_dir: (u64, u64),
}

/// Writes the IMAGE_DEBUG_DIRECTORY entry at `dir_rva` and `dir_off`. The
/// CodeView record follows the entry, and the entry points to it.
fn write_debug_directory(image: &mut [u8], dir_off: usize, dir_rva: u64, rec_len: usize) {
    let rec_rva = dir_rva + DEBUG_DIRECTORY_SIZE as u64;
    let rec_off = dir_off + DEBUG_DIRECTORY_SIZE;
    let mut entry = [0u8; DEBUG_DIRECTORY_SIZE];
    // Characteristics, TimeDateStamp and the version are zero.
    entry[12..16].copy_from_slice(&IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes());
    entry[16..20].copy_from_slice(&(rec_len as u32).to_le_bytes());
    entry[20..24].copy_from_slice(&(rec_rva as u32).to_le_bytes());
    entry[24..28].copy_from_slice(&(rec_off as u32).to_le_bytes());
    put(image, dir_off, &entry);
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Writes the DOS header, the PE and optional headers, and the section table.
fn write_headers(image: &mut [u8], h: &Headers, sections: &[&OutSection]) {
    let coff = PE_OFFSET + 4;
    let opt = coff + COFF_HEADER_SIZE;
    let table = opt + OPTIONAL_HEADER_SIZE;

    put(image, 0, b"MZ");
    put(image, 0x3c, &(PE_OFFSET as u32).to_le_bytes());
    put(image, PE_OFFSET, b"PE\0\0");

    let mut dll_chars = IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    if h.nxcompat {
        dll_chars |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    }
    if h.relocatable {
        dll_chars |=
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    }

    // COFF file header.
    put(image, coff, &h.machine.to_le_bytes());
    put(image, coff + 2, &(sections.len() as u16).to_le_bytes());
    put(image, coff + 16, &(OPTIONAL_HEADER_SIZE as u16).to_le_bytes());
    let file_chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    put(image, coff + 18, &file_chars.to_le_bytes());

    // Optional header, PE32+ flavour.
    put(image, opt, &0x20bu16.to_le_bytes());
    put(image, opt + 4, &(h.code_size as u32).to_le_bytes());
    put(image, opt + 8, &(h.init_size as u32).to_le_bytes());
    put(image, opt + 12, &(h.uninit_size as u32).to_le_bytes());
    put(image, opt + 16, &(h.entry_rva as u32).to_le_bytes());
    put(image, opt + 20, &(h.base_of_code as u32).to_le_bytes());
    put(image, opt + 24, &h.image_base.to_le_bytes());
    put(image, opt + 32, &(SECTION_ALIGN as u32).to_le_bytes());
    put(image, opt + 36, &(FILE_ALIGN as u32).to_le_bytes());
    put(image, opt + 40, &6u16.to_le_bytes());
    put(image, opt + 48, &6u16.to_le_bytes());
    put(image, opt + 56, &(h.size_of_image as u32).to_le_bytes());
    put(image, opt + 60, &(h.size_of_headers as u32).to_le_bytes());
    put(image, opt + 68, &h.subsystem.to_le_bytes());
    put(image, opt + 70, &dll_chars.to_le_bytes());
    put(image, opt + 72, &0x10_0000u64.to_le_bytes());
    put(image, opt + 80, &0x1000u64.to_le_bytes());
    put(image, opt + 88, &0x10_0000u64.to_le_bytes());
    put(image, opt + 96, &0x1000u64.to_le_bytes());
    put(image, opt + 108, &(NUM_DATA_DIRECTORIES as u32).to_le_bytes());
    let dir = opt + 112 + BASE_RELOC_DIRECTORY * 8;
    put(image, dir, &(h.reloc_dir.0 as u32).to_le_bytes());
    put(image, dir + 4, &(h.reloc_dir.1 as u32).to_le_bytes());
    let debug = opt + 112 + DEBUG_DIRECTORY * 8;
    put(image, debug, &(h.debug_dir.0 as u32).to_le_bytes());
    put(image, debug + 4, &(h.debug_dir.1 as u32).to_le_bytes());
    let import = opt + 112 + IMPORT_DIRECTORY * 8;
    put(image, import, &(h.import_dir.0 as u32).to_le_bytes());
    put(image, import + 4, &(h.import_dir.1 as u32).to_le_bytes());
    let iat = opt + 112 + IAT_DIRECTORY * 8;
    put(image, iat, &(h.iat_dir.0 as u32).to_le_bytes());
    put(image, iat + 4, &(h.iat_dir.1 as u32).to_le_bytes());

    // Section table. A section with initialized data has no uninitialized
    // flag: its uninitialized tail is just part of its virtual size.
    for (i, o) in sections.iter().enumerate() {
        let at = table + i * SECTION_HEADER_SIZE;
        let n = o.name.len().min(8);
        put(image, at, &[0u8; 8]);
        put(image, at, &o.name[..n]);
        put(image, at + 8, &(o.virt_size as u32).to_le_bytes());
        put(image, at + 12, &(o.rva as u32).to_le_bytes());
        put(image, at + 16, &(o.raw_size as u32).to_le_bytes());
        put(image, at + 20, &(o.raw_off as u32).to_le_bytes());
        let chars = if o.chars & SCN_CNT_INITIALIZED_DATA != 0 {
            o.chars & !SCN_CNT_UNINITIALIZED_DATA
        } else {
            o.chars
        };
        put(image, at + 36, &chars.to_le_bytes());
    }
}

/// Returns the symbol records of object `oi`, from its `.debug$S` sections,
/// with each address that a relocation fills in replaced by its value: the
/// section-relative offset for `SECREL`, and the section number for `SECTION`.
/// Addresses the image does not keep are zero.
fn debug_symbols<A: Arch>(ln: &Linker<'_>, oi: usize, chunk_loc: &[Option<(u16, u32)>]) -> Vec<u8> {
    let target = |symbol: u32| -> Option<(u16, u32)> {
        let resolved = match ln.locs[oi][symbol as usize] {
            Loc::Global(g) => ln.resolve(g),
            other => Some(other),
        };
        match resolved {
            Some(Loc::Chunk { chunk, value }) => {
                chunk_loc[chunk as usize].map(|(segment, base)| (segment, base + value))
            }
            _ => None,
        }
    };
    let mut out = Vec::new();
    for sec in ln.objs[oi].sections.iter().filter(|s| s.name == b".debug$S") {
        let mut data = sec.data.to_vec();
        for r in &sec.relocs {
            let at = r.offset as usize;
            let found = target(r.symbol);
            if r.kind == A::SECREL_RELOC && at + 4 <= data.len() {
                let v = found.map_or(0, |(_, off)| off);
                data[at..at + 4].copy_from_slice(&v.to_le_bytes());
            } else if r.kind == A::SECTION_RELOC && at + 2 <= data.len() {
                let v = found.map_or(0, |(segment, _)| segment);
                data[at..at + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
        out.extend(pdb::symbol_records(&data));
    }
    out
}

/// The module name and object file name of an input object, as lld records
/// them. An archive member, named `archive(member)`, is named by its member
/// and refers to its archive. Other objects are named by their absolute path.
fn module_names(name: &str) -> (String, String) {
    let absolute = |p: &str| {
        std::path::absolute(p).map_or_else(|_| p.to_string(), |a| a.display().to_string())
    };
    match name.strip_suffix(')').and_then(|n| n.split_once('(')) {
        Some((archive, member)) => (member.to_string(), absolute(archive)),
        None => (absolute(name), absolute(name)),
    }
}

/// The size of an `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_SIZE: u64 = 20;
/// The flag that marks an import by ordinal in a lookup table entry.
const ORDINAL_FLAG: u64 = 1 << 63;

/// The import tables that lld puts in .rdata, laid out from `base`: the import
/// directory, each DLL's lookup table, the address tables, the hint and name
/// entries, and the DLL names. DLLs are listed by their lowercase names, and
/// each DLL's imports by name, as lld orders them.
struct ImportTables {
    bytes: Vec<u8>,
    dir_rva: u64,
    dir_size: u64,
    iat_rva: u64,
    iat_size: u64,
    /// The RVA of each import slot, indexed like `Linker::import_slots`.
    slot_rva: Vec<u64>,
}

/// Reserves `len` bytes at `cursor`, returning where they start.
fn take(cursor: &mut u64, len: u64) -> u64 {
    let at = *cursor;
    *cursor += len;
    at
}

fn import_tables(slots: &[ImportMember<'_>], base: u64) -> ImportTables {
    // Group the slots by DLL, in the order each DLL is first imported from, as lld
    // does. DLL names compare without case.
    let mut dlls: Vec<(&[u8], Vec<usize>)> = Vec::new();
    for (i, s) in slots.iter().enumerate() {
        let lower = s.dll.to_ascii_lowercase();
        match dlls.iter_mut().find(|(d, _)| d.to_ascii_lowercase() == lower) {
            Some((_, list)) => list.push(i),
            None => dlls.push((s.dll, vec![i])),
        }
    }
    for (_, list) in &mut dlls {
        list.sort_by(|&a, &b| slots[a].symbol.cmp(slots[b].symbol));
    }

    let dir_size = IMPORT_DESCRIPTOR_SIZE * (dlls.len() as u64 + 1);
    // The lookup and address tables are 8-byte aligned, after the directory.
    let mut cursor = dir_size.next_multiple_of(8);
    let ilt: Vec<u64> =
        dlls.iter().map(|(_, l)| take(&mut cursor, 8 * (l.len() as u64 + 1))).collect();
    let iat_start = cursor;
    let iat: Vec<u64> =
        dlls.iter().map(|(_, l)| take(&mut cursor, 8 * (l.len() as u64 + 1))).collect();
    let iat_size = cursor - iat_start;
    let mut hint_at = vec![0u64; slots.len()];
    for (_, list) in &dlls {
        for &i in list {
            if slots[i].ordinal.is_none() {
                let len = (2 + slots[i].export.len() as u64 + 1).next_multiple_of(2);
                hint_at[i] = take(&mut cursor, len);
            }
        }
    }
    let name_at: Vec<u64> =
        dlls.iter().map(|(d, _)| take(&mut cursor, d.len() as u64 + 1)).collect();

    let mut bytes = vec![0u8; cursor as usize];
    let mut slot_rva = vec![0u64; slots.len()];
    for (d, (dll, list)) in dlls.iter().enumerate() {
        let desc = d * IMPORT_DESCRIPTOR_SIZE as usize;
        put(&mut bytes, desc, &((base + ilt[d]) as u32).to_le_bytes());
        // The TimeDateStamp and ForwarderChain fields stay zero.
        put(&mut bytes, desc + 12, &((base + name_at[d]) as u32).to_le_bytes());
        put(&mut bytes, desc + 16, &((base + iat[d]) as u32).to_le_bytes());
        put(&mut bytes, name_at[d] as usize, dll);
        for (j, &i) in list.iter().enumerate() {
            let slot = &slots[i];
            let entry = match slot.ordinal {
                Some(ordinal) => ORDINAL_FLAG | ordinal as u64,
                None => base + hint_at[i],
            };
            let off = 8 * j;
            put(&mut bytes, ilt[d] as usize + off, &entry.to_le_bytes());
            put(&mut bytes, iat[d] as usize + off, &entry.to_le_bytes());
            slot_rva[i] = base + iat[d] + off as u64;
            if slot.ordinal.is_none() {
                put(&mut bytes, hint_at[i] as usize, &slot.hint.to_le_bytes());
                put(&mut bytes, hint_at[i] as usize + 2, &slot.export);
            }
        }
    }

    ImportTables { bytes, dir_rva: base, dir_size, iat_rva: base + iat_start, iat_size, slot_rva }
}
