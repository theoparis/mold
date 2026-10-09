//! PDB output: the MSF container and the streams that describe a linked image.
//!
//! The streams are serialized first, with the stream indices fixed by their
//! order, and then the container is built from them. The info stream carries
//! a GUID that is a hash of the other streams, so it is serialized twice.

pub mod dbi;
pub mod hash;
pub mod info;
pub mod msf;
pub mod names;

use dbi::{Dbi, Module, NIL_STREAM, Section, SectionContrib};
use hash::{StringMap, hash_v1};
use msf::Builder;
use names::StringTable;

/// `DEBUG_SECTION_MAGIC`, which begins every module symbol stream.
const DEBUG_SECTION_MAGIC: u32 = 4;

/// Stream indices, fixed by the order the streams are written in.
const OLD_DIRECTORY: usize = 0;
const INFO: usize = 1;
const TPI: usize = 2;
const DBI: usize = 3;
const IPI: usize = 4;
const LINK_INFO: usize = 5;
const NAMES: usize = 6;
const SECTION_HEADERS: usize = 7;
/// The first module symbol stream. Module `i` uses `FIRST_MODULE + i`.
const FIRST_MODULE: usize = 8;

/// `PdbTpiV80`, and the first type index that TPI and IPI number from.
const TPI_VERSION_V80: u32 = 20040203;
const FIRST_TYPE_INDEX: u32 = 0x1000;

/// One object's contribution to the PDB.
pub struct ModuleInput {
    pub name: String,
    pub obj_name: String,
    /// The module's symbol records, after the signature.
    pub symbols: Vec<u8>,
    pub first_contrib: SectionContrib,
}

/// Everything needed to write the PDB of a linked image.
pub struct Input {
    pub age: u32,
    /// The absolute path of the PDB file. It is the first EC name, which the
    /// modules refer to by offset zero.
    pub pdb_path: String,
    pub machine: u16,
    pub modules: Vec<ModuleInput>,
    pub contribs: Vec<SectionContrib>,
    pub sections: Vec<Section>,
    /// The COFF section headers, as they appear in the image.
    pub section_headers: Vec<u8>,
}

/// An empty TPI or IPI stream: a header, and no records or hash data.
fn empty_tpi() -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&TPI_VERSION_V80.to_le_bytes());
    out.extend_from_slice(&56u32.to_le_bytes()); // HeaderSize
    out.extend_from_slice(&FIRST_TYPE_INDEX.to_le_bytes());
    out.extend_from_slice(&FIRST_TYPE_INDEX.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // TypeRecordBytes
    out.extend_from_slice(&NIL_STREAM.to_le_bytes()); // HashStreamIndex
    out.extend_from_slice(&NIL_STREAM.to_le_bytes()); // HashAuxStreamIndex
    out.extend_from_slice(&4u32.to_le_bytes()); // HashKeySize
    out.extend_from_slice(&0u32.to_le_bytes()); // NumHashBuckets
    out.resize(56, 0); // Hash and index buffers: all empty.
    out
}

/// Serializes every stream of the PDB, in index order, with `guid` in the info stream.
fn streams(input: &Input, guid: [u8; 16]) -> Vec<Vec<u8>> {
    let modules: Vec<Module> = input
        .modules
        .iter()
        .enumerate()
        .map(|(i, m)| Module {
            name: m.name.clone(),
            obj_name: m.obj_name.clone(),
            stream: (FIRST_MODULE + i) as u16,
            sym_bytes: 4 + m.symbols.len() as u32,
            first_contrib: m.first_contrib,
        })
        .collect();
    let mut ec_names = StringTable::default();
    ec_names.insert(input.pdb_path.as_bytes());
    let ec = ec_names.serialize();
    let dbi = Dbi {
        age: input.age,
        machine: input.machine,
        global_stream: NIL_STREAM,
        public_stream: NIL_STREAM,
        sym_record_stream: NIL_STREAM,
        modules: &modules,
        contribs: &input.contribs,
        sections: &input.sections,
        ec_names: &ec,
        section_hdr_stream: SECTION_HEADERS as u16,
    };

    let mut named = StringMap::new(hash_v1);
    named.insert(b"/LinkInfo", LINK_INFO as u32);
    named.insert(b"/names", NAMES as u32);

    let mut out: Vec<Vec<u8>> = vec![Vec::new(); FIRST_MODULE];
    out[OLD_DIRECTORY] = Vec::new();
    out[INFO] = info::info_stream(input.age, guid, &named, &[]);
    out[TPI] = empty_tpi();
    out[DBI] = dbi::dbi_stream(&dbi);
    out[IPI] = empty_tpi();
    out[LINK_INFO] = Vec::new();
    out[NAMES] = StringTable::default().serialize();
    out[SECTION_HEADERS] = input.section_headers.to_vec();
    for m in &input.modules {
        let mut s = DEBUG_SECTION_MAGIC.to_le_bytes().to_vec();
        s.extend_from_slice(&m.symbols);
        // The global refs substream follows the line info. It is empty.
        s.extend_from_slice(&0u32.to_le_bytes());
        out.push(s);
    }
    out
}

/// A 128-bit content hash of the streams, used as the PDB's GUID.
fn content_guid(streams: &[Vec<u8>]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (half, seed) in [(0usize, 0xcbf2_9ce4_8422_2325u64), (8, 0x8422_2325_cbf2_9ce4)] {
        let mut h = seed;
        for s in streams {
            for &b in s {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            h ^= s.len() as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        out[half..half + 8].copy_from_slice(&h.to_le_bytes());
    }
    out
}

/// Writes the PDB file for `input` and returns its bytes and GUID.
pub fn write(input: &Input) -> (Vec<u8>, [u8; 16]) {
    let guid = content_guid(&streams(input, [0; 16]));
    let mut builder = Builder::new();
    for s in streams(input, guid) {
        builder.add_stream(s);
    }
    (builder.finish(), guid)
}

/// The CodeView RSDS record that points a debugger at the PDB: the signature,
/// the PDB's GUID and age, and the NUL-terminated path.
pub fn codeview_record(guid: [u8; 16], age: u32, path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + path.len() + 1);
    out.extend_from_slice(b"RSDS");
    out.extend_from_slice(&guid);
    out.extend_from_slice(&age.to_le_bytes());
    out.extend_from_slice(path.as_bytes());
    out.push(0);
    out
}
