//! The public and global symbol streams: the public records, the hash tables
//! that find symbols by name, the address map, and the symbol record stream
//! that the hash tables refer to. Follows LLVM's `GSIStreamBuilder`.

use super::hash::hash_v1;

/// The number of hash buckets in a GSI table.
const IPHR_HASH: usize = 4096;
/// The bitmap has one bit per bucket, plus one for the unused last bucket.
const BITMAP_WORDS: usize = (IPHR_HASH + 32) / 32;
const GSI_HDR_SIGNATURE: u32 = u32::MAX;
const GSI_HDR_VERSION: u32 = 0xeffe_0000 + 19990810;
/// The size of the GSI hash header: signature, version, record and bucket sizes.
const GSI_HEADER_SIZE: usize = 16;
/// The size of the publics stream header.
const PUBLICS_HEADER_SIZE: usize = 28;
/// The size of a hash record: a symbol offset and a reference count.
const HASH_RECORD_SIZE: usize = 8;
/// Each bucket's chain start is stored as its offset in 32-bit pointers.
const CHAIN_OFFSET_SCALE: u32 = 12;
const S_PUB32: u16 = 0x110e;
/// `PublicSymFlags::Function`.
const PUB_FLAG_FUNCTION: u32 = 1 << 1;

#[derive(Clone)]
/// A defined external symbol that the publics list names.
pub struct Public {
    pub name: Vec<u8>,
    /// One-based index of the output section.
    pub segment: u16,
    /// Offset of the symbol within its section.
    pub offset: u32,
    pub function: bool,
}

/// The three streams that together hold the image's symbols.
pub struct Streams {
    pub publics: Vec<u8>,
    pub globals: Vec<u8>,
    pub records: Vec<u8>,
}

/// Lays out a public record: a prefix, the symbol's fields, the name and a NUL,
/// padded to four bytes.
fn public_record(p: &Public) -> Vec<u8> {
    let size = (4 + 10 + p.name.len() + 1).next_multiple_of(4);
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&((size - 2) as u16).to_le_bytes());
    out.extend_from_slice(&S_PUB32.to_le_bytes());
    let flags = if p.function { PUB_FLAG_FUNCTION } else { 0 };
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&p.offset.to_le_bytes());
    out.extend_from_slice(&p.segment.to_le_bytes());
    out.extend_from_slice(&p.name);
    out.resize(size, 0);
    out
}

/// Orders names the way the reference GSI does: shorter first, then
/// case-insensitively for ASCII names and bytewise otherwise.
fn gsi_name_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    if a.is_ascii() && b.is_ascii() {
        a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())
    } else {
        a.cmp(b)
    }
}

/// A hash table over symbol records.
struct HashTable {
    /// Each record's offset in the symbol record stream, plus one, and its
    /// reference count, which is always one here.
    records: Vec<(u32, u32)>,
    bitmap: [u32; BITMAP_WORDS],
    /// The chain start of each non-empty bucket, in bucket order.
    buckets: Vec<u32>,
}

impl HashTable {
    /// Buckets `symbols` (name and record offset) by name hash, and sorts each
    /// bucket. Each record's stored offset is its position in the record stream.
    fn build(symbols: &[(&[u8], u32)]) -> Self {
        let bucket_of: Vec<usize> =
            symbols.iter().map(|(name, _)| hash_v1(name) as usize % IPHR_HASH).collect();
        let mut starts = vec![0usize; IPHR_HASH + 1];
        for &b in &bucket_of {
            starts[b + 1] += 1;
        }
        for b in 0..IPHR_HASH {
            starts[b + 1] += starts[b];
        }

        // Place each symbol in its bucket, in input order.
        let mut cursor = starts.clone();
        let mut order = vec![0usize; symbols.len()];
        for (i, &b) in bucket_of.iter().enumerate() {
            order[cursor[b]] = i;
            cursor[b] += 1;
        }

        // Sort each bucket by name, then by record offset, as the reference does.
        for b in 0..IPHR_HASH {
            order[starts[b]..starts[b + 1]].sort_by(|&x, &y| {
                gsi_name_cmp(symbols[x].0, symbols[y].0).then(symbols[x].1.cmp(&symbols[y].1))
            });
        }

        let records: Vec<(u32, u32)> = order.iter().map(|&i| (symbols[i].1 + 1, 1)).collect();
        let mut bitmap = [0u32; BITMAP_WORDS];
        let mut buckets = Vec::new();
        for b in 0..IPHR_HASH {
            if starts[b] != starts[b + 1] {
                bitmap[b / 32] |= 1 << (b % 32);
                buckets.push(starts[b] as u32 * CHAIN_OFFSET_SCALE);
            }
        }
        HashTable { records, bitmap, buckets }
    }

    /// Bytes of the table: its header, records, bitmap and buckets.
    fn serialized_len(&self) -> usize {
        GSI_HEADER_SIZE
            + self.records.len() * HASH_RECORD_SIZE
            + BITMAP_WORDS * 4
            + self.buckets.len() * 4
    }

    fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&GSI_HDR_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&GSI_HDR_VERSION.to_le_bytes());
        out.extend_from_slice(&((self.records.len() * HASH_RECORD_SIZE) as u32).to_le_bytes());
        out.extend_from_slice(&((BITMAP_WORDS * 4 + self.buckets.len() * 4) as u32).to_le_bytes());
        for &(off, cref) in &self.records {
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&cref.to_le_bytes());
        }
        for w in self.bitmap {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for b in &self.buckets {
            out.extend_from_slice(&b.to_le_bytes());
        }
    }
}

/// Builds the publics, globals and record streams. The globals table is empty,
/// since the linker does not yet emit global symbol records.
pub fn build(mut publics: Vec<Public>) -> Streams {
    publics.sort_by(|a, b| a.name.cmp(&b.name));

    let mut records = Vec::new();
    let mut offsets = Vec::with_capacity(publics.len());
    for p in &publics {
        offsets.push(records.len() as u32);
        records.extend_from_slice(&public_record(p));
    }

    let symbols: Vec<(&[u8], u32)> =
        publics.iter().zip(&offsets).map(|(p, &off)| (p.name.as_slice(), off)).collect();
    let table = HashTable::build(&symbols);

    // The address map lists the publics by address, as offsets into the records.
    let mut by_addr: Vec<usize> = (0..publics.len()).collect();
    by_addr.sort_by(|&a, &b| {
        let (pa, pb) = (&publics[a], &publics[b]);
        (pa.segment, pa.offset).cmp(&(pb.segment, pb.offset)).then(pa.name.cmp(&pb.name))
    });

    let mut out = Vec::new();
    out.extend_from_slice(&(table.serialized_len() as u32).to_le_bytes()); // SymHash
    out.extend_from_slice(&((publics.len() * 4) as u32).to_le_bytes()); // AddrMap
    out.resize(PUBLICS_HEADER_SIZE, 0); // Thunks and sections: none.
    table.serialize(&mut out);
    for i in by_addr {
        out.extend_from_slice(&offsets[i].to_le_bytes());
    }

    let mut globals = Vec::new();
    HashTable::build(&[]).serialize(&mut globals);

    Streams { publics: out, globals, records }
}
