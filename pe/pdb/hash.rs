//! Hash functions and the string hash table that PDB streams serialize.
//!
//! These follow LLVM's `Hash.cpp` and `HashTable.h`, so that a reader's
//! lookups land on the same buckets that the writer filled.

/// `hashStringV1`, used by the named-stream map of the info stream.
pub fn hash_v1(s: &[u8]) -> u32 {
    let mut result = 0u32;
    let mut chunks = s.chunks_exact(4);
    for c in &mut chunks {
        result ^= u32::from_le_bytes(c.try_into().unwrap());
    }
    let mut rem = chunks.remainder();
    if rem.len() >= 2 {
        result ^= u16::from_le_bytes([rem[0], rem[1]]) as u32;
        rem = &rem[2..];
    }
    if let [b] = rem {
        result ^= *b as u32;
    }
    result |= 0x2020_2020;
    result ^= result >> 11;
    result ^ (result >> 16)
}

/// A hash table from strings to `u32` values, as PDB streams store them.
///
/// Each key is kept in an appended buffer of NUL-terminated names, and the
/// table stores each key's offset into that buffer. Probing is linear from
/// `hash % capacity`, and the table doubles when it reaches the load limit.
pub struct StringMap {
    names: Vec<u8>,
    /// Each occupied bucket holds the key's offset in `names` and its value.
    buckets: Vec<Option<(u32, u32)>>,
    len: u32,
    hash: fn(&[u8]) -> u32,
}

const DEFAULT_CAPACITY: usize = 8;

fn max_load(capacity: usize) -> usize {
    capacity * 2 / 3 + 1
}

impl StringMap {
    pub fn new(hash: fn(&[u8]) -> u32) -> Self {
        StringMap { names: Vec::new(), buckets: vec![None; DEFAULT_CAPACITY], len: 0, hash }
    }

    /// The NUL-terminated names that the table's keys point into.
    pub fn names(&self) -> &[u8] {
        &self.names
    }

    fn name_at(&self, offset: u32) -> &[u8] {
        let s = &self.names[offset as usize..];
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        &s[..end]
    }

    /// Returns the bucket holding `name`, or the first empty bucket on its
    /// probe path where it would be inserted.
    fn find(&self, name: &[u8]) -> Result<usize, usize> {
        let cap = self.buckets.len();
        let start = (self.hash)(name) as usize % cap;
        let mut i = start;
        loop {
            match self.buckets[i] {
                Some((offset, _)) if self.name_at(offset) == name => return Ok(i),
                Some(_) => {}
                None => return Err(i),
            }
            i = (i + 1) % cap;
            assert!(i != start, "string map has no empty bucket");
        }
    }

    /// Sets `name` to `value`, adding it if it isn't present.
    pub fn insert(&mut self, name: &[u8], value: u32) {
        match self.find(name) {
            Ok(i) => self.buckets[i] = self.buckets[i].map(|(off, _)| (off, value)),
            Err(i) => {
                let offset = self.names.len() as u32;
                self.names.extend_from_slice(name);
                self.names.push(0);
                self.buckets[i] = Some((offset, value));
                self.len += 1;
                self.grow();
            }
        }
    }

    fn grow(&mut self) {
        let cap = self.buckets.len();
        if (self.len as usize) < max_load(cap) {
            return;
        }
        let old = std::mem::replace(&mut self.buckets, vec![None; max_load(cap) * 2]);
        for (offset, value) in old.into_iter().flatten() {
            let name = self.name_at(offset).to_vec();
            let i = self.find(&name).unwrap_err();
            self.buckets[i] = Some((offset, value));
        }
    }

    /// Serializes the table as LLVM's `HashTable::commit` does.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_le_bytes());
        out.extend_from_slice(&(self.buckets.len() as u32).to_le_bytes());
        let present: Vec<usize> =
            self.buckets.iter().enumerate().filter(|(_, b)| b.is_some()).map(|(i, _)| i).collect();
        write_bit_vector(out, present);
        write_bit_vector(out, Vec::new());
        for (offset, value) in self.buckets.iter().flatten() {
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Writes a sparse bit vector: a word count, then one little-endian word
/// per 32 bits up to the highest set bit. Bits are given in ascending order.
fn write_bit_vector(out: &mut Vec<u8>, bits: Vec<usize>) {
    let words = bits.last().map_or(0, |&b| b / 32 + 1);
    out.extend_from_slice(&(words as u32).to_le_bytes());
    let mut word = vec![0u32; words];
    for b in bits {
        word[b / 32] |= 1 << (b % 32);
    }
    for w in word {
        out.extend_from_slice(&w.to_le_bytes());
    }
}
