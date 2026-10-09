//! The PDB string table, which the `/names` stream and the DBI's EC names
//! substream both use. Follows LLVM's `PDBStringTableBuilder`.

use std::collections::HashMap;

use super::hash::hash_v1;

const SIGNATURE: u32 = 0xEFFE_EFFE;
/// `HashVersion` 1, the hash `hash_v1` computes.
const HASH_VERSION: u32 = 1;

/// Pairs of (string count, bucket count) where the bucket count grows, from
/// the reference implementation's `NMT::grow`. The bucket count for `n`
/// strings is the one paired with the first entry whose count is at least `n`.
const STRINGS_TO_BUCKETS: &[(u32, u32)] = &[
    (0, 1),
    (1, 2),
    (2, 4),
    (4, 7),
    (6, 11),
    (9, 17),
    (13, 26),
    (20, 40),
    (31, 61),
    (46, 92),
    (70, 139),
    (105, 209),
    (157, 314),
    (236, 472),
    (355, 709),
    (532, 1064),
    (799, 1597),
    (1198, 2396),
    (1798, 3595),
    (2697, 5393),
    (4045, 8090),
    (6068, 12136),
    (9103, 18205),
    (13654, 27308),
    (20482, 40963),
    (30723, 61445),
    (46084, 92168),
    (69127, 138253),
    (103690, 207380),
    (155536, 311071),
    (233304, 466607),
    (349956, 699911),
    (524934, 1049867),
    (787401, 1574801),
    (1181101, 2362202),
    (1771652, 3543304),
    (2657479, 5314957),
    (3986218, 7972436),
    (5979328, 11958655),
    (8968992, 17937983),
    (13453488, 26906975),
    (20180232, 40360463),
    (30270348, 60540695),
    (45405522, 90811043),
    (68108283, 136216565),
    (102162424, 204324848),
    (153243637, 306487273),
    (229865455, 459730910),
    (344798183, 689596366),
    (517197275, 1034394550),
    (775795913, 1551591826),
    (1163693870, 2327387740),
];

fn bucket_count(strings: u32) -> u32 {
    let i = STRINGS_TO_BUCKETS.partition_point(|&(count, _)| count < strings);
    STRINGS_TO_BUCKETS[i].1
}

/// Strings with the offsets they are referred to by.
#[derive(Default)]
pub struct StringTable {
    /// The NUL-terminated strings, in insertion order.
    bytes: Vec<u8>,
    ids: HashMap<Vec<u8>, u32>,
}

impl StringTable {
    /// Adds `s` if needed and returns its offset in the table.
    pub fn insert(&mut self, s: &[u8]) -> u32 {
        if let Some(&id) = self.ids.get(s) {
            return id;
        }
        let id = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s);
        self.bytes.push(0);
        self.ids.insert(s.to_vec(), id);
        id
    }

    /// Serializes the header, strings, hash buckets and string count.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE.to_le_bytes());
        out.extend_from_slice(&HASH_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bytes);

        let buckets_len = bucket_count(self.ids.len() as u32);
        out.extend_from_slice(&buckets_len.to_le_bytes());
        // Place strings in offset order, so the layout doesn't depend on hash
        // map iteration order.
        let mut by_offset: Vec<(&Vec<u8>, &u32)> = self.ids.iter().collect();
        by_offset.sort_by_key(|&(_, &id)| id);
        let mut buckets = vec![0u32; buckets_len as usize];
        for (s, &id) in by_offset {
            let hash = hash_v1(s);
            for i in 0..buckets_len {
                let slot = (hash.wrapping_add(i) % buckets_len) as usize;
                if buckets[slot] == 0 {
                    buckets[slot] = id;
                    break;
                }
            }
        }
        for b in buckets {
            out.extend_from_slice(&b.to_le_bytes());
        }
        out.extend_from_slice(&(self.ids.len() as u32).to_le_bytes());
        out
    }
}
