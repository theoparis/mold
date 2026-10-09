//! The MSF container that PDB files are built on.
//!
//! This follows LLVM's `MSFBuilder`: block 0 is the superblock, blocks 1 and 2
//! are the two free page maps, and block 3 holds the directory's block map.
//! Each stream takes the lowest free blocks in the order it was added, and the
//! directory is allocated after all streams. Matching this order keeps block
//! placement the same as lld's.

use mold_common::util::align_to;

const BLOCK_SIZE: u32 = 4096;
const SUPER_BLOCK: u32 = 0;
const FPM_ALT: u32 = 1;
const FPM_MAIN: u32 = 2;
const BLOCK_MAP: u32 = 3;
const MIN_BLOCK_COUNT: usize = 4;
const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// Builds an MSF file from streams. `add_stream` allocates the blocks at once,
/// so the call order decides placement.
pub struct Builder {
    /// `free[b]` is true when block `b` is unallocated.
    free: Vec<bool>,
    streams: Vec<Vec<u8>>,
    /// Blocks holding each stream, indexed like `streams`.
    blocks: Vec<Vec<u32>>,
}

fn blocks_for(size: usize) -> usize {
    size.div_ceil(BLOCK_SIZE as usize)
}

impl Builder {
    pub fn new() -> Self {
        let mut free = vec![true; MIN_BLOCK_COUNT];
        for b in [SUPER_BLOCK, FPM_ALT, FPM_MAIN, BLOCK_MAP] {
            free[b as usize] = false;
        }
        Builder { free, streams: Vec::new(), blocks: Vec::new() }
    }

    /// Allocates the `n` lowest free blocks, growing the file as LLVM does.
    fn allocate(&mut self, n: usize) -> Vec<u32> {
        let free_count = self.free.iter().filter(|&&f| f).count();
        if free_count < n {
            let old_len = self.free.len();
            let mut new_len = old_len + (n - free_count);
            self.free.resize(new_len, true);
            // Each crossing of a free page map interval reserves its two FPM
            // blocks, which the bitmap then reports as allocated.
            let mut next_fpm = align_to(old_len as u64, BLOCK_SIZE as u64) as usize + 1;
            while next_fpm < new_len {
                new_len += 2;
                self.free.resize(new_len, true);
                self.free[next_fpm] = false;
                self.free[next_fpm + 1] = false;
                next_fpm += BLOCK_SIZE as usize;
            }
        }

        let mut out = Vec::with_capacity(n);
        for (i, f) in self.free.iter_mut().enumerate() {
            if out.len() == n {
                break;
            }
            if *f {
                *f = false;
                out.push(i as u32);
            }
        }
        out
    }

    /// Adds a stream holding `data` and returns its stream index.
    pub fn add_stream(&mut self, data: Vec<u8>) -> u32 {
        let blocks = self.allocate(blocks_for(data.len()));
        self.streams.push(data);
        self.blocks.push(blocks);
        (self.streams.len() - 1) as u32
    }

    /// Lays out the directory and returns the complete file.
    pub fn finish(mut self) -> Vec<u8> {
        let dir_len =
            4 + 4 * self.streams.len() + 4 * self.blocks.iter().map(Vec::len).sum::<usize>();
        let dir_blocks = self.allocate(blocks_for(dir_len));
        let num_blocks = self.free.len();

        let mut dir = Vec::with_capacity(dir_len);
        dir.extend_from_slice(&(self.streams.len() as u32).to_le_bytes());
        for s in &self.streams {
            dir.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }
        for blocks in &self.blocks {
            for b in blocks {
                dir.extend_from_slice(&b.to_le_bytes());
            }
        }

        let mut file = vec![0u8; num_blocks * BLOCK_SIZE as usize];
        let block_at = |b: u32| b as usize * BLOCK_SIZE as usize;

        // Superblock.
        let sb = &mut file[..56];
        sb[..32].copy_from_slice(MAGIC);
        sb[32..36].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        sb[36..40].copy_from_slice(&FPM_MAIN.to_le_bytes());
        sb[40..44].copy_from_slice(&(num_blocks as u32).to_le_bytes());
        sb[44..48].copy_from_slice(&(dir_len as u32).to_le_bytes());
        // Unknown1 at 48..52 stays zero.
        sb[52..56].copy_from_slice(&BLOCK_MAP.to_le_bytes());

        // Free page maps: one bit per block, set when the block is free.
        // Bits past the end of the file count as free.
        let mut bitmap = vec![0u8; num_blocks.div_ceil(8)];
        for (i, byte) in bitmap.iter_mut().enumerate() {
            for bit in 0..8 {
                let b = i * 8 + bit;
                if b >= num_blocks || self.free[b] {
                    *byte |= 1 << bit;
                }
            }
        }
        for fpm in [FPM_MAIN, FPM_ALT] {
            // Every interval the reader expects gets its block filled with
            // 0xFF first, then the used bitmap bytes are copied over.
            let intervals = (num_blocks - fpm as usize).div_ceil(BLOCK_SIZE as usize);
            for k in 0..intervals {
                let at = block_at(fpm + (k as u32) * BLOCK_SIZE);
                file[at..at + BLOCK_SIZE as usize].fill(0xff);
            }
            for (k, chunk) in bitmap.chunks(BLOCK_SIZE as usize).enumerate() {
                let at = block_at(fpm + (k as u32) * BLOCK_SIZE);
                file[at..at + chunk.len()].copy_from_slice(chunk);
            }
        }

        // The block map lists the directory's blocks.
        let map_at = block_at(BLOCK_MAP);
        for (i, b) in dir_blocks.iter().enumerate() {
            file[map_at + 4 * i..map_at + 4 * i + 4].copy_from_slice(&b.to_le_bytes());
        }

        write_chain(&mut file, &dir, &dir_blocks);
        for (data, blocks) in self.streams.iter().zip(&self.blocks) {
            write_chain(&mut file, data, blocks);
        }
        file
    }
}

/// Copies `data` into `file` across `blocks`, one block at a time.
fn write_chain(file: &mut [u8], data: &[u8], blocks: &[u32]) {
    for (chunk, &b) in data.chunks(BLOCK_SIZE as usize).zip(blocks) {
        let at = b as usize * BLOCK_SIZE as usize;
        file[at..at + chunk.len()].copy_from_slice(chunk);
    }
}
