//! The PDB info stream (stream 1): the file's identity, its named streams,
//! and the features it uses. Follows LLVM's `InfoStreamBuilder::commit`.

use super::hash::StringMap;

/// `PdbImplVC70`, the implementation version lld writes.
const IMPL_VC70: u32 = 20000404;

/// Serializes the info stream for a file with the given identity. `named`
/// maps each named stream's name, such as `/names`, to its stream index.
pub fn info_stream(age: u32, guid: [u8; 16], named: &StringMap, features: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&IMPL_VC70.to_le_bytes());
    // The signature is left zero, as lld does before its content hash.
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&age.to_le_bytes());
    out.extend_from_slice(&guid);

    out.extend_from_slice(&(named.names().len() as u32).to_le_bytes());
    out.extend_from_slice(named.names());
    named.serialize(&mut out);

    out.extend_from_slice(&0u32.to_le_bytes());
    for f in features {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}
