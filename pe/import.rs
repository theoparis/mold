//! Import members of import libraries. Each member describes one symbol that
//! a DLL exports, in the short format that `IMPORT_OBJECT_HEADER` defines.

/// The symbol is imported by name, with its name as the DLL exports it.
const NAME_IMPORT: u8 = 0;
/// The symbol's name lacks a leading `?`, `@` or `_` that the DLL doesn't export.
const NAME_NOPREFIX: u8 = 1;
/// The symbol is imported by its ordinal, not by name.
const NAME_ORDINAL: u8 = 2;
/// The symbol's name is undecorated: a leading `_`, and everything from `@`.
const NAME_UNDECORATE: u8 = 3;

/// The kind of symbol that an import member describes.
#[derive(Clone, Copy, PartialEq)]
pub enum ImportKind {
    Code,
    Data,
}

/// One symbol that a DLL exports, as an import library describes it.
#[derive(Clone)]
pub struct ImportMember<'a> {
    /// The `__imp_` name that objects refer to, from the archive's symbol table.
    pub imp_name: &'a [u8],
    /// The name in the import library, which is the symbol that objects refer to.
    pub symbol: &'a [u8],
    /// The name the DLL exports, which the loader looks up. Empty for an ordinal.
    pub export: Vec<u8>,
    pub dll: &'a [u8],
    pub hint: u16,
    /// The export ordinal, when the import is by ordinal.
    pub ordinal: Option<u16>,
    pub kind: ImportKind,
}

/// Returns true if `data` is an import member, which starts with the header's
/// signature: 0 followed by 0xFFFF.
pub fn is_import(data: &[u8]) -> bool {
    data.len() >= 20 && data[0..2] == [0, 0] && data[2..4] == [0xff, 0xff]
}

/// Splits off a NUL-terminated string, returning it and the rest.
fn cstr(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = data.iter().position(|&b| b == 0)?;
    Some((&data[..end], &data[end + 1..]))
}

/// Parses an import member, whose `imp_name` is its `__imp_` symbol. The header
/// is 20 bytes: the signature, version, machine, timestamp, data size, the hint,
/// then a flags word with the import type and the name type. Two NUL-terminated
/// strings follow: the symbol and the DLL.
pub fn parse<'a>(data: &'a [u8], imp_name: &'a [u8]) -> Result<ImportMember<'a>, String> {
    if !is_import(data) {
        return Err("not an import member".to_string());
    }
    let hint = u16::from_le_bytes([data[16], data[17]]);
    let flags = u16::from_le_bytes([data[18], data[19]]);
    let kind = match flags & 0b11 {
        0 => ImportKind::Code,
        1 => ImportKind::Data,
        other => return Err(format!("unsupported import type {other}")),
    };
    let name_type = ((flags >> 2) & 0b111) as u8;

    let (symbol, rest) = cstr(&data[20..]).ok_or("truncated import member")?;
    let (dll, _) = cstr(rest).ok_or("truncated import member")?;

    let (export, ordinal) = match name_type {
        NAME_ORDINAL => (Vec::new(), Some(hint)),
        NAME_IMPORT => (symbol.to_vec(), None),
        NAME_NOPREFIX => {
            let stripped = symbol
                .strip_prefix(b"?")
                .or_else(|| symbol.strip_prefix(b"@"))
                .or_else(|| symbol.strip_prefix(b"_"))
                .unwrap_or(symbol);
            (stripped.to_vec(), None)
        }
        NAME_UNDECORATE => {
            let trimmed = symbol.strip_prefix(b"_").unwrap_or(symbol);
            let end = trimmed.iter().position(|&b| b == b'@').unwrap_or(trimmed.len());
            (trimmed[..end].to_vec(), None)
        }
        other => return Err(format!("unsupported import name type {other}")),
    };

    // An ordinal import has no hint, so the hint field holds the ordinal.
    let hint = if ordinal.is_some() { 0 } else { hint };
    Ok(ImportMember { imp_name, symbol, export, dll, hint, ordinal, kind })
}
