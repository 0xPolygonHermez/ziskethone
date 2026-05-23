//! Binary container writer for the ZisK Ethereum guest input file.
//!
//! See `BINARY_FORMAT.md` at the repository root for the on-disk layout.

use std::io::{Cursor, Write};

use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

pub const MAGIC: &[u8; 4] = b"ZEG0";
pub const VERSION: u32 = 0;

pub const FILE_HEADER_SIZE: usize = 32;
pub const SECTION_ENTRY_SIZE: usize = 16;

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SectionKind {
    ParentHeader = 1,
    CurrentHeader = 2,
    Transactions = 3,
    Withdrawals = 4,
    StateTrieNodes = 5,
    StorageTrieNodes = 6,
    Bytecodes = 7,
    AncestorHeaders = 8,
}

pub struct Section {
    pub kind: SectionKind,
    pub payload: Vec<u8>,
}

pub struct BinaryWriter {
    pub chain_id: u64,
    pub block_number: u64,
    pub sections: Vec<Section>,
}

impl BinaryWriter {
    pub fn new(chain_id: u64, block_number: u64) -> Self {
        Self { chain_id, block_number, sections: Vec::new() }
    }

    pub fn push(&mut self, kind: SectionKind, payload: Vec<u8>) {
        self.sections.push(Section { kind, payload });
    }

    /// Encode a length-prefixed list of byte blobs (used as the payload of
    /// list-style sections such as `Transactions`, `Bytecodes`, ...).
    pub fn encode_blob_list(items: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(items.len() as u32)?;
        for item in items {
            buf.write_u32::<LittleEndian>(item.len() as u32)?;
            buf.write_all(item)?;
        }
        Ok(buf)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        let section_count = self.sections.len() as u32;
        let table_size = self.sections.len() * SECTION_ENTRY_SIZE;
        let payload_start = FILE_HEADER_SIZE + table_size;

        let total_payload: usize = self.sections.iter().map(|s| s.payload.len()).sum();
        let mut out = Vec::with_capacity(payload_start + total_payload);
        let mut cursor = Cursor::new(&mut out);

        // FileHeader
        cursor.write_all(MAGIC)?;
        cursor.write_u32::<LittleEndian>(VERSION)?;
        cursor.write_u32::<LittleEndian>(section_count)?;
        cursor.write_u32::<LittleEndian>(0)?; // flags
        cursor.write_u64::<LittleEndian>(self.chain_id)?;
        cursor.write_u64::<LittleEndian>(self.block_number)?;
        debug_assert_eq!(cursor.position() as usize, FILE_HEADER_SIZE);

        // SectionTable
        let mut offset = payload_start as u32;
        for s in &self.sections {
            cursor.write_u32::<LittleEndian>(s.kind as u32)?;
            cursor.write_u32::<LittleEndian>(0)?; // reserved
            cursor.write_u32::<LittleEndian>(offset)?;
            cursor.write_u32::<LittleEndian>(s.payload.len() as u32)?;
            offset += s.payload.len() as u32;
        }
        debug_assert_eq!(cursor.position() as usize, payload_start);

        // Payloads
        for s in &self.sections {
            cursor.write_all(&s.payload)?;
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let mut w = BinaryWriter::new(1, 42);
        w.push(SectionKind::CurrentHeader, vec![0xAA, 0xBB]);
        let bytes = w.finish().unwrap();

        assert_eq!(&bytes[0..4], MAGIC);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 42);

        // Section entry
        let kind = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let off = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        assert_eq!(kind, SectionKind::CurrentHeader as u32);
        assert_eq!(off as usize, FILE_HEADER_SIZE + SECTION_ENTRY_SIZE);
        assert_eq!(len, 2);
        assert_eq!(&bytes[off as usize..(off as usize + len as usize)], &[0xAA, 0xBB]);
    }

    #[test]
    fn blob_list_roundtrip() {
        let items = vec![vec![1, 2, 3], vec![], vec![9; 17]];
        let encoded = BinaryWriter::encode_blob_list(&items).unwrap();
        assert_eq!(&encoded[0..4], &3u32.to_le_bytes());
    }
}
