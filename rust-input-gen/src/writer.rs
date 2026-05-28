//! Streaming byte writer for the ZisK C++ guest input file.
//!
//! Wraps a `Vec<u8>` with helpers that match the encoding conventions
//! in `BINARY_FORMAT.md`: little-endian integers, raw byte fields,
//! zero padding to 8-byte boundaries. Every section writer is expected
//! to leave the cursor 8-byte aligned; `assert_aligned` between
//! section calls catches mistakes early.

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Current byte offset (== `buf.len()`).
    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    // ----- raw writes -----

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Zero-fill exactly `n` bytes.
    pub fn pad(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    /// Zero-fill to the next 8-byte boundary (no-op if already aligned).
    pub fn pad_to_8(&mut self) {
        let rem = self.buf.len() % 8;
        if rem != 0 {
            self.pad(8 - rem);
        }
    }

    /// Panics if the cursor isn't 8-byte aligned. Use between section
    /// writes as a sanity check — every section in `BINARY_FORMAT.md`
    /// is sized to a multiple of 8 bytes.
    pub fn assert_aligned(&self) {
        debug_assert_eq!(
            self.buf.len() % 8,
            0,
            "writer not 8-byte aligned at offset {}",
            self.buf.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_to_8_aligns() {
        let mut w = Writer::new();
        w.u8(0x11);
        assert_eq!(w.pos(), 1);
        w.pad_to_8();
        assert_eq!(w.pos(), 8);
        assert_eq!(w.into_bytes(), vec![0x11, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn pad_to_8_noop_when_aligned() {
        let mut w = Writer::new();
        w.u64_le(0xdead_beef);
        let before = w.pos();
        w.pad_to_8();
        assert_eq!(w.pos(), before);
    }

    #[test]
    fn u64_le_is_little_endian() {
        let mut w = Writer::new();
        w.u64_le(1);
        assert_eq!(&w.into_bytes()[..], &[1, 0, 0, 0, 0, 0, 0, 0]);
    }
}
