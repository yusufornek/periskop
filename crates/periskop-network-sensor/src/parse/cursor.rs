//! A reader that cannot walk off the end of a packet sample.
//!
//! Every byte this crate parses comes from the network, which means every
//! length field in it was written by somebody else. A parser that indexes a
//! slice directly turns a hostile length into a panic, and a panic inside the
//! sensor takes down a scan that was supposed to keep running whatever the
//! sensor found. So there is exactly one way to read a byte here, it returns
//! `Option`, and the parsers above are written so that `None` becomes a stated
//! parse failure rather than a silent empty result.
//!
//! Arithmetic on offsets is checked for the same reason: a 16 bit length from
//! the wire added to an offset must not be allowed to wrap on any target.

/// A forward reader over a byte sample, with a seek for the one format that
/// needs it (DNS name compression points backwards).
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The current offset, which DNS name reading needs in order to resume
    /// after a name it parsed out of band.
    pub(crate) fn at(&self) -> usize {
        self.at
    }

    pub(crate) fn seek(&mut self, to: usize) -> Option<()> {
        if to > self.bytes.len() {
            return None;
        }
        self.at = to;
        Some(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at = self.at.checked_add(1)?;
        Some(byte)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from(*bytes.first()?) << 8 | u16::from(*bytes.get(1)?))
    }

    /// Three byte big endian length, which is how TLS spells a handshake size.
    pub(crate) fn u24(&mut self) -> Option<u32> {
        let bytes = self.take(3)?;
        Some(
            u32::from(*bytes.first()?) << 16
                | u32::from(*bytes.get(1)?) << 8
                | u32::from(*bytes.get(2)?),
        )
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(
            u32::from(*bytes.first()?) << 24
                | u32::from(*bytes.get(1)?) << 16
                | u32::from(*bytes.get(2)?) << 8
                | u32::from(*bytes.get(3)?),
        )
    }

    pub(crate) fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    pub(crate) fn skip(&mut self, count: usize) -> Option<()> {
        self.take(count).map(|_| ())
    }

    /// Everything left, used where a format says "the rest of this structure".
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let slice = self.bytes.get(self.at..).unwrap_or_default();
        self.at = self.bytes.len();
        slice
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reading_past_the_end_yields_nothing_instead_of_panicking() {
        // The property the whole module exists for. A hostile length field must
        // not be able to take the scan down.
        let mut cursor = Cursor::new(&[0x01]);
        assert_eq!(cursor.u8(), Some(1));
        assert_eq!(cursor.u8(), None);
        assert_eq!(cursor.u16(), None);
        assert_eq!(cursor.u24(), None);
        assert_eq!(cursor.u32(), None);
        assert_eq!(cursor.take(1), None);
    }

    #[test]
    fn a_failed_read_does_not_move_the_offset() {
        // A parser that keeps going after a short read has to see the same
        // bytes it would have seen before, or the failure turns into a shift.
        let mut cursor = Cursor::new(&[0xaa, 0xbb]);
        assert_eq!(cursor.take(5), None);
        assert_eq!(cursor.at(), 0);
        assert_eq!(cursor.u16(), Some(0xaabb));
    }

    #[test]
    fn multi_byte_reads_are_big_endian_as_every_wire_format_here_is() {
        let mut cursor = Cursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        assert_eq!(cursor.u16(), Some(0x0102));
        assert_eq!(cursor.u24(), Some(0x0003_0405));
        assert_eq!(cursor.u32(), Some(0x0607_0809));
        assert!(cursor.is_empty());
    }

    #[test]
    fn seeking_beyond_the_sample_is_refused() {
        // DNS compression pointers are attacker chosen offsets, so the seek has
        // to be the place that rejects them rather than the caller.
        let mut cursor = Cursor::new(&[0x00, 0x01]);
        assert_eq!(cursor.seek(9), None);
        assert_eq!(cursor.at(), 0);
        assert_eq!(cursor.seek(2), Some(()));
        assert!(cursor.is_empty());
    }

    #[test]
    fn the_rest_of_an_exhausted_cursor_is_empty_rather_than_absent() {
        let mut cursor = Cursor::new(&[0x07]);
        assert_eq!(cursor.rest(), &[0x07]);
        assert_eq!(cursor.rest(), &[] as &[u8]);
    }
}
