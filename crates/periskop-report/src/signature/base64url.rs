//! base64url without padding, as the signature envelope contract requires.
//!
//! Written here rather than pulled in. This is an encoding, not cryptography, so
//! the rule in `CLAUDE.md` about never hand writing crypto does not reach it, and
//! the whole of it is pinned against the RFC 4648 §10 vectors below.
//!
//! One property matters more than compactness and is enforced on decode: a byte
//! string has exactly one spelling. Padding is rejected, non alphabet characters
//! are rejected, and the bits left over at the end of the last group must be
//! zero. Without that last check `Xw` and `Xx` would decode to the same byte, so
//! a signature value would have several spellings and an envelope could be
//! altered without changing what it verifies to.

use thiserror::Error;

/// RFC 4648 §5: the URL and filename safe alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Base64Error {
    #[error("base64url text has a length that no byte string encodes to")]
    Length,
    #[error("base64url text contains a character outside the unpadded URL safe alphabet")]
    Alphabet,
    #[error("base64url text carries non zero bits past the end of the decoded bytes")]
    TrailingBits,
}

/// Encodes bytes, no padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let (b0, b1, b2, produced) = match chunk {
            [a] => (*a, 0, 0, 2),
            [a, b] => (*a, *b, 0, 3),
            [a, b, c] => (*a, *b, *c, 4),
            // `chunks(3)` never yields anything else. Returning rather than
            // panicking keeps the production lint contract intact.
            _ => return out,
        };
        let group = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for shift in [18u32, 12, 6, 0].iter().take(produced) {
            // Masking with 63 makes the index provably in range for a 64 entry
            // table, so this cannot be made to fail by any input.
            let index = ((group >> shift) & 63) as usize;
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}

/// Decodes unpadded base64url, rejecting every spelling but the canonical one.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    // A group of one symbol carries six bits, which is not a byte and not
    // nothing. No byte string encodes to such a length.
    if text.len() % 4 == 1 {
        return Err(Base64Error::Length);
    }

    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for symbol in text.bytes() {
        let value = symbol_value(symbol).ok_or(Base64Error::Alphabet)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }

    if bits > 0 && (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(Base64Error::TrailingBits);
    }
    Ok(out)
}

/// The six bit value of one symbol, or `None` for anything outside the alphabet.
///
/// `=` is outside it on purpose: the contract says unpadded, and accepting the
/// padded spelling as well would give one signature two representations.
fn symbol_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// RFC 4648 §10, with the standard alphabet's `+` and `/` never arising in
    /// these particular vectors, so they hold for the URL safe alphabet too.
    #[test]
    fn the_rfc_vectors_encode_as_the_rfc_says() {
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                decode(encoded).unwrap(),
                plain.as_bytes(),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn the_url_safe_symbols_are_the_ones_in_use() {
        // 0xfb 0xff exercises both characters that differ from the standard
        // alphabet. A verifier that used `+` and `/` would reject a valid
        // envelope, which is a failure that looks like tampering.
        let encoded = encode(&[0xfb, 0xff]);
        assert_eq!(encoded, "-_8");
        assert_eq!(decode(&encoded).unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn padding_is_rejected() {
        assert_eq!(decode("Zg=="), Err(Base64Error::Alphabet));
    }

    #[test]
    fn a_character_outside_the_alphabet_is_rejected() {
        // Both spellings the standard alphabet uses and this one does not, plus a
        // space, at lengths that pass the length check so the alphabet check is
        // what actually fires.
        assert_eq!(decode("Zm9+"), Err(Base64Error::Alphabet));
        assert_eq!(decode("Zm9/"), Err(Base64Error::Alphabet));
        assert_eq!(decode("Zm9v YmFy"), Err(Base64Error::Length));
        assert_eq!(decode("Zm9v Fy"), Err(Base64Error::Alphabet));
    }

    #[test]
    fn an_impossible_length_is_rejected() {
        assert_eq!(decode("Z"), Err(Base64Error::Length));
        assert_eq!(decode("Zm9vY"), Err(Base64Error::Length));
    }

    #[test]
    fn a_second_spelling_of_the_same_bytes_is_rejected() {
        // `Zg` and `Zh` both carry the byte 0x66; the second sets bits that fall
        // outside it. Accepting both would let an envelope be edited without
        // changing what it decodes to.
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zh"), Err(Base64Error::TrailingBits));
    }

    #[test]
    fn every_byte_value_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }
}
