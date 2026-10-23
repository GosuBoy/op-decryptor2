//! XTEA key parsing and the original OP-1's little-endian block transform.

use anyhow::{bail, ensure, Result};
use std::fmt;

/// Four XTEA key words. Debug formatting deliberately hides their contents.
#[derive(Clone)]
pub struct Key([u32; 4]);

impl Key {
    /// Parse four consecutive eight-digit hexadecimal words.
    ///
    /// This is the historical decryptor's command-line convention, also used by
    /// the printed OTP page. It differs from a raw little-endian memory dump.
    pub fn from_hex(text: &str) -> Result<Self> {
        ensure!(
            text.len() == 32,
            "key must contain exactly 32 hexadecimal digits"
        );
        let mut bytes = [0_u8; 16];
        for (output, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            *output = (high << 4) | low;
        }
        let mut words = [0_u32; 4];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four-byte key word"));
        }
        Ok(Self(words))
    }

    /// Read four words from their little-endian in-memory representation.
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        let mut words = [0_u32; 4];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().expect("four-byte key word"));
        }
        Self(words)
    }

    /// Read page 0xd0 from a textual OTP dump.
    ///
    /// The expected line is `!0xd0 <16 hex digits> <16 hex digits>`. The leading
    /// `!` is optional; the two printed words are concatenated in display order.
    /// Other pages are ignored, and duplicate or malformed page 0xd0 entries
    /// are rejected instead of choosing one silently.
    pub fn from_otp_text(text: &str) -> Result<Self> {
        let mut found = None;
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let Some(page) = fields.first() else {
                continue;
            };
            let page = page.strip_prefix('!').unwrap_or(page);
            if !page.eq_ignore_ascii_case("0xd0") {
                continue;
            }
            ensure!(
                found.is_none(),
                "OTP dump contains duplicate page 0xd0 entries"
            );
            ensure!(
                fields.len() == 3 && fields[1].len() == 16 && fields[2].len() == 16,
                "OTP page 0xd0 must contain exactly two 16-digit hexadecimal words"
            );
            found = Some(Self::from_hex(&format!("{}{}", fields[1], fields[2]))?);
        }
        found.ok_or_else(|| anyhow::anyhow!("OTP dump does not contain page 0xd0"))
    }

    pub(crate) fn decrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        let mut left = u32::from_le_bytes(block[..4].try_into().expect("left word"));
        let mut right = u32::from_le_bytes(block[4..].try_into().expect("right word"));
        let delta = 0x9e37_79b9_u32;
        let mut sum = delta.wrapping_mul(32);
        for _ in 0..32 {
            right = right
                .wrapping_sub(mix(left) ^ sum.wrapping_add(self.0[((sum >> 11) & 3) as usize]));
            sum = sum.wrapping_sub(delta);
            left = left.wrapping_sub(mix(right) ^ sum.wrapping_add(self.0[(sum & 3) as usize]));
        }
        let mut output = [0_u8; 8];
        output[..4].copy_from_slice(&left.to_le_bytes());
        output[4..].copy_from_slice(&right.to_le_bytes());
        output
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key([redacted])")
    }
}

fn mix(word: u32) -> u32 {
    ((word << 4) ^ (word >> 5)).wrapping_add(word)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("key contains a non-hexadecimal character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent XTEA known-answer values from LibTomCrypt's xtea_test:
    // https://github.com/libtom/libtomcrypt/blob/develop/src/ciphers/xtea.c
    // That source prints big-endian words; the OP-1 stores each word little-endian.
    #[test]
    fn independent_known_answer_vectors() {
        let vectors = [
            (
                "00000000000000000000000000000000",
                [0xd8, 0xd4, 0xe9, 0xde, 0xd9, 0x1e, 0x13, 0xf7],
                [0_u8; 8],
            ),
            (
                "00000001000000020000000300000004",
                [0x41, 0xab, 0x97, 0xa5, 0x72, 0x4d, 0x01, 0x76],
                [0_u8; 8],
            ),
            (
                "00000003000000040000000500000006",
                [0xa9, 0x5d, 0xfd, 0xb1, 0xdc, 0xc9, 0x6d, 0xcc],
                [1, 0, 0, 0, 2, 0, 0, 0],
            ),
        ];
        for (text, encrypted, plaintext) in vectors {
            assert_eq!(
                Key::from_hex(text).unwrap().decrypt_block(encrypted),
                plaintext
            );
        }
    }

    #[test]
    fn raw_memory_and_text_use_explicit_word_byte_orders() {
        let text = Key::from_hex("00000001000000020000000300000004").unwrap();
        let raw = Key::from_le_bytes([1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]);
        let encrypted = [0x41, 0xab, 0x97, 0xa5, 0x72, 0x4d, 0x01, 0x76];
        assert_eq!(text.decrypt_block(encrypted), raw.decrypt_block(encrypted));
        assert_eq!(text.decrypt_block(encrypted), [0; 8]);
    }

    #[test]
    fn rejects_bad_key_text_without_echoing_it() {
        for text in [
            "",
            "0000000000000000000000000000000",
            "000000000000000000000000000000000",
            "0000000000000000000000000000000g",
            "0000000000000000000000000000000 ",
            "éééééééééééééééé",
        ] {
            assert!(Key::from_hex(text).is_err());
        }
        assert_eq!(
            format!("{:?}", Key::from_le_bytes([0xff; 16])),
            "Key([redacted])"
        );
    }

    #[test]
    fn accepts_uppercase_hexadecimal() {
        assert_eq!(
            Key::from_hex("00112233445566778899AABBCCDDEEFF")
                .unwrap()
                .decrypt_block([0; 8]),
            Key::from_hex("00112233445566778899aabbccddeeff")
                .unwrap()
                .decrypt_block([0; 8]),
        );
    }

    #[test]
    fn otp_page_uses_display_order_and_ignores_other_pages() {
        let dump =
            "\n!0xcf invalid ignored\n!0xD0 0000000100000002 0000000300000004\n0xd1 ignored\n";
        let encrypted = [0x41, 0xab, 0x97, 0xa5, 0x72, 0x4d, 0x01, 0x76];
        assert_eq!(
            Key::from_otp_text(dump).unwrap().decrypt_block(encrypted),
            [0; 8]
        );
        assert_eq!(
            Key::from_otp_text("0xd0 0000000100000002 0000000300000004")
                .unwrap()
                .decrypt_block(encrypted),
            [0; 8]
        );
    }

    #[test]
    fn rejects_missing_malformed_and_duplicate_otp_pages() {
        for dump in [
            "",
            "!0xd1 0000000100000002 0000000300000004",
            "!0xd0",
            "!0xd0 0000000100000002",
            "!0xd0 0000000100000002 0000000300000004 extra",
            "!0xd0 000000010000000 20000000300000004",
            "!0xd0 0000000100000002 000000030000000z",
            "!0xd0 0000000100000002 0000000300000004\n0xD0 0000000100000002 0000000300000004",
            "!0xd0 0000000100000002 0000000300000004\n0xD0 malformed",
        ] {
            assert!(Key::from_otp_text(dump).is_err());
        }
    }
}
