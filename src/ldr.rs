//! Checked parsing and transformation of original OP-1 Blackfin loader streams.

use crate::key::Key;
use anyhow::{bail, ensure, Context, Result};

const HEADER_BYTES: usize = 16;
const FILL: u16 = 0x0100;
const CALLBACK: u16 = 0x0400;
const INDIRECT: u16 = 0x2000;
const FINAL: u16 = 0x8000;

/// Counts describe active records up to and including FINAL, excluding the trailer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoaderReport {
    pub records: usize,
    /// Non-FILL records with a nonempty stored payload.
    pub payload_records: usize,
    pub fill_records: usize,
    pub encrypted_records: usize,
    /// Eight-byte XTEA units transformed.
    pub decrypted_units: usize,
    /// Units in a final partial 24-byte group, which the old tool skipped.
    pub encrypted_tail_units: usize,
    /// Byte offset of the FINAL header.
    pub final_offset: usize,
    /// Byte offset immediately after FINAL and its stored payload, if any.
    pub final_end: usize,
    pub trailer_bytes: usize,
}

#[derive(Debug)]
pub struct DecryptResult {
    pub bytes: Vec<u8>,
    pub report: LoaderReport,
}

/// Decrypt a loader without executing it or changing its layout.
///
/// Only CALLBACK is removed from supported encrypted records; INDIRECT remains
/// intact. Header checksums are repaired after that one flag change. Bytes after
/// FINAL are copied verbatim and are never interpreted as additional records.
///
/// Loader headers do not authenticate payload data or the supplied key. The
/// caller should compare a trusted plaintext hash when one is available.
pub fn decrypt_ldr(input: &[u8], key: Option<&Key>) -> Result<DecryptResult> {
    let mut bytes = input.to_vec();
    let mut report = LoaderReport::default();
    let mut offset = 0_usize;

    loop {
        if offset == input.len() {
            bail!(
                "loader ended without a FINAL record after {} records",
                report.records
            );
        }
        let payload_start = offset
            .checked_add(HEADER_BYTES)
            .context("loader header offset overflow")?;
        let header = input
            .get(offset..payload_start)
            .with_context(|| format!("truncated loader header at offset 0x{offset:x}"))?;
        ensure!(
            header[3] == 0xad,
            "invalid loader signature at offset 0x{offset:x}"
        );
        ensure!(
            header.iter().fold(0_u8, |sum, byte| sum ^ byte) == 0,
            "invalid loader header XOR checksum at offset 0x{offset:x}"
        );

        let flags = u16::from_le_bytes([header[0], header[1]]);
        let declared_count =
            u32::from_le_bytes(header[8..12].try_into().expect("validated header"));
        let is_fill = flags & FILL != 0;
        let has_callback = flags & CALLBACK != 0;
        if has_callback {
            ensure!(
                !is_fill && flags & INDIRECT != 0,
                "unsupported CALLBACK flags 0x{flags:04x} at offset 0x{offset:x}"
            );
        }

        let payload_len = if is_fill {
            0
        } else {
            usize::try_from(declared_count)
                .context("loader payload count exceeds addressable memory")?
        };
        let payload_end = payload_start
            .checked_add(payload_len)
            .context("loader payload offset overflow")?;
        ensure!(
            payload_end <= input.len(),
            "truncated loader payload at offset 0x{offset:x}: declared {payload_len} bytes, only {} remain",
            input.len() - payload_start
        );

        report.records += 1;
        if is_fill {
            report.fill_records += 1;
        } else if payload_len != 0 {
            report.payload_records += 1;
        }

        if has_callback {
            let key = key.with_context(|| {
                format!("a decryption key is required for CALLBACK record at offset 0x{offset:x}")
            })?;
            report.encrypted_records += 1;
            for group in bytes[payload_start..payload_end].chunks_mut(24) {
                if group.len() < 8 {
                    // Stock R246 contains four-byte callback payloads. An
                    // incomplete eight-byte unit is stored unchanged.
                    continue;
                }
                let encrypted = group[..8]
                    .try_into()
                    .expect("complete eight-byte XTEA unit");
                group[..8].copy_from_slice(&key.decrypt_block(encrypted));
                report.decrypted_units += 1;
                if group.len() < 24 {
                    report.encrypted_tail_units += 1;
                }
            }

            let header = &mut bytes[offset..payload_start];
            header[..2].copy_from_slice(&(flags & !CALLBACK).to_le_bytes());
            header[2] = 0;
            header[2] = header.iter().fold(0_u8, |sum, byte| sum ^ byte);
        }

        if flags & FINAL != 0 {
            report.final_offset = offset;
            report.final_end = payload_end;
            report.trailer_bytes = input.len() - payload_end;
            return Ok(DecryptResult { bytes, report });
        }
        offset = payload_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_CIPHER: [u8; 8] = [0xd8, 0xd4, 0xe9, 0xde, 0xd9, 0x1e, 0x13, 0xf7];

    fn header(flags: u16, address: u32, count: u32, argument: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES);
        bytes.extend(flags.to_le_bytes());
        bytes.extend([0, 0xad]);
        bytes.extend(address.to_le_bytes());
        bytes.extend(count.to_le_bytes());
        bytes.extend(argument.to_le_bytes());
        bytes[2] = bytes.iter().fold(0_u8, |sum, byte| sum ^ byte);
        bytes
    }

    fn final_record() -> Vec<u8> {
        header(0x8006, 0xffa0_0000, 0, 0)
    }

    fn zero_key() -> Key {
        Key::from_le_bytes([0; 16])
    }

    #[test]
    fn all_partial_group_lengths_and_tail_units_are_preserved_or_decrypted() {
        for length in 0..=80 {
            let mut encrypted = vec![0x5a; length];
            let mut plaintext = encrypted.clone();
            let mut units = 0;
            for (cipher, plain) in encrypted.chunks_mut(24).zip(plaintext.chunks_mut(24)) {
                if cipher.len() >= 8 {
                    cipher[..8].copy_from_slice(&ZERO_CIPHER);
                    plain[..8].fill(0);
                    units += 1;
                }
            }
            let mut input = header(0x2406, 0xff90_021c, length as u32, 0x1234_abcd);
            input.extend(encrypted);
            input.extend(final_record());
            let mut expected = header(0x2006, 0xff90_021c, length as u32, 0x1234_abcd);
            expected.extend(plaintext);
            expected.extend(final_record());

            let result = decrypt_ldr(&input, Some(&zero_key())).unwrap();
            assert_eq!(result.bytes, expected, "payload length {length}");
            assert_eq!(
                result.report.decrypted_units, units,
                "payload length {length}"
            );
            assert_eq!(result.report.encrypted_records, 1);
            assert_eq!(
                result.report.encrypted_tail_units,
                usize::from(length % 24 >= 8)
            );
            assert_eq!(result.report.final_offset, HEADER_BYTES + length);
            assert_eq!(result.report.final_end, 2 * HEADER_BYTES + length);
        }
    }

    #[test]
    fn stride_restarts_for_each_record_and_indirect_flag_survives() {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for address in [0xff80_0000, 0xff90_0000] {
            input.extend(header(0x2406, address, 16, 0));
            input.extend(ZERO_CIPHER);
            input.extend([0x5a; 8]);
            expected.extend(header(0x2006, address, 16, 0));
            expected.extend([0; 8]);
            expected.extend([0x5a; 8]);
        }
        input.extend(final_record());
        expected.extend(final_record());
        let result = decrypt_ldr(&input, Some(&zero_key())).unwrap();
        assert_eq!(result.bytes, expected);
        assert_eq!(result.report.encrypted_records, 2);
        assert_eq!(result.report.encrypted_tail_units, 2);
        assert_eq!(result.report.decrypted_units, 2);
    }

    #[test]
    fn first_metadata_and_unaligned_fill_are_not_normalized() {
        let mut input = header(0x5006, 0xffa0_0000, 0, 0x2122d8);
        input.extend(header(0x0106, 0x0300_0000, 0x3ffff, 0x1122_3344));
        input.extend(header(0x0106, 0x0300_0000, u32::MAX, 0));
        input.extend(final_record());
        let result = decrypt_ldr(&input, None).unwrap();
        assert_eq!(result.bytes, input);
        assert_eq!(result.report.records, 4);
        assert_eq!(result.report.fill_records, 2);
        assert_eq!(result.report.payload_records, 0);
    }

    #[test]
    fn final_payload_is_kept_and_trailer_is_opaque() {
        let mut input = header(0x8006, 0x0100_0000, 4, 0);
        input.extend([1, 2, 3, 4]);
        let trailer_start = input.len();
        input.extend(header(0x2406, 0xff90_0000, u32::MAX, 0));
        input.extend([0xff; 11]);
        let result = decrypt_ldr(&input, None).unwrap();
        assert_eq!(result.bytes, input);
        assert_eq!(result.report.records, 1);
        assert_eq!(result.report.encrypted_records, 0);
        assert_eq!(result.report.final_offset, 0);
        assert_eq!(result.report.final_end, trailer_start);
        assert_eq!(result.report.trailer_bytes, 27);
    }

    #[test]
    fn second_decryption_is_a_byte_identical_no_op_without_a_key() {
        let mut input = header(0x2406, 0xff90_0000, 8, 0);
        input.extend(ZERO_CIPHER);
        input.extend(final_record());
        input.extend([0x71; 256]);
        let first = decrypt_ldr(&input, Some(&zero_key())).unwrap();
        let second = decrypt_ldr(&first.bytes, None).unwrap();
        assert_eq!(second.bytes, first.bytes);
        assert_eq!(second.report.encrypted_records, 0);
        assert_eq!(second.report.trailer_bytes, 256);
    }

    #[test]
    fn rejects_bad_headers_and_missing_final() {
        for length in 0..HEADER_BYTES {
            assert!(decrypt_ldr(&final_record()[..length], None).is_err());
        }
        let mut signature = final_record();
        signature[3] = 0xae;
        assert!(decrypt_ldr(&signature, None)
            .unwrap_err()
            .to_string()
            .contains("signature"));
        let mut checksum = final_record();
        checksum[2] ^= 1;
        assert!(decrypt_ldr(&checksum, None)
            .unwrap_err()
            .to_string()
            .contains("checksum"));
        let no_final = header(0x0006, 0x0100_0000, 0, 0);
        assert!(decrypt_ldr(&no_final, None)
            .unwrap_err()
            .to_string()
            .contains("without a FINAL"));
    }

    #[test]
    fn rejects_payload_overruns_and_unknown_callback_shapes() {
        let mut truncated = header(0x0006, 0x0100_0000, u32::MAX, 0);
        truncated.extend([1, 2, 3, 4]);
        assert!(decrypt_ldr(&truncated, None)
            .unwrap_err()
            .to_string()
            .contains("truncated loader payload"));
        for flags in [0x0406, 0x2506] {
            let mut unsupported = header(flags, 0xff90_0000, 0, 0);
            unsupported.extend(final_record());
            assert!(decrypt_ldr(&unsupported, Some(&zero_key()))
                .unwrap_err()
                .to_string()
                .contains("unsupported CALLBACK"));
        }
    }

    #[test]
    fn callback_requires_a_key_even_if_the_payload_has_no_complete_unit() {
        let mut input = header(0x2406, 0xff80_0000, 4, 0);
        input.extend([0x12; 4]);
        input.extend(final_record());
        assert!(decrypt_ldr(&input, None)
            .unwrap_err()
            .to_string()
            .contains("a decryption key is required"));
        let result = decrypt_ldr(&input, Some(&zero_key())).unwrap();
        assert_eq!(result.report.encrypted_records, 1);
        assert_eq!(result.report.decrypted_units, 0);
    }
}
