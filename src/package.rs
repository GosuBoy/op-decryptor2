//! Bounded decoding of CRC32 + LZMA-alone + TAR update packages.

use std::io::{self, Cursor, Read, Write};

use anyhow::{bail, ensure, Context, Result};

pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LDR_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_DICTIONARY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFormat {
    Auto,
    Op1,
    Ldr,
}

#[derive(Debug)]
pub struct ExtractedLoader {
    pub bytes: Vec<u8>,
    /// The resolved format; never Auto.
    pub format: InputFormat,
    pub package_crc32: Option<u32>,
}

/// Extract just the main loader in memory. TAR paths are never written to disk.
pub fn extract_loader(input: &[u8], format: InputFormat) -> Result<ExtractedLoader> {
    ensure!(
        input.len() <= MAX_INPUT_BYTES,
        "input exceeds the 64 MiB limit"
    );
    let format = match format {
        InputFormat::Auto => {
            // A package CRC's high byte can also be 0xad. Prefer a verified
            // container CRC before considering a complete loader header.
            let package_crc_matches = input.len() >= 17
                && input[4] < 225
                && u32::from_le_bytes(input[..4].try_into()?) == crc32fast::hash(&input[4..]);
            let loader_header_matches = input.len() >= 16
                && input[3] == 0xad
                && input[..16].iter().fold(0_u8, |xor, byte| xor ^ byte) == 0;
            if !package_crc_matches && loader_header_matches {
                InputFormat::Ldr
            } else {
                InputFormat::Op1
            }
        }
        explicit => explicit,
    };
    match format {
        InputFormat::Ldr => Ok(ExtractedLoader {
            bytes: input.to_vec(),
            format,
            package_crc32: None,
        }),
        InputFormat::Op1 => {
            ensure!(
                input.len() >= 17,
                "OP-1 package is shorter than its CRC32 and LZMA headers"
            );
            let expected = u32::from_le_bytes(input[..4].try_into()?);
            let compressed = &input[4..];
            let actual = crc32fast::hash(compressed);
            ensure!(
                actual == expected,
                "package CRC32 mismatch: stored {expected:08x}, calculated {actual:08x}"
            );
            let archive = decompress_archive(compressed, MAX_ARCHIVE_BYTES)?;
            let bytes = main_loader_from_tar(&archive)?;
            Ok(ExtractedLoader {
                bytes,
                format,
                package_crc32: Some(actual),
            })
        }
        InputFormat::Auto => unreachable!("format was resolved above"),
    }
}

fn decompress_archive(compressed: &[u8], limit: usize) -> Result<Vec<u8>> {
    ensure!(compressed.len() >= 13, "truncated LZMA-alone header");
    ensure!(compressed[0] < 225, "invalid LZMA properties byte");
    let dictionary = u32::from_le_bytes(compressed[1..5].try_into()?) as usize;
    ensure!(
        dictionary <= MAX_DICTIONARY_BYTES,
        "LZMA dictionary exceeds the 64 MiB limit"
    );
    let declared = u64::from_le_bytes(compressed[5..13].try_into()?);
    ensure!(
        declared == u64::MAX || declared <= limit as u64,
        "declared LZMA output exceeds the decompression limit"
    );
    let options = lzma_rs::decompress::Options {
        memlimit: Some(MAX_DICTIONARY_BYTES),
        ..Default::default()
    };
    let mut input = Cursor::new(compressed);
    let mut output = LimitedBuffer {
        bytes: Vec::new(),
        limit,
    };
    lzma_rs::lzma_decompress_with_options(&mut input, &mut output, &options)
        .context("invalid or truncated LZMA-alone stream")?;
    ensure!(
        input.position() == compressed.len() as u64,
        "unexpected data after the LZMA stream"
    );
    Ok(output.bytes)
}

fn main_loader_from_tar(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() % 512 == 0,
        "TAR archive is not a multiple of 512 bytes"
    );
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut selected = None;
    for entry in archive.entries().context("cannot read TAR archive")? {
        let mut entry = entry.context("invalid TAR entry")?;
        let path = entry.path_bytes();
        let mut name = path.as_ref();
        while let Some(rest) = name.strip_prefix(b"./") {
            name = rest;
        }
        if name != b"OP1_vdk.ldr" {
            continue;
        }
        ensure!(
            selected.is_none(),
            "TAR contains more than one OP1_vdk.ldr member"
        );
        ensure!(
            entry.header().entry_type().is_file(),
            "OP1_vdk.ldr is not a regular file"
        );
        let size = entry.size();
        ensure!(
            size <= MAX_LDR_BYTES as u64,
            "OP1_vdk.ldr exceeds the 64 MiB limit"
        );
        let mut loader = Vec::new();
        entry
            .by_ref()
            .take(MAX_LDR_BYTES as u64 + 1)
            .read_to_end(&mut loader)
            .context("truncated OP1_vdk.ldr TAR member")?;
        ensure!(
            loader.len() as u64 == size,
            "truncated OP1_vdk.ldr TAR member"
        );
        selected = Some(loader);
    }
    let cursor = archive.into_inner();
    let offset = usize::try_from(cursor.position())?;
    // tar stops after the first zero header. Require a second zero block and
    // zero padding so a second hidden archive cannot silently select a member.
    ensure!(
        offset <= bytes.len() && bytes.len() - offset >= 512,
        "TAR is missing its end markers"
    );
    ensure!(
        bytes[offset..].iter().all(|&b| b == 0),
        "nonzero data after the TAR end marker"
    );
    match selected {
        Some(loader) => Ok(loader),
        None => bail!("TAR does not contain a root OP1_vdk.ldr member"),
    }
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "decompressed archive exceeds the size limit",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn package(archive: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        lzma_rs::lzma_compress(&mut Cursor::new(archive), &mut compressed).unwrap();
        let mut result = crc32fast::hash(&compressed).to_le_bytes().to_vec();
        result.extend_from_slice(&compressed);
        result
    }

    #[test]
    fn extracts_only_main_loader_from_old_gnu_archive() {
        let input = package(&archive(&[
            ("te-boot.ldr", b"boot"),
            ("./OP1_vdk.ldr", b"main"),
        ]));
        let result = extract_loader(&input, InputFormat::Auto).unwrap();
        assert_eq!(result.bytes, b"main");
        assert_eq!(result.format, InputFormat::Op1);
        assert!(result.package_crc32.is_some());
    }

    #[test]
    fn package_crc_high_byte_is_not_mistaken_for_a_loader_signature() {
        let mut input = package(&archive(&[("OP1_vdk.ldr", b"main")]));
        let original_dictionary = u32::from_le_bytes(input[5..9].try_into().unwrap());
        // A slightly larger valid dictionary changes the CRC, without changing
        // any decompressed bytes. Find one whose stored CRC ends in 0xad.
        for extra in 0..=65_535 {
            input[5..9].copy_from_slice(&(original_dictionary + extra).to_le_bytes());
            let crc = crc32fast::hash(&input[4..]);
            if crc >> 24 == 0xad {
                input[..4].copy_from_slice(&crc.to_le_bytes());
                let result = extract_loader(&input, InputFormat::Auto).unwrap();
                assert_eq!(result.format, InputFormat::Op1);
                assert_eq!(result.bytes, b"main");
                return;
            }
        }
        panic!("synthetic dictionary variants did not produce a 0xad CRC prefix");
    }

    #[test]
    fn rejects_corrupt_crc_before_decompressing() {
        let mut input = package(&archive(&[("OP1_vdk.ldr", b"main")]));
        *input.last_mut().unwrap() ^= 1;
        assert!(extract_loader(&input, InputFormat::Op1)
            .unwrap_err()
            .to_string()
            .contains("CRC32"));
    }

    #[test]
    fn rejects_duplicate_and_missing_members() {
        assert!(
            main_loader_from_tar(&archive(&[("OP1_vdk.ldr", b"a"), ("./OP1_vdk.ldr", b"b")]))
                .is_err()
        );
        assert!(main_loader_from_tar(&archive(&[("other/OP1_vdk.ldr", b"a")])).is_err());
    }

    #[test]
    fn rejects_symlink_as_main_loader() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_link_name("outside").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "OP1_vdk.ldr", io::empty())
            .unwrap();
        assert!(main_loader_from_tar(&builder.into_inner().unwrap()).is_err());
    }

    #[test]
    fn rejects_truncated_and_corrupt_tar() {
        let bytes = archive(&[("OP1_vdk.ldr", b"main")]);
        assert!(main_loader_from_tar(&bytes[..512]).is_err());
        assert!(main_loader_from_tar(&bytes[..bytes.len() - 1]).is_err());
        let mut broken = bytes.clone();
        broken[0] ^= 1;
        assert!(main_loader_from_tar(&broken).is_err());
        let mut trailing = bytes;
        *trailing.last_mut().unwrap() = 1;
        assert!(main_loader_from_tar(&trailing).is_err());
    }

    #[test]
    fn bounded_decoder_rejects_oversized_output_and_dictionary() {
        let input = package(&archive(&[("OP1_vdk.ldr", b"main")]));
        assert!(decompress_archive(&input[4..], 512).is_err());
        let mut compressed = input[4..].to_vec();
        compressed[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decompress_archive(&compressed, MAX_ARCHIVE_BYTES)
            .unwrap_err()
            .to_string()
            .contains("dictionary"));
    }

    #[test]
    fn rejects_truncated_compressed_stream_even_with_correct_crc() {
        let mut input = package(&archive(&[("OP1_vdk.ldr", b"main")]));
        input.truncate(input.len() - 6);
        let crc = crc32fast::hash(&input[4..]);
        input[..4].copy_from_slice(&crc.to_le_bytes());
        assert!(extract_loader(&input, InputFormat::Op1).is_err());
    }
}
