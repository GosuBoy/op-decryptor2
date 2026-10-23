//! Offline decryption of original Teenage Engineering OP-1 firmware.
//!
//! The output is an LDR stream, including its original opaque trailer. It is
//! neither a flat memory image nor a firmware update package.

pub mod key;
pub mod ldr;
pub mod package;

pub use key::Key;
pub use ldr::{decrypt_ldr, DecryptResult, LoaderReport};
pub use package::{extract_loader, ExtractedLoader, InputFormat};

use sha2::{Digest, Sha256};

/// SHA-256 of the official original OP-1 firmware 246 update package.
pub const STOCK_246_SHA256: &str =
    "c5315218f825f143b415ca554516541898abee843d3a236df0b54c04e1fb13a9";

/// SHA-256 of the encrypted OP1_vdk.ldr member from the stock 246 package.
pub const ENCRYPTED_246_SHA256: &str =
    "f79d299f6f9019c998013a4176223a6a1bc999a2d8c54451346861f6ea455c74";

/// SHA-256 of the established plaintext, with INDIRECT flags and trailer intact.
pub const PLAINTEXT_246_SHA256: &str =
    "1e806672dc440d495987c6b1f33b300876e6a3bb1d58254aac5fe60c960e906a";

/// Lowercase hexadecimal SHA-256 digest.
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
