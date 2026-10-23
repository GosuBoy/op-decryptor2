//! Filesystem and CLI behavior, using entirely synthetic loader data.

use std::{fs, io::Cursor, path::Path, process::Command};

use op_decryptor2::sha256;
use tempfile::TempDir;

const TEST_KEY: &str = "00000001000000020000000300000004";
// LibTomCrypt XTEA known-answer vector: zero plaintext under words [1, 2, 3, 4].
// OP-1 payload words are little-endian.
const CIPHER: [u8; 8] = [0x41, 0xab, 0x97, 0xa5, 0x72, 0x4d, 0x01, 0x76];

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_op-decryptor2"))
}

fn header(flags: u16, address: u32, count: u32, argument: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(flags.to_le_bytes());
    bytes.extend([0, 0xad]);
    bytes.extend(address.to_le_bytes());
    bytes.extend(count.to_le_bytes());
    bytes.extend(argument.to_le_bytes());
    bytes[2] = bytes.iter().fold(0, |xor, byte| xor ^ byte);
    bytes
}

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let first = header(0x5006, 0xffa0_0000, 0, 0x1234_5678);
    let mut encrypted = first.clone();
    let mut plaintext = first;
    encrypted.extend(header(0x2406, 0xff90_0000, 32, 0xdead_beef));
    plaintext.extend(header(0x2006, 0xff90_0000, 32, 0xdead_beef));
    encrypted.extend(CIPHER);
    plaintext.extend([0; 8]);
    encrypted.extend([0x5a; 16]);
    plaintext.extend([0x5a; 16]);
    // A complete eight-byte encrypted tail remains after the first 24-byte group.
    encrypted.extend(CIPHER);
    plaintext.extend([0; 8]);
    for bytes in [&mut encrypted, &mut plaintext] {
        bytes.extend(header(0x0106, 0x0300_0000, 0x3ffff, 0));
        bytes.extend(header(0x8006, 0xffa0_0000, 0, 0));
        // The trailer deliberately resembles an unsupported callback record.
        bytes.extend(header(0x0406, 0, u32::MAX, 0));
        bytes.extend([0xe7; 240]);
    }
    (encrypted, plaintext)
}

fn input(directory: &Path, bytes: &[u8], name: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn package(loader: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("te-boot.ldr", b"unchanged bootloader".as_slice()),
        ("./OP1_vdk.ldr", loader),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    let archive = builder.into_inner().unwrap();
    let mut compressed = Vec::new();
    lzma_rs::lzma_compress(&mut Cursor::new(archive), &mut compressed).unwrap();
    let mut result = crc32fast::hash(&compressed).to_le_bytes().to_vec();
    result.extend(compressed);
    result
}

#[test]
fn decrypts_raw_loader_with_key_file_and_preserves_input() {
    let directory = TempDir::new().unwrap();
    let (encrypted, expected) = fixture();
    let source = input(directory.path(), &encrypted, "source.ldr");
    let key = input(
        directory.path(),
        format!(" \n{TEST_KEY}\n").as_bytes(),
        "key.txt",
    );
    let destination = directory.path().join("result.ldr");
    let result = cli()
        .arg(&source)
        .arg("--key-file")
        .arg(&key)
        .arg("--output")
        .arg(&destination)
        .arg("--expect-sha256")
        .arg(sha256(&expected))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(destination).unwrap(), expected);
    assert_eq!(fs::read(source).unwrap(), encrypted);
    assert!(!String::from_utf8_lossy(&result.stdout).contains(TEST_KEY));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(TEST_KEY));
}

#[test]
fn decrypts_full_package_with_otp_text_and_default_output_name() {
    let directory = TempDir::new().unwrap();
    let (encrypted, expected) = fixture();
    let source = input(directory.path(), &package(&encrypted), "update.op1");
    let dump = input(
        directory.path(),
        b"!0xcf ignored\n!0xd0 0000000100000002 0000000300000004\n",
        "otp.txt",
    );
    let result = cli()
        .current_dir(directory.path())
        .arg(&source)
        .arg("--otp-dump")
        .arg(&dump)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(directory.path().join("plaintext.ldr")).unwrap(),
        expected
    );
    assert!(!directory.path().join("te-boot.ldr").exists());
}

#[test]
fn plaintext_is_an_identical_pass_through_without_a_key() {
    let directory = TempDir::new().unwrap();
    let (_, plaintext) = fixture();
    let source = input(directory.path(), &plaintext, "source.ldr");
    let destination = directory.path().join("result.ldr");
    let result = cli()
        .arg(source)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(destination).unwrap(), plaintext);
}

#[test]
fn missing_or_wrong_key_does_not_create_output() {
    let directory = TempDir::new().unwrap();
    let (encrypted, expected) = fixture();
    let source = input(directory.path(), &encrypted, "source.ldr");
    let destination = directory.path().join("result.ldr");
    let missing = cli()
        .arg(&source)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(!destination.exists());

    let wrong = cli()
        .arg(source)
        .arg("--key")
        .arg("00000000000000000000000000000000")
        .arg("--expect-sha256")
        .arg(sha256(&expected))
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(!destination.exists());
}

#[test]
fn malformed_loader_and_package_leave_no_output() {
    let directory = TempDir::new().unwrap();
    let (mut encrypted, _) = fixture();
    encrypted[2] ^= 1;
    let source = input(directory.path(), &encrypted, "bad.ldr");
    let destination = directory.path().join("result.ldr");
    let result = cli()
        .arg(source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--format")
        .arg("ldr")
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!destination.exists());

    let (encrypted, _) = fixture();
    let mut damaged = package(&encrypted);
    damaged[0] ^= 1;
    let source = input(directory.path(), &damaged, "bad.op1");
    let result = cli()
        .arg(source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!destination.exists());
}

#[test]
fn existing_output_requires_force_and_failed_validation_preserves_it() {
    let directory = TempDir::new().unwrap();
    let (encrypted, expected) = fixture();
    let source = input(directory.path(), &encrypted, "source.ldr");
    let sentinel = b"previous output must survive failures";
    let destination = input(directory.path(), sentinel, "result.ldr");

    let result = cli()
        .arg(&source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&destination).unwrap(), sentinel);

    let result = cli()
        .arg(&source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--expect-sha256")
        .arg("00".repeat(32))
        .arg("--force")
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&destination).unwrap(), sentinel);

    let result = cli()
        .arg(source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--force")
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(destination).unwrap(), expected);
}

#[test]
fn refuses_to_replace_the_input_even_with_force() {
    let directory = TempDir::new().unwrap();
    let (encrypted, _) = fixture();
    let source = input(directory.path(), &encrypted, "source.ldr");
    let result = cli()
        .arg(&source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--force")
        .arg("--output")
        .arg(&source)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(source).unwrap(), encrypted);
}

#[test]
fn conflicting_key_sources_and_invalid_key_files_fail_without_output() {
    let directory = TempDir::new().unwrap();
    let (encrypted, _) = fixture();
    let source = input(directory.path(), &encrypted, "source.ldr");
    let key = input(directory.path(), b"not-a-valid-key", "key.txt");
    let destination = directory.path().join("result.ldr");
    let conflicting = cli()
        .arg(&source)
        .arg("--key")
        .arg(TEST_KEY)
        .arg("--key-file")
        .arg(&key)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!conflicting.status.success());
    assert!(!destination.exists());
    let invalid = cli()
        .arg(&source)
        .arg("--key-file")
        .arg(&key)
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(!destination.exists());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("not-a-valid-key"));
}
