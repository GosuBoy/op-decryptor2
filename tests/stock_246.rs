//! Optional regression test against locally supplied firmware and key material.
//! No proprietary firmware or device keys are included in the repository.

use std::{env, fs, process::Command};

use op_decryptor2::{
    decrypt_ldr, extract_loader, sha256, InputFormat, Key, ENCRYPTED_246_SHA256,
    PLAINTEXT_246_SHA256, STOCK_246_SHA256,
};
use tempfile::TempDir;

#[test]
#[ignore = "requires OP1_FIRMWARE_246 and OP1_KEY_FILE pointing to local files"]
fn stock_246_matches_the_canonical_plaintext_and_cli_rejects_a_wrong_key() {
    let package_path = env::var_os("OP1_FIRMWARE_246")
        .expect("set OP1_FIRMWARE_246 to the official op1_246.op1 path");
    let key_path =
        env::var_os("OP1_KEY_FILE").expect("set OP1_KEY_FILE to a local 32-hex-digit key file");
    let package = fs::read(&package_path).expect("read local firmware");
    assert_eq!(package.len(), 13_039_128);
    assert_eq!(sha256(&package), STOCK_246_SHA256);

    let extracted = extract_loader(&package, InputFormat::Auto).unwrap();
    assert_eq!(extracted.format, InputFormat::Op1);
    assert_eq!(extracted.package_crc32, Some(0xcc08_445c));
    assert_eq!(sha256(&extracted.bytes), ENCRYPTED_246_SHA256);
    let text = fs::read_to_string(key_path).expect("read local key file");
    let key = Key::from_hex(text.trim()).expect("parse key without publishing it");
    let result = decrypt_ldr(&extracted.bytes, Some(&key)).unwrap();

    assert_eq!(result.bytes.len(), 2_171_624);
    assert_eq!(sha256(&result.bytes), PLAINTEXT_246_SHA256);
    assert_eq!(result.report.records, 800);
    assert_eq!(result.report.payload_records, 385);
    assert_eq!(result.report.fill_records, 413);
    assert_eq!(result.report.encrypted_records, 45);
    assert_eq!(result.report.decrypted_units, 3_358);
    assert_eq!(result.report.encrypted_tail_units, 30);
    assert_eq!(result.report.final_offset, 2_171_352);
    assert_eq!(result.report.final_end, 2_171_368);
    assert_eq!(result.report.trailer_bytes, 256);
    assert_eq!(&result.bytes[..16], &extracted.bytes[..16]);
    assert_eq!(
        &result.bytes[result.report.final_end..],
        &extracted.bytes[result.report.final_end..]
    );
    assert_eq!(
        decrypt_ldr(&result.bytes, None).unwrap().bytes,
        result.bytes
    );

    // Header checks alone cannot detect a wrong key. The CLI must use its known
    // stock baseline to reject a wrong decryption before writing any output.
    let directory = TempDir::new().unwrap();
    let source = directory.path().join("stock.ldr");
    let output = directory.path().join("wrong.ldr");
    fs::write(&source, &extracted.bytes).unwrap();
    let wrong = Command::new(env!("CARGO_BIN_EXE_op-decryptor2"))
        .arg(source)
        .arg("--key")
        .arg("00000000000000000000000000000000")
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(!output.exists());
}
