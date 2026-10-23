use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, ensure, Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};
use op_decryptor2::{
    decrypt_ldr, extract_loader, package::MAX_INPUT_BYTES, sha256, InputFormat, Key,
    ENCRYPTED_246_SHA256, PLAINTEXT_246_SHA256,
};

#[derive(Parser)]
#[command(version, about = "Decrypt original OP-1 firmware into plaintext.ldr")]
#[command(group(ArgGroup::new("key_source").args(["key", "key_file", "otp_dump"]).multiple(false)))]
#[command(
    after_help = "Examples:\n  op-decryptor2 op1_246.op1 --key-file key.txt\n  op-decryptor2 OP1_vdk.ldr --otp-dump otp.txt -o plaintext.ldr\n\nKey files contain 32 hexadecimal digits: four 32-bit words in display order.\nOTP dumps use the text format documented in the README. No key is bundled."
)]
struct Args {
    /// A complete .op1 update or an extracted Blackfin .ldr stream
    input: PathBuf,

    /// Destination for the complete plaintext loader, including its trailer
    #[arg(short, long, default_value = "plaintext.ldr")]
    output: PathBuf,

    /// 128-bit key as 32 hexadecimal digits (prefer --key-file)
    #[arg(long, value_name = "HEX")]
    key: Option<String>,

    /// File containing the 32 hexadecimal digits of the key
    #[arg(long, value_name = "PATH")]
    key_file: Option<PathBuf>,

    /// Text OTP dump with a page 0xd0 line containing two 64-bit hex words
    #[arg(long, value_name = "PATH")]
    otp_dump: Option<PathBuf>,

    /// Override input detection
    #[arg(long, value_enum, default_value = "auto")]
    format: Format,

    /// Require this plaintext SHA-256 before writing any output
    #[arg(long, value_name = "HEX", value_parser = parse_sha256)]
    expect_sha256: Option<String>,

    /// Atomically replace an existing output file
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Auto,
    Op1,
    Ldr,
}

impl From<Format> for InputFormat {
    fn from(value: Format) -> Self {
        match value {
            Format::Auto => Self::Auto,
            Format::Op1 => Self::Op1,
            Format::Ldr => Self::Ldr,
        }
    }
}

fn parse_sha256(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected exactly 64 hexadecimal digits".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let metadata = file.metadata().context("cannot inspect input file")?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.len() <= limit as u64,
        "{} exceeds the {limit}-byte limit",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the {limit}-byte limit",
        path.display()
    );
    Ok(bytes)
}

fn read_key(args: &Args) -> Result<Option<Key>> {
    if let Some(hex) = &args.key {
        return Key::from_hex(hex).map(Some);
    }
    if let Some(path) = &args.key_file {
        let bytes = read_bounded(path, 1024)?;
        let text =
            std::str::from_utf8(&bytes).context("key file must be UTF-8 hexadecimal text")?;
        return Key::from_hex(text.trim()).map(Some);
    }
    if let Some(path) = &args.otp_dump {
        let bytes = read_bounded(path, 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes)
            .context("OTP dump must use the documented UTF-8 text format")?;
        return Key::from_otp_text(text).map(Some);
    }
    Ok(None)
}

fn validate_destination(args: &Args) -> Result<()> {
    let input = args
        .input
        .canonicalize()
        .context("cannot resolve input path")?;
    if let Ok(output) = args.output.canonicalize() {
        ensure!(
            input != output,
            "input and output must be different files, even with --force"
        );
        for source in [&args.key_file, &args.otp_dump].into_iter().flatten() {
            if let Ok(source) = source.canonicalize() {
                ensure!(
                    source != output,
                    "output must not replace the key or OTP file"
                );
            }
        }
    }
    if !args.force && args.output.symlink_metadata().is_ok() {
        bail!(
            "output {} already exists; use --force to replace it",
            args.output.display()
        );
    }
    Ok(())
}

fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create an output file in {}", parent.display()))?;
    temporary
        .write_all(bytes)
        .context("cannot write plaintext loader")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot flush plaintext loader")?;
    let result = if force {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    };
    result
        .map_err(|error| error.error)
        .with_context(|| format!("cannot save {}", path.display()))?;
    Ok(())
}

fn run(args: Args) -> Result<()> {
    validate_destination(&args)?;
    let input = read_bounded(&args.input, MAX_INPUT_BYTES)?;
    let input_digest = sha256(&input);
    let key = read_key(&args)?;
    let extracted = extract_loader(&input, args.format.into())?;
    let loader_digest = sha256(&extracted.bytes);
    let result = decrypt_ldr(&extracted.bytes, key.as_ref())?;
    let digest = sha256(&result.bytes);

    let known_246 = loader_digest == ENCRYPTED_246_SHA256 || loader_digest == PLAINTEXT_246_SHA256;
    if known_246 {
        ensure!(
            digest == PLAINTEXT_246_SHA256,
            "firmware 246 plaintext SHA-256 mismatch; check the supplied key (output was not written)"
        );
    }
    if let Some(expected) = &args.expect_sha256 {
        ensure!(digest == *expected, "plaintext SHA-256 mismatch: expected {expected}, got {digest} (output was not written)");
    }
    write_output(&args.output, &result.bytes, args.force)?;

    println!("Output: {}", args.output.display());
    println!("Bytes: {}", result.bytes.len());
    println!("Input SHA-256: {input_digest}");
    if let Some(crc) = extracted.package_crc32 {
        println!("Package CRC32: {crc:08x} (verified)");
        println!("Encrypted/member LDR SHA-256: {loader_digest}");
    }
    println!("Plaintext SHA-256: {digest}");
    let report = &result.report;
    println!(
        "Records: {} ({} payload, {} fill)",
        report.records, report.payload_records, report.fill_records
    );
    println!("Callback records decrypted: {}", report.encrypted_records);
    println!(
        "XTEA units: {} ({} in partial 24-byte groups)",
        report.decrypted_units, report.encrypted_tail_units
    );
    println!(
        "FINAL end: 0x{:x}; preserved trailer: {} bytes",
        report.final_end, report.trailer_bytes
    );
    if known_246 {
        println!("Verification: exact match to the established firmware 246 plaintext.");
    } else if args.expect_sha256.is_some() {
        println!("Verification: exact match to the requested plaintext SHA-256.");
    } else {
        println!("Verification: loader structure and header checksums only. Key correctness is unverified without a trusted plaintext hash.");
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
