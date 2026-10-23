# op-decryptor2

A Rust command-line tool and library for **decrypting the original Teenage
Engineering OP-1's `OP1_vdk.ldr` firmware loader**.

### What does it decrypt?

An original OP-1 firmware update (`.op1`) contains a file named `OP1_vdk.ldr`.
This is a **Blackfin loader (LDR)**: a sequence of headers and payloads that the
device's boot process loads into memory. Some of its payload bytes are
**encrypted with XTEA**. The affected LDR records carry a **decryption callback
flag** telling the loader to decrypt them at load time, using a 128-bit key
stored in the Blackfin chip's **OTP (one-time-programmable) memory, page `0xd0`**.

**op-decryptor2 performs that XTEA decryption offline.** Given either a full
`.op1` package or an extracted encrypted `OP1_vdk.ldr`, together with the
OTP-derived key (or a compatible text OTP dump), it produces **another LDR
file whose XTEA-encrypted payloads are decrypted and whose loader decryption
callback flags have been removed**. The output retains the LDR record
structure, other flags (including `INDIRECT`), metadata, and trailing bytes.
It does not remove unrelated program callbacks or function calls.

The default output filename, `plaintext.ldr`, is simply a name for that
**decrypted LDR**. It is not an input requirement or a different file format:
the result is still an LDR, not source code, a flat memory dump, or a complete
`.op1` update. The tool runs locally without connecting to or modifying an OP-1.

**Firmware 246 is verified byte for byte** against our established plaintext
baseline. The repository contains source code and synthetic tests; supply the
firmware and decryption key locally.

## Install

Requires [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer. All
decompression and cryptographic code is Rust; no Python, Ghidra, Blackfin tools,
native LZMA library, or connected OP-1 is required.

```sh
cargo install --git https://github.com/GosuBoy/op-decryptor2 --locked
```

Or build from a checkout:

```sh
git clone https://github.com/GosuBoy/op-decryptor2.git
cd op-decryptor2
cargo build --release --locked
```

The executable is `target/release/op-decryptor2` (`op-decryptor2.exe` on Windows).
CI tests Linux, macOS, and Windows, plus the minimum Rust version.

## Use

Supply an original OP-1 update (or its extracted `OP1_vdk.ldr`) and the
XTEA key from OTP page `0xd0`. The tool does **not** read the device's OTP
memory itself; provide either a key file or a compatible text OTP dump.

Decrypt a complete `.op1` update (automatically extracts `OP1_vdk.ldr`):

```sh
op-decryptor2 op1_246.op1 --key-file key.txt -o plaintext.ldr
```

Decrypt an already extracted, encrypted `OP1_vdk.ldr`:

```sh
op-decryptor2 OP1_vdk.ldr --key-file key.txt -o plaintext.ldr
```

Alternatively, read the key from a supported **text** OTP dump:

```sh
op-decryptor2 op1_246.op1 --otp-dump otp.txt -o plaintext.ldr
```

`plaintext.ldr` is just the default name for the **decrypted LDR output**;
you can choose any filename with `-o`. Use `--force` to replace an existing
output; the input cannot also be the output. Output is written through a temporary
file after all validation succeeds. Failure leaves an existing output intact.

### Where to get an OTP dump

The OP-1's XTEA key is stored in the Blackfin BF524's OTP page `0xd0`,
not in the firmware update. A publicly shared **reference OTP text dump** is
available in [Tolsi/op1dumps](https://github.com/Tolsi/op1dumps/blob/e42843c4a31ae88dbe5d7ee2413b02bd5caeff92/TE-OP-1-BF524-OTP-dump.txt).
Save the linked file as `otp.txt`, or download it from a terminal:

```sh
curl -L https://raw.githubusercontent.com/Tolsi/op1dumps/e42843c4a31ae88dbe5d7ee2413b02bd5caeff92/TE-OP-1-BF524-OTP-dump.txt -o otp.txt
```

Pass that file with `--otp-dump otp.txt` as shown above. This is a reference
dump from another device, not an OTP read from your own OP-1; key correctness
must be verified against the firmware (automatically for stock firmware 246).
The tool does not read OTP directly from hardware.

### Key formats

`--key-file` reads **32 hexadecimal digits**, optionally surrounded by whitespace.
The digits represent four eight-digit 32-bit key words in displayed order, matching
the historical decryptor's command-line convention. For example, this **synthetic
test key** means the words `[1, 2, 3, 4]`:

```text
00000001000000020000000300000004
```

This is a word-oriented textual format, not the bytes of a little-endian memory
dump. A key can alternatively be supplied directly as `--key HEX`.

`--otp-dump` accepts the public reference dump's text format. It reads
exactly one page `0xd0`, containing two 16-digit hexadecimal words:

```text
!0xd0  0000000100000002 0000000300000004
```

The example is synthetic. The leading `!` is optional, hexadecimal letter case is
ignored, and other pages are skipped. The two data fields are concatenated in
display order. Missing, malformed, or duplicate target pages are errors. Binary
OTP dumps are not accepted by this option. Only one key source may be specified.

If the input is already a decrypted LDR with no XTEA decryption callback flags,
no key is required. Its bytes are preserved exactly; processing it again is a no-op.

### Verification

For the known encrypted firmware-246 loader, the program **automatically requires
the canonical plaintext SHA-256**, even when its `.op1` container has been
repacked. An incorrect key fails before any output is written.

For another supported original-OP-1 loader, provide a trusted expected hash when
available:

```sh
op-decryptor2 OP1_vdk.ldr --key-file key.txt \
  --expect-sha256 1e806672dc440d495987c6b1f33b300876e6a3bb1d58254aac5fe60c960e906a
```

The hash above is specifically the firmware-246 baseline. Loader header XORs
check framing, not payload correctness. The outer package CRC32 detects container
corruption, not authenticity. For an unknown loader without a trusted output hash,
the program explicitly reports that key correctness remains unverified.

`--format op1` or `--format ldr` overrides automatic detection. Run
`op-decryptor2 --help` for all options.

## How decryption works and what it preserves

1. Verify the `.op1` package's four-byte little-endian CRC32, decompress its
   LZMA-alone stream, and select the root `OP1_vdk.ldr` TAR member in memory.
2. Parse each 16-byte Blackfin loader header; require signature byte `0xad` and
   a zero XOR across its bytes. A FILL record declares memory fill, not file data.
3. In supported CALLBACK + INDIRECT records, apply 32-cycle XTEA to each complete
   eight-byte unit at payload offsets `0, 24, 48, ...`. Payload words are
   little-endian. Restart the stride for every record.
4. **Clear CALLBACK (`0x0400`) only, preserving INDIRECT (`0x2000`)**, and repair
   the header XOR. These records no longer request XTEA decryption at load time.
   All other header fields and unaffected payload bytes remain unchanged.
5. Stop interpreting records after FINAL (`0x8000`) and preserve all following
   bytes verbatim.

The older public decryptor skipped complete eight-byte cipher units in partial
24-byte groups and cleared both CALLBACK and INDIRECT. Those behaviors do not
reproduce our canonical plaintext. This implementation handles the partial groups
and retains INDIRECT. A remainder shorter than eight bytes stays unchanged;
firmware 246 includes valid four-byte callback payloads.

Bounds are 64 MiB for input, selected LDR, and LZMA dictionary, and 256 MiB for
decompressed TAR. TAR entries are never extracted to filesystem paths. Duplicate
main members, nonregular main members, malformed headers, truncated streams,
unsupported callback flag combinations, and missing FINAL records are rejected.
FILL counts are never used to allocate memory or rounded to alignment.

The output is a **Blackfin LDR with decrypted payload bytes and no loader
XTEA-decryption callback flags**, including its original loader metadata and
trailer. It is not a flat memory image or a `.op1` update. The program performs
no hardware access, flashing, repacking, or loader execution.
The verified target is the original OP-1; OP-1 Field and OP-XY are outside scope.

## Verified firmware-246 baseline

The [official firmware package](https://teenage.engineering/_software/op-1/op1_246.op1)
was decoded independently and then processed with the release-build Rust CLI.
The output matched the previously established plaintext hash exactly.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Official `op1_246.op1` | 13,039,128 | `c5315218f825f143b415ca554516541898abee843d3a236df0b54c04e1fb13a9` |
| Encrypted `OP1_vdk.ldr` | 2,171,624 | `f79d299f6f9019c998013a4176223a6a1bc999a2d8c54451346861f6ea455c74` |
| Decrypted LDR (default name `plaintext.ldr`) | 2,171,624 | `1e806672dc440d495987c6b1f33b300876e6a3bb1d58254aac5fe60c960e906a` |

Verified structure: **800 active records**, including 385 payload records, 413
FILL records, and two zero-payload controls; **45 callback records**, **3,358 XTEA
units**, including **30 units in partial groups**; FINAL ends at `0x2121e8`,
followed by **256 preserved opaque bytes**. The FIRST header and the anomalous
FILL count `0x3ffff` at record index 710 remain unchanged.

## Develop and test

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Normal tests use synthetic data and independent XTEA known-answer vectors. They
cover tail handling, key byte order, loader framing, container corruption,
malformed inputs, OTP parsing, idempotence, and safe output-file behavior.

An opt-in real-firmware regression test accepts local files and verifies the exact
baseline, record counts, trailer, and automatic wrong-key rejection:

```sh
OP1_FIRMWARE_246=/path/to/op1_246.op1 \
OP1_KEY_FILE=/path/to/key.txt \
cargo test --locked --test stock_246 -- --ignored
```

Keep firmware and key files outside the checkout. They are not required for normal
tests or CI and must not be included in contributions.

The library exposes `Key`, `extract_loader`, `decrypt_ldr`, and a `LoaderReport`:

```rust,no_run
use op_decryptor2::{decrypt_ldr, extract_loader, InputFormat, Key};

# fn main() -> anyhow::Result<()> {
let input = std::fs::read("op1_246.op1")?;
let key = Key::from_hex(std::fs::read_to_string("key.txt")?.trim())?;
let loader = extract_loader(&input, InputFormat::Auto)?;
let result = decrypt_ldr(&loader.bytes, Some(&key))?;
// Verify a trusted output hash before persisting the result, as the CLI does.
println!("{} records", result.report.records);
# Ok(())
# }
```

The low-level library decryptor validates loader structure; automatic known-build
SHA-256 enforcement is performed by the CLI. Library callers should enforce their
own trusted output hash before saving or consuming decrypted code.

## Research and license

This is a newly written Rust implementation, informed by:

- [sualk/op1-decryptor](https://github.com/sualk/op1-decryptor/tree/20f86baa116b4c7b1da7e0d4e3a24f171c76767b),
  documenting the XTEA transform, key convention, and 24-byte stride.
- [op1hacks/docs](https://github.com/op1hacks/docs), documenting the update container
  and encryption layout.
- [Tolsi/op1dumps](https://github.com/Tolsi/op1dumps/tree/e42843c4a31ae88dbe5d7ee2413b02bd5caeff92),
  the public reference for the OTP text format.
- [LibTomCrypt XTEA test vectors](https://github.com/libtom/libtomcrypt/blob/develop/src/ciphers/xtea.c),
  used independently of OP-1 firmware in the synthetic tests.

The source in this repository is [MIT licensed](LICENSE). Third-party firmware,
research, and upstream source retain their own applicable terms.
