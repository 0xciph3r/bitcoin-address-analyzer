# Bitcoin Address Analyzer (Rust CLI)

A CLI tool that analyzes and validates Bitcoin addresses while demonstrating production Rust patterns and `rust-bitcoin` usage.

## Why this design

### 1) Library-first architecture

We split logic into a library (`src/lib.rs`) and a thin CLI (`src/main.rs`). This is a common Rust pattern that keeps business logic testable and reusable.

- `src/analyzer.rs`: Pure analysis logic (parsing, scripts, witness data).
- `src/types.rs`: Domain models (`AddressAnalysis`, `ChecksumType`).
- `src/formatter.rs`: Output formatting (text, JSON, README).
- `src/main.rs`: CLI parsing and output routing.

### 2) Using `rust-bitcoin`

We rely on the official `bitcoin` crate to:

- Validate Base58Check / Bech32 / Bech32m checksums.
- Extract `AddressType`, `Script`, and witness data safely.
- Avoid re-implementing Bitcoin consensus rules in application code.

### 3) Network handling

Some address prefixes overlap across Testnet/Signet/Regtest. We return a **list** of possible networks via `is_valid_for_network` rather than forcing a single network.

### 4) Output formats

We support:

- **text**: human-friendly console output.
- **json**: machine-readable output.
- **readme**: Markdown-style report for documentation/teaching.

## What the CLI reports

- Address type (P2PKH → P2TR)
- Network(s): Mainnet/Testnet/Signet/Regtest
- ScriptPubKey hex + ASM
- Witness version and program
- Payload meaning (pubkey hash, script hash, taproot key)
- Checksum type and validity
- Specific parse errors when invalid

## How to run

### 1) Build

```bash
cargo build
```

### 2) Run (text output)

```bash
cargo run -- <address>
```

### 3) JSON output

```bash
cargo run -- --format json <address>
```

### 4) README-style output

```bash
cargo run -- --format readme <address>
```

### 5) Verbose diagnostics

```bash
cargo run -- --verbose <address>
```

## Example

```bash
cargo run -- --format json bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
```

## Tests

```bash
cargo test
```

## Learning notes

- **Legacy addresses** (P2PKH/P2SH) use Base58Check.
- **SegWit v0** (P2WPKH/P2WSH) uses Bech32.
- **SegWit v1+** (Taproot) uses Bech32m.
- Script templates show how funds are locked on-chain.

---
