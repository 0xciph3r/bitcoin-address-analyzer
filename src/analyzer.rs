//! Core analysis logic for Bitcoin addresses.

use crate::types::{AddressAnalysis, ChecksumType};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hex::DisplayHex;
use bitcoin::{Address, AddressType, Network, WitnessVersion};
use std::str::FromStr;

/// Analyze a Bitcoin address string and return a structured report.
pub fn analyze(input: &str) -> AddressAnalysis {
    // Step 1: Parse the address.
    // Parsing validates checksum rules (Base58Check or Bech32/Bech32m).
    let address: Address<NetworkUnchecked> = match Address::from_str(input) {
        Ok(addr) => addr,
        Err(e) => return AddressAnalysis::invalid(input, e.to_string()),
    };

    // Step 2: Determine all networks this address is valid for.
    // Testnet/signet/regtest share prefixes, so we return a list.
    let networks = possible_networks(&address);

    // Step 3: Extract script and witness details.
    // `assume_checked_ref()` is safe here because checksum already validated the payload.
    let checked = address.assume_checked_ref();
    let address_type = checked.address_type();
    let script = checked.script_pubkey();

    // Step 4: Extract witness program info (if SegWit).
    let witness_program = checked.witness_program();
    let witness_version = witness_program.map(|p| p.version());
    let witness_program_hex = witness_program
        .map(|p| p.program().as_bytes().to_lower_hex_string());
    let payload_explanation = witness_program
        .and_then(|p| explain_witness_payload(p.version(), p.program().len()));

    // Step 5: Determine checksum type.
    let checksum = checksum_for(address_type, witness_version);

    // Step 6: Return a structured analysis object.
    AddressAnalysis::valid(
        input.to_string(),
        address,
        address_type,
        networks,
        script.as_bytes().to_lower_hex_string(),
        script.to_asm_string(),
        witness_version,
        witness_program_hex,
        payload_explanation,
        checksum,
    )
}

/// Compute all networks that accept this address.
fn possible_networks(address: &Address<NetworkUnchecked>) -> Vec<Network> {
    let candidates = [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ];

    candidates
        .into_iter()
        .filter(|n| address.is_valid_for_network(*n))
        .collect()
}

/// Decide which checksum algorithm was validated.
fn checksum_for(
    address_type: Option<AddressType>,
    witness_version: Option<WitnessVersion>,
) -> Option<ChecksumType> {
    match witness_version {
        // SegWit v0 uses Bech32 (BIP173).
        Some(WitnessVersion::V0) => Some(ChecksumType::Bech32),
        // SegWit v1+ uses Bech32m (BIP350).
        Some(_) => Some(ChecksumType::Bech32m),
        // Legacy addresses use Base58Check.
        None => match address_type {
            Some(AddressType::P2pkh) | Some(AddressType::P2sh) => Some(ChecksumType::Base58Check),
            _ => Some(ChecksumType::Base58Check),
        },
    }
}

/// Explain witness payload meaning based on version and program length.
fn explain_witness_payload(version: WitnessVersion, len: usize) -> Option<String> {
    let explanation = match (version, len) {
        (WitnessVersion::V0, 20) => "P2WPKH pubkey hash (20 bytes)",
        (WitnessVersion::V0, 32) => "P2WSH script hash (32 bytes)",
        (WitnessVersion::V1, 32) => "P2TR x-only pubkey (32 bytes)",
        (WitnessVersion::V1, 2) => "P2A anchor program (2 bytes)",
        _ => "Unknown witness program",
    };
    Some(explanation.to_string())
}
