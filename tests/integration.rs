//! Integration tests for the analyzer and formatters.

use bitcoin_address_analyzer::{analyze, format_json, format_readme, ChecksumType};
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::{Address, AddressType, Network, WitnessVersion};

#[test]
fn analyzes_p2pkh_mainnet() {
    // Known valid legacy address.
    let analysis = analyze("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    assert!(analysis.is_valid);
    assert_eq!(analysis.address_type, Some(AddressType::P2pkh));
    assert!(analysis.networks.contains(&Network::Bitcoin));
    assert_eq!(analysis.checksum, Some(ChecksumType::Base58Check));
}

#[test]
fn analyzes_p2wpkh_mainnet() {
    // Construct a deterministic v0 segwit address for testing.
    let program = WitnessProgram::new(WitnessVersion::V0, &[0u8; 20]).unwrap();
    let addr = Address::from_witness_program(program, Network::Bitcoin);
    let analysis = analyze(&addr.to_string());
    assert!(analysis.is_valid);
    assert_eq!(analysis.address_type, Some(AddressType::P2wpkh));
    assert_eq!(analysis.witness_version, Some(WitnessVersion::V0));
    assert_eq!(analysis.checksum, Some(ChecksumType::Bech32));
    assert_eq!(analysis.networks, vec![Network::Bitcoin]);
}

#[test]
fn analyzes_taproot_mainnet() {
    // Construct a deterministic v1 segwit (taproot) address.
    let program = WitnessProgram::new(WitnessVersion::V1, &[1u8; 32]).unwrap();
    let addr = Address::from_witness_program(program, Network::Bitcoin);
    let analysis = analyze(&addr.to_string());
    assert!(analysis.is_valid);
    assert_eq!(analysis.address_type, Some(AddressType::P2tr));
    assert_eq!(analysis.witness_version, Some(WitnessVersion::V1));
    assert_eq!(analysis.checksum, Some(ChecksumType::Bech32m));
    assert_eq!(analysis.networks, vec![Network::Bitcoin]);
}

#[test]
fn analyzes_testnet_and_signet() {
    // Testnet and signet share HRP (tb), so the address is valid for both.
    let program = WitnessProgram::new(WitnessVersion::V0, &[1u8; 20]).unwrap();
    let addr = Address::from_witness_program(program, Network::Testnet);
    let analysis = analyze(&addr.to_string());
    assert!(analysis.is_valid);
    assert!(analysis.networks.contains(&Network::Testnet));
    assert!(analysis.networks.contains(&Network::Signet));
    assert!(!analysis.networks.contains(&Network::Bitcoin));
}

#[test]
fn analyzes_regtest() {
    // Regtest has its own HRP (bcrt), so this should be unambiguous.
    let program = WitnessProgram::new(WitnessVersion::V0, &[2u8; 20]).unwrap();
    let addr = Address::from_witness_program(program, Network::Regtest);
    let analysis = analyze(&addr.to_string());
    assert!(analysis.is_valid);
    assert!(analysis.networks.contains(&Network::Regtest));
    assert_eq!(analysis.networks.len(), 1);
}

#[test]
fn rejects_invalid_address() {
    // Invalid input should produce a readable error.
    let analysis = analyze("not-a-bitcoin-address");
    assert!(!analysis.is_valid);
    assert!(analysis.error.is_some());
}

#[test]
fn json_output_contains_fields() {
    let analysis = analyze("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    let json = format_json(&analysis).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["address_type"], "P2PKH");
}

#[test]
fn readme_output_contains_sections() {
    let analysis = analyze("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    let md = format_readme(&analysis);
    assert!(md.contains("# Bitcoin Address Analysis"));
    assert!(md.contains("## Script"));
}
