//! Domain types used across analyzer and formatter.

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, AddressType, Network, WitnessVersion};
use std::fmt;

/// The checksum algorithm validated during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumType {
    /// Base58Check (legacy P2PKH/P2SH).
    Base58Check,
    /// Bech32 checksum (SegWit v0).
    Bech32,
    /// Bech32m checksum (SegWit v1+ e.g. Taproot).
    Bech32m,
}

/// Pretty-print checksum names.
impl fmt::Display for ChecksumType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ChecksumType::Base58Check => "Base58Check",
            ChecksumType::Bech32 => "Bech32",
            ChecksumType::Bech32m => "Bech32m",
        };
        write!(f, "{label}")
    }
}

/// Structured analysis report for a Bitcoin address.
#[derive(Debug, Clone)]
pub struct AddressAnalysis {
    /// Original user input.
    pub input: String,
    /// Whether parsing/validation succeeded.
    pub is_valid: bool,
    /// Error message when invalid.
    pub error: Option<String>,
    /// Parsed address (unchecked network) when valid.
    pub address: Option<Address<NetworkUnchecked>>,
    /// Address type (P2PKH, P2TR, etc.) if recognized.
    pub address_type: Option<AddressType>,
    /// All networks the address is valid for.
    pub networks: Vec<Network>,
    /// ScriptPubKey in hex.
    pub script_pubkey_hex: Option<String>,
    /// ScriptPubKey in ASM (opcode-like format).
    pub script_asm: Option<String>,
    /// Witness version, if SegWit.
    pub witness_version: Option<WitnessVersion>,
    /// Witness program (payload) in hex.
    pub witness_program_hex: Option<String>,
    /// Human explanation of witness payload (pubkey hash, script hash, etc.).
    pub payload_explanation: Option<String>,
    /// Checksum algorithm validated by parsing.
    pub checksum: Option<ChecksumType>,
}

impl AddressAnalysis {
    /// Construct a valid analysis result.
    pub fn valid(
        input: String,
        address: Address<NetworkUnchecked>,
        address_type: Option<AddressType>,
        networks: Vec<Network>,
        script_pubkey_hex: String,
        script_asm: String,
        witness_version: Option<WitnessVersion>,
        witness_program_hex: Option<String>,
        payload_explanation: Option<String>,
        checksum: Option<ChecksumType>,
    ) -> Self {
        Self {
            input,
            is_valid: true,
            error: None,
            address: Some(address),
            address_type,
            networks,
            script_pubkey_hex: Some(script_pubkey_hex),
            script_asm: Some(script_asm),
            witness_version,
            witness_program_hex,
            payload_explanation,
            checksum,
        }
    }

    /// Construct an invalid analysis result.
    pub fn invalid(input: &str, error: String) -> Self {
        Self {
            input: input.to_string(),
            is_valid: false,
            error: Some(error),
            address: None,
            address_type: None,
            networks: Vec::new(),
            script_pubkey_hex: None,
            script_asm: None,
            witness_version: None,
            witness_program_hex: None,
            payload_explanation: None,
            checksum: None,
        }
    }
}
