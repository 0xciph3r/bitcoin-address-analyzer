//! Human-readable formatting for AddressAnalysis.

use crate::types::AddressAnalysis;
use bitcoin::{AddressType, Network, WitnessVersion};
use serde_json::json;
use std::fmt;

/// Display the analysis in a readable, teaching-friendly format.
impl fmt::Display for AddressAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Header
        writeln!(f, "------------------------------------------------------------")?;
        writeln!(f, "Address: {}", self.input)?;
        writeln!(f, "------------------------------------------------------------")?;

        // Invalid path: show error and stop early.
        if !self.is_valid {
            writeln!(f, "Status: INVALID")?;
            if let Some(err) = &self.error {
                writeln!(f, "Error: {}", err)?;
            }
            return Ok(());
        }

        // Basic identity fields.
        writeln!(f, "Status: VALID")?;
        writeln!(f, "Networks: {}", format_networks(&self.networks))?;
        writeln!(f, "Type: {}", format_address_type(self.address_type))?;

        // Checksum details.
        if let Some(checksum) = &self.checksum {
            writeln!(f, "Checksum: {} (valid)", checksum)?;
        }

        // Script details.
        writeln!(f, "\nScript Details")?;
        if let Some(hex) = &self.script_pubkey_hex {
            writeln!(f, "Script PubKey (Hex): {}", hex)?;
        }
        if let Some(asm) = &self.script_asm {
            writeln!(f, "Script ASM: {}", asm)?;
        }
        if let Some(template) = script_template(self.address_type, self.witness_version) {
            writeln!(f, "Script Template: {}", template)?;
        }

        // Witness details (SegWit or Taproot).
        if let Some(version) = self.witness_version {
            writeln!(f, "\nWitness Data")?;
            writeln!(f, "Version: {}", version.to_num())?;
            if let Some(program) = &self.witness_program_hex {
                writeln!(f, "Program (Hex): {}", program)?;
            }
            if let Some(expl) = &self.payload_explanation {
                writeln!(f, "Payload Meaning: {}", expl)?;
            }
        } else {
            // Legacy addresses have no witness program.
            writeln!(f, "\nLegacy Address (no witness program)")?;
        }

        // Footer
        writeln!(f, "------------------------------------------------------------")
    }
}

/// Render JSON output for machine consumption.
pub fn format_json(analysis: &AddressAnalysis) -> Result<String, serde_json::Error> {
    // Build a JSON object with explicit strings to avoid type ambiguity.
    let payload = json!({
        "input": analysis.input,
        "valid": analysis.is_valid,
        "error": analysis.error,
        "address_type": analysis.address_type.map(address_type_label),
        "networks": network_labels(&analysis.networks),
        "checksum": analysis.checksum.as_ref().map(|c| c.to_string()),
        "script_pubkey_hex": analysis.script_pubkey_hex,
        "script_asm": analysis.script_asm,
        "script_template": script_template(analysis.address_type, analysis.witness_version),
        "witness_version": analysis.witness_version.map(|v| v.to_num()),
        "witness_program_hex": analysis.witness_program_hex,
        "payload_explanation": analysis.payload_explanation,
    });

    serde_json::to_string_pretty(&payload)
}

/// Render README-style Markdown output for learning or documentation.
pub fn format_readme(analysis: &AddressAnalysis) -> String {
    // Use Markdown headings and bullet lists for clarity.
    let mut out = String::new();

    out.push_str("# Bitcoin Address Analysis\n\n");
    out.push_str(&format!("**Input:** `{}`\n\n", analysis.input));

    if !analysis.is_valid {
        out.push_str("## Status\n");
        out.push_str("- Invalid\n");
        if let Some(err) = &analysis.error {
            out.push_str(&format!("- Error: `{}`\n", err));
        }
        return out;
    }

    out.push_str("## Status\n");
    out.push_str("- Valid\n");
    out.push_str(&format!("- Networks: {}\n", format_networks(&analysis.networks)));
    out.push_str(&format!("- Type: {}\n", format_address_type(analysis.address_type)));

    if let Some(checksum) = &analysis.checksum {
        out.push_str(&format!("- Checksum: {} (valid)\n", checksum));
    }

    out.push_str("\n## Script\n");
    if let Some(hex) = &analysis.script_pubkey_hex {
        out.push_str(&format!("- ScriptPubKey (hex): `{}`\n", hex));
    }
    if let Some(asm) = &analysis.script_asm {
        out.push_str(&format!("- Script ASM: `{}`\n", asm));
    }
    if let Some(template) = script_template(analysis.address_type, analysis.witness_version) {
        out.push_str(&format!("- Script template: `{}`\n", template));
    }

    out.push_str("\n## Witness\n");
    if let Some(version) = analysis.witness_version {
        out.push_str(&format!("- Version: `{}`\n", version.to_num()));
        if let Some(program) = &analysis.witness_program_hex {
            out.push_str(&format!("- Program (hex): `{}`\n", program));
        }
        if let Some(expl) = &analysis.payload_explanation {
            out.push_str(&format!("- Meaning: `{}`\n", expl));
        }
    } else {
        out.push_str("- None (legacy address)\n");
    }

    out
}

/// Map internal network enums to human-facing labels.
fn format_networks(networks: &[Network]) -> String {
    if networks.is_empty() {
        return "Unknown".to_string();
    }

    networks
        .iter()
        .map(|n| match n {
            Network::Bitcoin => "Mainnet",
            Network::Testnet => "Testnet",
            Network::Signet => "Signet",
            Network::Regtest => "Regtest",
            Network::Testnet4 => "Testnet4",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Internal network labels for JSON arrays.
fn network_labels(networks: &[Network]) -> Vec<String> {
    networks
        .iter()
        .map(|n| match n {
            Network::Bitcoin => "Mainnet",
            Network::Testnet => "Testnet",
            Network::Signet => "Signet",
            Network::Regtest => "Regtest",
            Network::Testnet4 => "Testnet4",
        }
        .to_string())
        .collect()
}

/// Convert AddressType to a descriptive string.
fn format_address_type(address_type: Option<AddressType>) -> String {
    match address_type {
        Some(AddressType::P2pkh) => "P2PKH (Pay to PubKey Hash)".to_string(),
        Some(AddressType::P2sh) => "P2SH (Pay to Script Hash)".to_string(),
        Some(AddressType::P2wpkh) => "P2WPKH (SegWit v0 PubKey Hash)".to_string(),
        Some(AddressType::P2wsh) => "P2WSH (SegWit v0 Script Hash)".to_string(),
        Some(AddressType::P2tr) => "P2TR (Taproot v1)".to_string(),
        Some(AddressType::P2a) => "P2A (Pay to Anchor)".to_string(),
        Some(_) => "Unknown".to_string(),
        None => "Unknown".to_string(),
    }
}

/// AddressType label for JSON output.
fn address_type_label(address_type: AddressType) -> String {
    match address_type {
        AddressType::P2pkh => "P2PKH".to_string(),
        AddressType::P2sh => "P2SH".to_string(),
        AddressType::P2wpkh => "P2WPKH".to_string(),
        AddressType::P2wsh => "P2WSH".to_string(),
        AddressType::P2tr => "P2TR".to_string(),
        AddressType::P2a => "P2A".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Canonical script templates for each standard address type.
fn script_template(
    address_type: Option<AddressType>,
    witness_version: Option<WitnessVersion>,
) -> Option<&'static str> {
    match (address_type, witness_version) {
        (Some(AddressType::P2pkh), _) =>
            Some("OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG"),
        (Some(AddressType::P2sh), _) => Some("OP_HASH160 <script_hash> OP_EQUAL"),
        (Some(AddressType::P2wpkh), _) => Some("OP_0 <pubkey_hash>"),
        (Some(AddressType::P2wsh), _) => Some("OP_0 <script_hash>"),
        (Some(AddressType::P2tr), _) => Some("OP_1 <x-only pubkey>"),
        (Some(AddressType::P2a), Some(WitnessVersion::V1)) => Some("OP_1 0x4e73 (anchor)"),
        _ => None,
    }
}
