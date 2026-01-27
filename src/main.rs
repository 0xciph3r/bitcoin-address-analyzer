//! CLI entry point for the Bitcoin Address Analyzer.

use anyhow::Result;
use clap::{Parser, ValueEnum};
use bitcoin_address_analyzer::{analyze, format_json, format_readme};

/// CLI output formats supported by the tool.
#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    /// Human-readable text (default).
    Text,
    /// Machine-readable JSON.
    Json,
    /// README-style Markdown.
    Readme,
}

/// CLI definition using clap derive.
#[derive(Parser, Debug)]
#[command(name = "bitcoin-address-analyzer")]
#[command(about = "Analyze Bitcoin addresses")]
#[command(version = "0.1.0")]
struct Cli {
    /// Bitcoin address to analyze
    address: String,

    /// Output format: text, json, or readme
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Print extra diagnostic information
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> Result<()> {
    // Parse CLI args.
    let args = Cli::parse();

    // Run analysis.
    let analysis = analyze(&args.address);

    // Render output based on the chosen format.
    let output = match args.format {
        OutputFormat::Text => analysis.to_string(),
        OutputFormat::Json => format_json(&analysis)?,
        OutputFormat::Readme => format_readme(&analysis),
    };

    print!("{}", output);

    // Optional diagnostics for troubleshooting.
    if args.verbose {
        eprintln!("\nDiagnostics:");
        eprintln!("- valid: {}", analysis.is_valid);
        eprintln!("- networks: {:?}", analysis.networks);
        eprintln!("- address_type: {:?}", analysis.address_type);
        eprintln!("- witness_version: {:?}", analysis.witness_version);
    }

    // Return non-zero exit code on invalid input.
    if !analysis.is_valid {
        std::process::exit(1);
    }

    Ok(())
}
