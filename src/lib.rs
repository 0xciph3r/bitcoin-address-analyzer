//! Library entry point for the Bitcoin Address Analyzer.
//!
//! We keep the core logic in a library so it is reusable, testable, and
//! separate from the CLI interface (a common Rust pattern).

/// Analysis logic (parsing, network detection, script/witness extraction).
pub mod analyzer;
/// Human-readable output formatting for the analysis result.
pub mod formatter;
/// Domain types shared across the application.
pub mod types;

/// Re-export the main analysis function for convenience.
pub use analyzer::analyze;
/// Re-export core types for consumers/tests.
pub use types::{AddressAnalysis, ChecksumType};
/// Re-export extra formatters for JSON/README output.
pub use formatter::{format_json, format_readme};
