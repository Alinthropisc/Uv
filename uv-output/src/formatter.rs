// Strategy trait for scan output.

use uv_core::types::result::ScanResult;

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Plain,
    Greppable,
    Json,
    Xml,
    /// masscan-compatible binary format (base64-encoded for string contexts).
    Binary,
    /// Newline-delimited JSON — one object per host (masscan out-ndjson.c style).
    NdJson,
    /// TLS certificate PEM output.
    Certs,
    /// Unicornscan-compatible text output.
    Unicornscan,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "plain" | "normal" => Some(Self::Plain),
            "greppable" | "grep" | "oG" => Some(Self::Greppable),
            "json" | "oJ" => Some(Self::Json),
            "xml" | "oX" => Some(Self::Xml),
            "binary" | "bin" | "oB" => Some(Self::Binary),
            "ndjson" | "nd" => Some(Self::NdJson),
            "certs" | "pem" => Some(Self::Certs),
            "unicornscan" | "uni" => Some(Self::Unicornscan),
            _ => None,
        }
    }
}

/// Strategy trait — each formatter serialises a ScanResult to a String.
pub trait Formatter: Send + Sync {
    fn format(&self, result: &ScanResult) -> String;
    fn name(&self) -> &'static str;
}
