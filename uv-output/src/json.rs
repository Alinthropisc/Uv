use crate::formatter::Formatter;
use uv_core::types::result::ScanResult;

pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn name(&self) -> &'static str {
        "json"
    }

    fn format(&self, result: &ScanResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}
