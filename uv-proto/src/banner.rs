// Strategy + Chain of Responsibility: BannerParser trait + ParserChain

use serde::{Deserialize, Serialize};

/// Result of a successful banner parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBanner {
    pub service: String,
    pub version: Option<String>,
    pub info: Option<String>,
    pub raw_text: Option<String>,
}

impl ParsedBanner {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            version: None,
            info: None,
            raw_text: None,
        }
    }

    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    pub fn with_info(mut self, i: impl Into<String>) -> Self {
        self.info = Some(i.into());
        self
    }

    pub fn with_raw(mut self, r: impl Into<String>) -> Self {
        self.raw_text = Some(r.into());
        self
    }
}

/// Strategy trait — each protocol implements this.
pub trait BannerParser: Send + Sync {
    /// Try to parse `banner` received on `port`.
    /// Returns `Some(ParsedBanner)` on match, `None` to pass to next handler.
    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner>;

    fn name(&self) -> &'static str;
}

/// Chain of Responsibility — walks parsers in registration order.
#[derive(Default)]
pub struct ParserChain {
    parsers: Vec<Box<dyn BannerParser>>,
}

impl ParserChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style registration.
    pub fn add(mut self, p: impl BannerParser + 'static) -> Self {
        self.parsers.push(Box::new(p));
        self
    }

    /// Walk the chain; return first match or a generic fallback.
    pub fn parse(&self, banner: &[u8], port: u16) -> ParsedBanner {
        for p in &self.parsers {
            if let Some(result) = p.parse(banner, port) {
                return result;
            }
        }
        // Fallback: return raw printable text
        let raw = std::str::from_utf8(banner)
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();
        ParsedBanner::new("unknown").with_raw(raw)
    }
}
