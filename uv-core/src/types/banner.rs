use serde::{Deserialize, Serialize};

use super::protocol::UvServiceKind;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvBanner {
    pub raw: Vec<u8>,
    pub text: Option<String>,
    pub tls: bool,
}

impl UvBanner {
    pub fn uv_from_bytes(raw: Vec<u8>, tls: bool) -> Self {
        let text = String::from_utf8(raw.clone()).ok().map(|s| s.trim().to_owned());
        Self {
            raw,
            text,
            tls
        }
    }

    pub fn uv_is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvServiceInfo {
    pub service: UvServiceKind,
    pub version: Option<String>,
    pub extra: Option<String>,
    pub banner: Option<UvBanner>,
}

impl UvServiceInfo {
    pub fn uv_new(service: UvServiceKind) -> Self {
        Self {
            service,
            version: None,
            extra: None,
            banner: None,
        }
    }

    pub fn uv_with_banner(mut self, banner: UvBanner) -> Self {
        self.banner = Some(banner);
        self
    }

    pub fn uv_with_version(mut self, ver: impl Into<String>) -> Self {
        self.version = Some(ver.into());
        self
    }
}