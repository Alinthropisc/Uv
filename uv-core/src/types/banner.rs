use super::protocol::ServiceKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Banner {
    pub raw: Vec<u8>,
    pub text: Option<String>,
    pub tls: bool,
}

impl Banner {
    pub fn from_bytes(raw: Vec<u8>, tls: bool) -> Self {
        let text = String::from_utf8(raw.clone())
            .ok()
            .map(|s| s.trim().to_owned());
        Self { raw, text, tls }
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub service: ServiceKind,
    pub version: Option<String>,
    pub extra: Option<String>,
    pub banner: Option<Banner>,
}

impl ServiceInfo {
    pub fn new(service: ServiceKind) -> Self {
        Self {
            service,
            version: None,
            extra: None,
            banner: None,
        }
    }

    pub fn with_banner(mut self, banner: Banner) -> Self {
        self.banner = Some(banner);
        self
    }

    pub fn with_version(mut self, ver: impl Into<String>) -> Self {
        self.version = Some(ver.into());
        self
    }
}
