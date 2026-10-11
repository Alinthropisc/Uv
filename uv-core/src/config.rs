use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvScanConfig {
    pub batch_size: usize,
    pub timeout_ms: u32,
    pub tries: u8,
    pub rate_pps: u64,
    pub burst_size: u64,
    pub udp: bool,
    pub greppable: bool,
    pub accessible: bool,
    pub no_banner: bool,
    pub config_path: Option<PathBuf>,
}

impl Default for UvScanConfig {
    fn default() -> Self {
        Self {
            batch_size: 4500,
            timeout_ms: 1500,
            tries: 1,
            rate_pps: 10_000_000,
            burst_size: 100_000,
            udp: false,
            greppable: false,
            accessible: false,
            no_banner: false,
            config_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvProbeConfig {
    pub banner_timeout_ms: u32,
    pub tls_enabled: bool,
    pub max_banner_bytes: usize,
}

impl Default for UvProbeConfig {
    fn default() -> Self {
        Self {
            banner_timeout_ms: 2000,
            tls_enabled: true,
            max_banner_bytes: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvRateConfig {
    pub pps: u64,
    pub burst_size: u64,
}

impl Default for UvRateConfig {
    fn default() -> Self {
        Self {
            pps: 10_000_000,
            burst_size: 100_000,
        }
    }
}