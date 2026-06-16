// Timing templates — mirrors nmap -T0 through -T5.
// Each template sets rate_pps, timeout_ms, concurrency, min_rtt.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TimingTemplate {
    /// T0 — Paranoid: 100 pps, 5000ms timeout, serial, min 5s between probes.
    T0,
    /// T1 — Sneaky: 1_000 pps, 3000ms, low concurrency.
    T1,
    /// T2 — Polite: 10_000 pps, 2000ms — slows to avoid network stress.
    T2,
    /// T3 — Normal (default): 100_000 pps, 1500ms, 256 concurrent.
    #[default]
    T3,
    /// T4 — Aggressive: 1_000_000 pps, 500ms, 512 concurrent. (requires fast LAN)
    T4,
    /// T5 — Insane: 10_000_000 pps, 200ms, 1024 concurrent. (masscan mode)
    T5,
}

#[derive(Debug, Clone)]
pub struct TimingParams {
    pub rate_pps: u64,
    pub timeout_ms: u32,
    pub concurrency: usize,
    pub min_rtt_ms: u32,
    pub max_retries: u8,
    pub scan_delay_ms: u32, // min delay between probes to same host
}

impl TimingTemplate {
    pub fn params(self) -> TimingParams {
        match self {
            TimingTemplate::T0 => TimingParams {
                rate_pps: 100,
                timeout_ms: 5_000,
                concurrency: 1,
                min_rtt_ms: 100,
                max_retries: 5,
                scan_delay_ms: 5_000,
            },
            TimingTemplate::T1 => TimingParams {
                rate_pps: 1_000,
                timeout_ms: 3_000,
                concurrency: 8,
                min_rtt_ms: 50,
                max_retries: 3,
                scan_delay_ms: 1_000,
            },
            TimingTemplate::T2 => TimingParams {
                rate_pps: 10_000,
                timeout_ms: 2_000,
                concurrency: 64,
                min_rtt_ms: 20,
                max_retries: 2,
                scan_delay_ms: 400,
            },
            TimingTemplate::T3 => TimingParams {
                rate_pps: 100_000,
                timeout_ms: 1_500,
                concurrency: 256,
                min_rtt_ms: 10,
                max_retries: 1,
                scan_delay_ms: 0,
            },
            TimingTemplate::T4 => TimingParams {
                rate_pps: 1_000_000,
                timeout_ms: 500,
                concurrency: 512,
                min_rtt_ms: 5,
                max_retries: 1,
                scan_delay_ms: 0,
            },
            TimingTemplate::T5 => TimingParams {
                rate_pps: 10_000_000,
                timeout_ms: 200,
                concurrency: 1024,
                min_rtt_ms: 0,
                max_retries: 0,
                scan_delay_ms: 0,
            },
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "0" | "T0" | "paranoid" => Some(Self::T0),
            "1" | "T1" | "sneaky" => Some(Self::T1),
            "2" | "T2" | "polite" => Some(Self::T2),
            "3" | "T3" | "normal" => Some(Self::T3),
            "4" | "T4" | "aggressive" => Some(Self::T4),
            "5" | "T5" | "insane" => Some(Self::T5),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::T0 => "T0 (paranoid)",
            Self::T1 => "T1 (sneaky)",
            Self::T2 => "T2 (polite)",
            Self::T3 => "T3 (normal)",
            Self::T4 => "T4 (aggressive)",
            Self::T5 => "T5 (insane)",
        }
    }
}
