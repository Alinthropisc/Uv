// OS fingerprint types.

use serde::{Deserialize, Serialize};

/// Extracted fingerprint from live probes — matches nmap FP string format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub seq_index: Option<u32>, // ISN predictability index
    pub ttl_guess: Option<u8>,  // inferred initial TTL
    pub window_scale: Option<u8>,
    pub df: bool,
    pub ecn: bool,
    pub tcp_opt_str: String, // e.g. "MSTNW" — option order fingerprint
    pub icmp_echo_df: bool,
    pub os_class: Option<String>,
}

/// A candidate OS match from the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8, // 0-100
    pub os_class: String,
    pub cpe: String,
}

impl OsFingerprint {
    /// Build TCP option order string from a list of option names.
    pub fn set_tcp_opts(&mut self, opts: &[&str]) {
        self.tcp_opt_str = opts
            .iter()
            .map(|o| match *o {
                "mss" => 'M',
                "sack" => 'S',
                "timestamp" => 'T',
                "nop" => 'N',
                "wscale" => 'W',
                "eol" => 'E',
                _ => '?',
            })
            .collect();
    }

    /// Guess initial TTL from observed TTL (assume ≤3 hops).
    pub fn guess_ttl(observed: u8) -> u8 {
        for candidate in [32u8, 64, 128, 255] {
            if observed <= candidate {
                return candidate;
            }
        }
        255
    }
}
