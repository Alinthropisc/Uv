// OS matcher — Strategy pattern.
// Scores a live fingerprint against each DB entry.

use std::cmp::Reverse;

use crate::db::OsDb;
use crate::fingerprint::{OsFingerprint, OsMatch};

pub struct OsMatcher {
    db: OsDb,
}

impl OsMatcher {
    pub fn new(db: OsDb) -> Self {
        Self { db }
    }

    /// Score fingerprint against all DB entries, return top matches.
    pub fn match_fp(&self, fp: &OsFingerprint) -> Vec<OsMatch> {
        let mut matches: Vec<OsMatch> = self
            .db
            .entries()
            .iter()
            .filter_map(|entry| {
                let score = self.score(fp, entry);
                if score >= 30 {
                    Some(OsMatch {
                        name: entry.name.clone(),
                        accuracy: score,
                        os_class: entry.os_class.clone(),
                        cpe: entry.cpe.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        matches.sort_by_key(|b| Reverse(b.accuracy));
        matches.truncate(5);
        matches
    }

    fn score(&self, fp: &OsFingerprint, entry: &crate::db::OsEntry) -> u8 {
        let mut score = 0u8;
        let mut total = 0u8;

        // TTL match
        total += 20;
        if fp.ttl_guess == Some(entry.ttl) {
            score += 20;
        }

        // Window scale
        total += 15;
        if fp.window_scale == entry.window_scale {
            score += 15;
        }

        // DF bit
        total += 10;
        if fp.df == entry.df {
            score += 10;
        }

        // TCP option order
        total += 30;
        if fp.tcp_opt_str == entry.tcp_opt_str {
            score += 30;
        }

        // ECN
        total += 10;
        if fp.ecn == entry.ecn {
            score += 10;
        }

        // ICMP DF
        total += 15;
        if fp.icmp_echo_df == entry.icmp_echo_df {
            score += 15;
        }

        (score as u32 * 100 / total.max(1) as u32).min(100) as u8
    }
}
