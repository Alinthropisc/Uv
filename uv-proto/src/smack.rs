// SMACK — Aho-Corasick multi-pattern banner matcher (masscan smack1.c style).
// Builds a goto/fail/output automaton at compile time, then matches in O(n) over banner bytes.
// Used to classify banners into service types without regex overhead.

use std::collections::HashMap;

const GOTO_FAIL: u32 = u32::MAX;

/// A compiled Aho-Corasick automaton.
pub struct Smack {
    /// goto[state][byte] = next_state | GOTO_FAIL
    goto: Vec<[u32; 256]>,
    /// fail[state] = fallback state
    fail: Vec<u32>,
    /// output[state] = list of matched pattern indices
    output: Vec<Vec<usize>>,
}

impl Smack {
    /// Build automaton from a list of (pattern_bytes, label) pairs.
    pub fn build(patterns: &[(&[u8], usize)]) -> Self {
        let mut goto: Vec<[u32; 256]> = vec![[GOTO_FAIL; 256]];
        let mut output: Vec<Vec<usize>> = vec![vec![]];

        // Phase 1: build goto function
        for &(pattern, label) in patterns {
            let mut state = 0u32;
            for &b in pattern {
                let next = goto[state as usize][b as usize];
                if next == GOTO_FAIL {
                    let new_state = goto.len() as u32;
                    goto.push([GOTO_FAIL; 256]);
                    output.push(vec![]);
                    goto[state as usize][b as usize] = new_state;
                    state = new_state;
                } else {
                    state = next;
                }
            }
            output[state as usize].push(label);
        }

        // Root: GOTO_FAIL → stay at root (state 0)
        for b in 0..=255u8 {
            if goto[0][b as usize] == GOTO_FAIL {
                goto[0][b as usize] = 0;
            }
        }

        // Phase 2: build fail function via BFS
        let n = goto.len();
        let mut fail = vec![0u32; n];
        let mut queue = std::collections::VecDeque::new();

        // Depth-1 states: fail → root
        for b in 0..=255usize {
            let s = goto[0][b];
            if s != 0 {
                fail[s as usize] = 0;
                queue.push_back(s);
            }
        }

        while let Some(r) = queue.pop_front() {
            for b in 0..=255usize {
                let s = goto[r as usize][b];
                if s == GOTO_FAIL {
                    // Fill goto with fail chain
                    goto[r as usize][b] = goto[fail[r as usize] as usize][b];
                } else {
                    fail[s as usize] = goto[fail[r as usize] as usize][b];
                    // Merge output
                    let fail_out = output[fail[s as usize] as usize].clone();
                    output[s as usize].extend(fail_out);
                    queue.push_back(s);
                }
            }
        }

        Self { goto, fail, output }
    }

    /// Run the automaton over `text`. Returns iterator of (byte_offset, label).
    pub fn find_all<'a>(&'a self, text: &'a [u8]) -> SmackIter<'a> {
        SmackIter {
            smack: self,
            text,
            pos: 0,
            state: 0,
            emit_buf: vec![],
        }
    }

    /// Returns true if any pattern matches in `text`.
    pub fn matches_any(&self, text: &[u8]) -> bool {
        let mut state = 0u32;
        for &b in text {
            state = self.goto[state as usize][b as usize];
            if !self.output[state as usize].is_empty() {
                return true;
            }
        }
        false
    }

    /// Returns the first matching label in `text`, if any.
    pub fn first_match(&self, text: &[u8]) -> Option<usize> {
        let mut state = 0u32;
        for &b in text {
            state = self.goto[state as usize][b as usize];
            if let Some(&label) = self.output[state as usize].first() {
                return Some(label);
            }
        }
        None
    }
}

pub struct SmackIter<'a> {
    smack: &'a Smack,
    text: &'a [u8],
    pos: usize,
    state: u32,
    emit_buf: Vec<(usize, usize)>,
}

impl<'a> Iterator for SmackIter<'a> {
    type Item = (usize, usize); // (byte_offset, label)

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.emit_buf.pop() {
            return Some(item);
        }
        while self.pos < self.text.len() {
            let b = self.text[self.pos];
            self.state = self.smack.goto[self.state as usize][b as usize];
            let pos = self.pos;
            self.pos += 1;
            let out = &self.smack.output[self.state as usize];
            if !out.is_empty() {
                for &label in out.iter().skip(1) {
                    self.emit_buf.push((pos, label));
                }
                return Some((pos, out[0]));
            }
        }
        None
    }
}

/// Service label index — matches masscan masscan-app.h APP_* constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum ServiceLabel {
    Ssh = 0,
    Http,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Mysql,
    Redis,
    Mongodb,
    Telnet,
    Rdp,
    Smb,
    Tls,
    Dns,
    Memcached,
    Unknown,
}

impl ServiceLabel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Http => "http",
            Self::Ftp => "ftp",
            Self::Smtp => "smtp",
            Self::Pop3 => "pop3",
            Self::Imap => "imap",
            Self::Mysql => "mysql",
            Self::Redis => "redis",
            Self::Mongodb => "mongodb",
            Self::Telnet => "telnet",
            Self::Rdp => "rdp",
            Self::Smb => "smb",
            Self::Tls => "tls",
            Self::Dns => "dns",
            Self::Memcached => "memcached",
            Self::Unknown => "unknown",
        }
    }
}

/// Build the default banner classification automaton.
pub fn default_banner_smack() -> Smack {
    let patterns: &[(&[u8], usize)] = &[
        (b"SSH-", ServiceLabel::Ssh as usize),
        (b"HTTP/", ServiceLabel::Http as usize),
        (b"GET /", ServiceLabel::Http as usize),
        (b"220 ", ServiceLabel::Ftp as usize), // FTP/SMTP both use 220
        (b"220-", ServiceLabel::Smtp as usize),
        (b"EHLO", ServiceLabel::Smtp as usize),
        (b"+OK", ServiceLabel::Pop3 as usize),
        (b"* OK", ServiceLabel::Imap as usize),
        (b"\x4a\x00\x00\x00", ServiceLabel::Mysql as usize), // MySQL greeting
        (b"+PONG", ServiceLabel::Redis as usize),
        (b"-ERR", ServiceLabel::Redis as usize),
        (b"\x16\x03", ServiceLabel::Tls as usize), // TLS ClientHello/ServerHello
        (b"\x15\x03", ServiceLabel::Tls as usize), // TLS Alert
        (b"STAT ", ServiceLabel::Memcached as usize),
        (b"\xff\x53\x4d\x42", ServiceLabel::Smb as usize), // SMB magic
        (b"\x03\x00", ServiceLabel::Rdp as usize),         // TPKT/RDP
    ];
    Smack::build(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_match() {
        let smack = default_banner_smack();
        assert_eq!(
            smack.first_match(b"SSH-2.0-OpenSSH_8.9"),
            Some(ServiceLabel::Ssh as usize)
        );
    }

    #[test]
    fn test_http_match() {
        let smack = default_banner_smack();
        assert!(smack.matches_any(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_no_match() {
        let smack = default_banner_smack();
        assert!(!smack.matches_any(b"\x00\x01\x02\x03"));
    }
}
