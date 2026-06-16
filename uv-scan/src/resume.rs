// Resume state — mirrors masscan --resume / masscan.conf.
// Saves scan progress to a file; on restart, skips already-scanned IP:port pairs.

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::Path;

/// Persisted scan state for resume support.
#[derive(Debug, Default)]
pub struct ResumeState {
    pub completed: HashSet<(u32, u16)>, // (ipv4_u32, port)
    path: Option<String>,
}

impl ResumeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load state from file. Missing file = fresh scan (not an error).
    pub fn load(path: &str) -> io::Result<Self> {
        let mut state = Self {
            path: Some(path.to_string()),
            ..Default::default()
        };
        if !Path::new(path).exists() {
            return Ok(state);
        }

        let file = fs::File::open(path)?;
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // format: "ip:port"
            if let Some((ip_s, port_s)) = line.split_once(':') {
                if let (Ok(ip), Ok(port)) = (ip_s.parse::<IpAddr>(), port_s.parse::<u16>()) {
                    if let IpAddr::V4(v4) = ip {
                        state.completed.insert((u32::from(v4), port));
                    }
                }
            }
        }
        Ok(state)
    }

    /// Mark a port as scanned and flush to disk.
    pub fn mark_done(&mut self, ip: IpAddr, port: u16) -> io::Result<()> {
        if let IpAddr::V4(v4) = ip {
            let key = (u32::from(v4), port);
            if self.completed.insert(key) {
                if let Some(path) = &self.path {
                    let mut f = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?;
                    writeln!(f, "{ip}:{port}")?;
                }
            }
        }
        Ok(())
    }

    pub fn is_done(&self, ip: IpAddr, port: u16) -> bool {
        if let IpAddr::V4(v4) = ip {
            self.completed.contains(&(u32::from(v4), port))
        } else {
            false
        }
    }

    pub fn done_count(&self) -> usize {
        self.completed.len()
    }

    /// Clear the resume file (start fresh).
    pub fn reset(&mut self) -> io::Result<()> {
        self.completed.clear();
        if let Some(path) = &self.path {
            fs::remove_file(path).ok();
        }
        Ok(())
    }
}
