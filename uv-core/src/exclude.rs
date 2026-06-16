// Exclusion lists — mirrors masscan --excludefile and nmap --exclude.
// IpExcludeList: CIDR ranges to skip.
// PortExcludeList: port numbers/ranges to skip.

use std::net::IpAddr;
use std::str::FromStr;

/// IP exclusion list — loaded from file or CLI --exclude.
#[derive(Debug, Default, Clone)]
pub struct IpExcludeList {
    entries: Vec<IpExcludeEntry>,
}

#[derive(Debug, Clone)]
enum IpExcludeEntry {
    Single(IpAddr),
    CidrV4 { base: u32, mask: u32 },
}

impl IpExcludeList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single IP or CIDR range ("192.168.1.0/24" or "10.0.0.1").
    pub fn add(&mut self, s: &str) -> Result<(), String> {
        if let Some((addr_s, prefix_s)) = s.split_once('/') {
            let prefix: u8 = prefix_s.parse().map_err(|_| format!("bad prefix: {s}"))?;
            let addr = Ipv4Parse::parse(addr_s).ok_or_else(|| format!("bad IP: {s}"))?;
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            self.entries.push(IpExcludeEntry::CidrV4 {
                base: addr & mask,
                mask,
            });
        } else {
            let addr = IpAddr::from_str(s).map_err(|e| e.to_string())?;
            self.entries.push(IpExcludeEntry::Single(addr));
        }
        Ok(())
    }

    /// Load from a file (one entry per line, # comments ignored).
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut list = Self::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let _ = list.add(line);
        }
        Ok(list)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        for entry in &self.entries {
            match entry {
                IpExcludeEntry::Single(a) => {
                    if *a == ip {
                        return true;
                    }
                }
                IpExcludeEntry::CidrV4 { base, mask } => {
                    if let IpAddr::V4(v4) = ip {
                        let n = u32::from(v4);
                        if n & mask == *base {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Port exclusion list — comma-separated ports and ranges.
#[derive(Debug, Default, Clone)]
pub struct PortExcludeList {
    ranges: Vec<(u16, u16)>, // inclusive [start, end]
}

impl PortExcludeList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse "80,443,8000-8080".
    pub fn parse(s: &str) -> Self {
        let mut list = Self::new();
        for part in s.split(',') {
            let part = part.trim();
            if let Some((a, b)) = part.split_once('-') {
                if let (Ok(start), Ok(end)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    list.ranges.push((start, end));
                }
            } else if let Ok(p) = part.parse::<u16>() {
                list.ranges.push((p, p));
            }
        }
        list
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ranges.iter().any(|(s, e)| port >= *s && port <= *e)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

// --- minimal IPv4 parser to avoid dep on std::net::Ipv4Addr's FromStr error type ---
struct Ipv4Parse;
impl Ipv4Parse {
    fn parse(s: &str) -> Option<u32> {
        let mut parts = s.split('.');
        let a: u32 = parts.next()?.parse().ok()?;
        let b: u32 = parts.next()?.parse().ok()?;
        let c: u32 = parts.next()?.parse().ok()?;
        let d: u32 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((a << 24) | (b << 16) | (c << 8) | d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_exclude() {
        let mut list = IpExcludeList::new();
        list.add("192.168.1.0/24").unwrap();
        assert!(list.contains("192.168.1.50".parse().unwrap()));
        assert!(!list.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn port_exclude_range() {
        let list = PortExcludeList::parse("80,8000-8080,443");
        assert!(list.contains(80));
        assert!(list.contains(443));
        assert!(list.contains(8042));
        assert!(!list.contains(9000));
    }
}
