// Port range parsing: "22,80,443,8000-9000,top100"

use crate::top::top_ports;

#[derive(Debug, Clone)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
    TopN(usize),
    All,
}

/// Parse a port spec string into a sorted, deduplicated Vec<u16>.
/// Accepts: "22,80,443", "1-1024", "top100", "top1000", "-" (all ports).
pub fn parse_port_spec(spec: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part == "-" || part == "all" {
            return (1u16..=65535).collect();
        }
        if let Some(n_str) = part.strip_prefix("top") {
            let n: usize = n_str.parse().unwrap_or(100);
            for e in top_ports(n) {
                ports.push(e.port);
            }
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (a.parse::<u16>(), b.parse::<u16>()) {
                for p in start..=end {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mixed() {
        let v = parse_port_spec("22,80,443,8000-8002");
        assert_eq!(v, vec![22, 80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn parse_top10() {
        let v = parse_port_spec("top10");
        assert_eq!(v.len(), 10);
        assert!(v.contains(&80));
    }
}
