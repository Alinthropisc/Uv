// TCP probe specs — mirrors nmap's SEQ/OPS/WIN/ECN/T1-T7/U1/IE probes.

use std::net::Ipv4Addr;

/// A single TCP/UDP/ICMP probe to send for OS detection.
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub name: &'static str,
    pub proto: ProbeProto,
    pub flags: u8, // TCP flags bitmask
    pub window: u16,
    pub options: Vec<TcpOption>,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProto {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
pub enum TcpOption {
    Mss(u16),
    Nop,
    WScale(u8),
    SackPermitted,
    Timestamp(u32, u32),
}

/// Collected response features for one probe.
#[derive(Debug, Clone, Default)]
pub struct OsProbe {
    pub seq_diffs: Vec<i64>, // ISN differences across SEQ probes
    pub ttl: Option<u8>,
    pub window_sizes: Vec<u16>,
    pub tcp_options: Vec<String>,
    pub icmp_code: Option<u8>,
    pub df_bit: bool,
    pub ecn_echo: bool,
}

/// Standard nmap-style probe set (abridged).
pub fn standard_probes(target: Ipv4Addr, open_port: u16, closed_port: u16) -> Vec<ProbeSpec> {
    let _ = (target, open_port, closed_port); // parameterised for future use
    vec![
        ProbeSpec {
            name: "SEQ1",
            proto: ProbeProto::Tcp,
            flags: 0x02, // SYN
            window: 1,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0xFFFFFFFF, 0),
                TcpOption::Nop,
                TcpOption::WScale(10),
            ],
            payload: None,
        },
        ProbeSpec {
            name: "SEQ2",
            proto: ProbeProto::Tcp,
            flags: 0x02,
            window: 63,
            options: vec![
                TcpOption::Mss(1400),
                TcpOption::WScale(0),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0xFFFFFFFF, 0),
                TcpOption::Nop,
            ],
            payload: None,
        },
        ProbeSpec {
            name: "IE1",
            proto: ProbeProto::Icmp,
            flags: 0,
            window: 0,
            options: vec![],
            payload: None,
        },
        ProbeSpec {
            name: "IE2",
            proto: ProbeProto::Icmp,
            flags: 0,
            window: 0,
            options: vec![],
            payload: None,
        },
        ProbeSpec {
            name: "U1",
            proto: ProbeProto::Udp,
            flags: 0,
            window: 0,
            options: vec![],
            payload: Some(b"C".repeat(300)),
        },
    ]
}
