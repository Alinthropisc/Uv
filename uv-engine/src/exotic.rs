// Exotic TCP scan types: NULL, FIN, Xmas, ACK, Window.
// All require raw sockets (root/CAP_NET_RAW).
// In user-space these are simulated via TCP connect() with flag inspection;
// true raw-socket variants live in uv-ffi and are called from here.

use std::net::IpAddr;
use uv_core::{
    scan_type::ScanType,
    types::{Port, PortState, ProbeResult, Protocol},
};

pub struct ExoticScanner {
    pub scan_type: ScanType,
    pub timeout_ms: u32,
}

impl ExoticScanner {
    pub fn new(scan_type: ScanType, timeout_ms: u32) -> Self {
        Self {
            scan_type,
            timeout_ms,
        }
    }

    /// Probe a single port. Returns ProbeResult.
    /// Real raw-socket logic delegates to uv-ffi; here we report Unknown
    /// so the caller knows the scan type is registered but raw TX is needed.
    pub async fn probe(&self, addr: IpAddr, port: Port) -> ProbeResult {
        let state = match self.scan_type {
            // TCP connect can be done in user-space
            ScanType::TcpConnect => self.tcp_connect_probe(addr, port).await,
            // Raw-socket types: state is Open|Closed|Filtered based on response
            // Actual packet crafting happens in uv-ffi/rawsock.
            ScanType::Null | ScanType::Fin | ScanType::Xmas => {
                // No response → open|filtered; RST → closed; ICMP unreach → filtered
                // Without raw socket we can't distinguish — return Unknown
                PortState::Unknown
            }
            ScanType::Ack | ScanType::Window => {
                // RST received → unfiltered; no response → filtered
                PortState::Unknown
            }
            _ => PortState::Unknown,
        };

        ProbeResult {
            port,
            proto: Protocol::Tcp,
            state,
            rtt: None,
            service: None,
        }
    }

    async fn tcp_connect_probe(&self, addr: IpAddr, port: Port) -> PortState {
        use std::net::SocketAddr;
        use std::time::Duration;
        let sa = SocketAddr::new(addr, port);
        let timeout = Duration::from_millis(self.timeout_ms as u64);
        tokio::task::spawn_blocking(move || {
            match std::net::TcpStream::connect_timeout(&sa, timeout) {
                Ok(_) => PortState::Open,
                Err(e) => {
                    use std::io::ErrorKind;
                    match e.kind() {
                        ErrorKind::ConnectionRefused => PortState::Closed,
                        ErrorKind::TimedOut => PortState::Filtered,
                        _ => PortState::Unknown,
                    }
                }
            }
        })
        .await
        .unwrap_or(PortState::Unknown)
    }

    /// TCP flag bytes for each scan type (for uv-ffi raw packet builder).
    pub fn tcp_flags(&self) -> u8 {
        match self.scan_type {
            ScanType::Null => 0x00,               // no flags
            ScanType::Fin => 0x01,                // FIN
            ScanType::Xmas => 0x01 | 0x08 | 0x20, // FIN+PSH+URG
            ScanType::Ack => 0x10,                // ACK
            ScanType::Window => 0x10,             // ACK (same; look at window)
            ScanType::SynStealth => 0x02,         // SYN
            _ => 0x02,
        }
    }
}
